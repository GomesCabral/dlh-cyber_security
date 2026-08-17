#!/usr/bin/env bash
set -Eeuo pipefail

DEFAULT_PCAP="/home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PCAP="${1:-$DEFAULT_PCAP}"
CONFIG="${SURICATA_CONFIG:-$SCRIPT_DIR/suricata.yaml}"
CATEGORY_MAP="${SIGNATURE_CATEGORIES:-$SCRIPT_DIR/signature_categories.json}"
OUTPUT="${OUTPUT_FILE:-$SCRIPT_DIR/suricata_alerts.json}"
TMPDIR_ANALYSIS=""

cleanup() {
    if [[ -n "$TMPDIR_ANALYSIS" && -d "$TMPDIR_ANALYSIS" ]]; then
        rm -rf -- "$TMPDIR_ANALYSIS"
    fi
}
trap cleanup EXIT

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

for command in suricata jq mktemp date; do
    command -v "$command" >/dev/null 2>&1 || die "Required command not found: $command"
done

[[ -r "$PCAP" ]] || die "PCAP does not exist or is not readable: $PCAP"
[[ -r "$CONFIG" ]] || die "Suricata configuration not found: $CONFIG"
[[ -r "$CATEGORY_MAP" ]] || die "Signature category map not found: $CATEGORY_MAP"
jq -e 'type == "object"' "$CATEGORY_MAP" >/dev/null \
    || die "Category map must contain a JSON object: $CATEGORY_MAP"

TMPDIR_ANALYSIS="$(mktemp -d "${TMPDIR:-/tmp}/suricata-replay.XXXXXX")"
STARTED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

printf 'Replaying %s with Suricata...\n' "$PCAP"
suricata -c "$CONFIG" -r "$PCAP" -l "$TMPDIR_ANALYSIS"

FINISHED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
EVE="$TMPDIR_ANALYSIS/eve.json"
[[ -f "$EVE" ]] || die "Suricata completed but did not create $EVE"

# This is analysis only: all detection decisions come from the Suricata ruleset.
# The map supports either flat keys or {"by_signature": {}, "by_id": {}}.
jq -s \
    --arg pcap "$PCAP" \
    --arg started_at "$STARTED_AT" \
    --arg finished_at "$FINISHED_AT" \
    --slurpfile category_map "$CATEGORY_MAP" '
    def category_for($a):
        ($a.signature_id | tostring) as $sid
        | ($a.signature // "") as $sig
        | ($category_map[0].by_id[$sid]
           // $category_map[0].by_signature[$sig]
           // $category_map[0][$sid]
           // $category_map[0][$sig]
           // "other") as $category
        | if (["reconnaissance", "exploit", "lateral_movement",
               "exfiltration", "malware_c2", "policy_violation", "other"]
              | index($category))
          then $category else "other" end;

    def counts_by($field):
        group_by(.[$field])
        | map({key: (.[0][$field] // "unknown"), count: length})
        | sort_by([-.count, .key]);

    def count_object($field):
        counts_by($field) | map({(.key | tostring): .count}) | add // {};

    [ .[]
      | select(.event_type == "alert")
      | {
          timestamp,
          src_ip,
          src_port: (.src_port // null),
          dst_ip,
          dst_port: (.dst_port // null),
          proto,
          signature: .alert.signature,
          signature_id: .alert.signature_id,
          rule_category: .alert.category,
          severity: .alert.severity
        }
      | .classification = category_for(.)
    ] as $alerts
    | ($alerts | group_by(.signature_id)
       | map({
           signature_id: .[0].signature_id,
           signature: .[0].signature,
           classification: .[0].classification,
           count: length
         })
       | sort_by([-.count, .signature])) as $by_signature
    | {
        pcap: $pcap,
        started_at: $started_at,
        finished_at: $finished_at,
        total_alerts: ($alerts | length),
        unique_signatures: ($by_signature | length),
        severity_distribution: ($alerts | count_object("severity")),
        by_category: ($alerts | count_object("classification")),
        by_signature: $by_signature,
        top_sources: ($alerts | counts_by("src_ip") | .[:10]
                      | map({src_ip: .key, count})),
        top_destinations: ($alerts | counts_by("dst_ip") | .[:10]
                           | map({dst_ip: .key, count})),
        alerts: $alerts
      }
    ' "$EVE" >"$OUTPUT"

printf 'Analysis written to %s\n' "$OUTPUT"
jq '{total_alerts, unique_signatures, severity_distribution, by_category,
     top_sources, top_destinations}' "$OUTPUT"