#!/bin/bash
#
# 9-suricata_analysis.sh
#
# Replays a PCAP through Suricata (offline/read mode), parses eve.json,
# and produces a classified, ranked alert summary for Tier 1 triage.
#
# This script does NOT perform detection. Suricata + its ruleset is the
# authoritative detection engine. This script is a reader/aggregator that
# turns raw eve.json alert events into an analyst-friendly report.
#
# Usage:
#   ./9-suricata_analysis.sh [path/to/file.pcap]
#
# Default PCAP:
#   /home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap
#
set -euo pipefail

# ----------------------------------------------------------------------------
# Config / arguments
# ----------------------------------------------------------------------------
DEFAULT_PCAP="/home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap"
if [[ -n "${1:-}" ]]; then
  PCAP="$1"
else
  PCAP="$DEFAULT_PCAP"
fi
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SURICATA_CONF="${SURICATA_CONF:-${SCRIPT_DIR}/suricata.yaml}"
CATEGORY_MAP="${CATEGORY_MAP:-${SCRIPT_DIR}/signature_categories.json}"
OUTPUT="${OUTPUT:-${SCRIPT_DIR}/suricata_alerts.json}"
TOP_N="${TOP_N:-10}"

log()  { printf '[9-suricata_analysis] %s\n' "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }

# ----------------------------------------------------------------------------
# Preconditions
# ----------------------------------------------------------------------------
command -v suricata >/dev/null 2>&1 || die "suricata is not installed / not on PATH"
command -v jq       >/dev/null 2>&1 || die "jq is required to parse eve.json"

[[ -f "$PCAP" ]]           || die "PCAP not found: $PCAP"
[[ -f "$SURICATA_CONF" ]]  || die "suricata.yaml not found at $SURICATA_CONF"
[[ -f "$CATEGORY_MAP" ]]   || die "signature_categories.json not found at $CATEGORY_MAP"
jq -e . "$CATEGORY_MAP" >/dev/null 2>&1 || die "signature_categories.json is not valid JSON"

TMPDIR="$(mktemp -d /tmp/suricata_replay.XXXXXX)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# ----------------------------------------------------------------------------
# 1. Replay the PCAP through Suricata (offline mode, single run, no live iface)
# ----------------------------------------------------------------------------
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Replaying $PCAP through Suricata -> $TMPDIR"

suricata -c "$SURICATA_CONF" -r "$PCAP" -l "$TMPDIR" --runmode=single

FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

EVE="${TMPDIR}/eve.json"
[[ -s "$EVE" ]] || die "Suricata did not produce a non-empty eve.json"

# ----------------------------------------------------------------------------
# 2. Parse + classify + aggregate with jq
#    eve.json is JSON-Lines (one JSON object per line) -> jq -s slurps
#    all of them into a single array before we operate on it.
# ----------------------------------------------------------------------------
log "Parsing eve.json and classifying alerts"

jq -s \
  --arg pcap "$PCAP" \
  --arg started "$STARTED_AT" \
  --arg finished "$FINISHED_AT" \
  --argjson topn "$TOP_N" \
  --slurpfile catmap "$CATEGORY_MAP" \
  '
  # ---- classify a signature string against the keyword/regex map ----------
  # First matching regex key (case-insensitive) wins; unmatched -> "other".
  def classify($sig):
    ($catmap[0] | to_entries
      | map(select(.key as $k | $sig | test($k; "i")))
      | if length > 0 then .[0].value else "other" end);

  # ---- group_by + count helper ----------------------------------------
  def counts_by(f):
    group_by(f) | map({key: (.[0] | f | tostring), value: length}) | sort_by(-.value) | from_entries;

  [ .[] | select(.event_type == "alert") ]
  | map({
      timestamp:     .timestamp,
      src_ip:        .src_ip,
      src_port:      .src_port,
      dst_ip:        .dest_ip,
      dst_port:      .dest_port,
      proto:         .proto,
      signature:     .alert.signature,
      signature_id:  .alert.signature_id,
      category:      .alert.category,
      severity:      .alert.severity,
      classification: classify(.alert.signature)
    }) as $alerts
  | {
      pcap:               $pcap,
      started_at:         $started,
      finished_at:        $finished,
      total_alerts:       ($alerts | length),
      unique_signatures:  ($alerts | map(.signature) | unique | length),
      severity_distribution: ($alerts | counts_by(.severity)),
      by_category:        ($alerts | counts_by(.classification)),
      by_signature:        ($alerts | counts_by(.signature)),
      top_sources: (
        $alerts | group_by(.src_ip)
        | map({ip: .[0].src_ip, count: length})
        | sort_by(-.count) | .[0:$topn]
      ),
      top_destinations: (
        $alerts | group_by(.dst_ip)
        | map({ip: .[0].dst_ip, count: length})
        | sort_by(-.count) | .[0:$topn]
      ),
      alerts: $alerts
    }
  ' "$EVE" > "$OUTPUT"

TOTAL=$(jq '.total_alerts' "$OUTPUT")
UNIQ=$(jq '.unique_signatures' "$OUTPUT")
log "Done. ${TOTAL} alerts across ${UNIQ} unique signatures -> ${OUTPUT}"

# ----------------------------------------------------------------------------
# 3. Tier-1 triage cue: flag anything that isn't recon/policy noise
# ----------------------------------------------------------------------------
ESCALATE=$(jq -r '
  [.alerts[] | select(.classification as $c
    | ($c == "lateral_movement" or $c == "malware_c2" or $c == "exfiltration" or $c == "exploit"))]
  | length
' "$OUTPUT")

if [[ "$ESCALATE" -gt 0 ]]; then
  log "⚠ ${ESCALATE} alert(s) fall in lateral_movement / malware_c2 / exfiltration / exploit — escalate to Tier 2."
fi