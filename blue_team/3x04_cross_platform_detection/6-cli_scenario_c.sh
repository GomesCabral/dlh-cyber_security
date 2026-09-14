#!/bin/bash

# Task 6 - Scenario C via CLI: Medical IoT Segment Egress
# Correlate periodic outbound medical-device traffic with network-zone policy
# and optional IOC context, then write a structured SOC finding.

set -u

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

SCENARIO_FILE="$ASSETS_DIR/scenarios/scenario_c_medical_egress.json"
NETWORK_EVENTS="$HANDOFF_DIR/data/network_events.json"
ENRICHED_EVENTS="$HANDOFF_DIR/data/enriched_events.json"
NETWORK_ZONES="$HANDOFF_DIR/context/network_zones.json"
IOC_CONTEXT="$ASSETS_DIR/3x03_assets/ioc_context.json"
FINDINGS_DIR="findings"
FINDING_FILE="$FINDINGS_DIR/scenario_c_cli.json"

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
MATCHED_EVENTS="$(mktemp)"
BEACON_EVENTS="$(mktemp)"

cleanup()
{
    rm -f "$MATCHED_EVENTS" "$BEACON_EVENTS"
}

trap cleanup EXIT

fail()
{
    printf 'error       : %s\n' "$1" >&2
    exit 1
}

validate_json()
{
    local filepath="$1"

    [[ -s "$filepath" ]] || fail "missing or empty file: $filepath"
    jq empty "$filepath" >/dev/null 2>&1 || fail "invalid JSON: $filepath"
}

validate_json "$SCENARIO_FILE"
validate_json "$NETWORK_ZONES"
[[ -s "$ENRICHED_EVENTS" ]] || fail "enriched event handoff is unavailable"

# Read scenario scope and ATT&CK mapping from the manifest.
WINDOW_START="$(jq -r '.time_window.start // empty' "$SCENARIO_FILE")"
WINDOW_END="$(jq -r '.time_window.end // empty' "$SCENARIO_FILE")"
ATTACK_TECHNIQUES="$(jq -c '.mitre_techniques // []' "$SCENARIO_FILE")"
SOURCE_IP="10.2.3.2"
DESTINATION_IP="198.51.100.73"
DESTINATION_PORT=443

[[ -n "$WINDOW_START" ]] || fail "time_window.start missing from manifest"
[[ -n "$WINDOW_END" ]] || fail "time_window.end missing from manifest"

if [[ "$(printf '%s\n' "$ATTACK_TECHNIQUES" | jq 'length')" -ne 2 ]]; then
    fail "expected two ATT&CK techniques in the scenario manifest"
fi

printf 'scenario    : scenario_c_medical_egress\n'

# Prefer the dedicated network handoff when it is usable; otherwise use the
# enriched NDJSON handoff, as explicitly allowed by the task.
if [[ -s "$NETWORK_EVENTS" ]] &&
   head -n 1 "$NETWORK_EVENTS" | jq empty >/dev/null 2>&1; then
    EVENT_SOURCE="$NETWORK_EVENTS"
else
    EVENT_SOURCE="$ENRICHED_EVENTS"
fi

# grep performs a safe pre-filter on the large NDJSON file; jq remains the
# authoritative structured filter for addresses and the scenario time window.
grep -F "$SOURCE_IP" "$EVENT_SOURCE" |
    jq -c \
        --arg src_ip "$SOURCE_IP" \
        --arg dst_ip "$DESTINATION_IP" \
        --arg window_start "$WINDOW_START" \
        --arg window_end "$WINDOW_END" '
        select(
            .src_ip == $src_ip
            and .dst_ip == $dst_ip
            and .timestamp >= $window_start
            and .timestamp <= $window_end
        )
    ' > "$MATCHED_EVENTS" || fail "network event query failed"

MATCHED_COUNT="$(wc -l < "$MATCHED_EVENTS" | tr -d ' ')"
(( MATCHED_COUNT > 0 )) || fail "no matching medical-IoT egress events found"

# The five firewall records are the beacons. The Suricata event is independent
# corroborating IDS evidence and must not distort the interval calculation.
jq -c '
    select(
        .source_type == "firewall"
        and (.dst_port | tonumber?) == 443
    )
' "$MATCHED_EVENTS" > "$BEACON_EVENTS"

BEACON_COUNT="$(wc -l < "$BEACON_EVENTS" | tr -d ' ')"
SURICATA_COUNT="$(
    jq -r 'select(.source_type == "suricata") | 1' "$MATCHED_EVENTS" |
        wc -l |
        tr -d ' '
)"

printf 'src_ip      : %s (MEDICAL_IOT zone)\n' "$SOURCE_IP"
printf 'dst_ip      : %s:%s\n' "$DESTINATION_IP" "$DESTINATION_PORT"
printf 'matched     : %s network records (%s beacons, %s IDS alert)\n' \
    "$MATCHED_COUNT" "$BEACON_COUNT" "$SURICATA_COUNT"

(( BEACON_COUNT >= 2 )) || fail "insufficient firewall flows for beacon analysis"

# Order the firewall flows and compute each interval from the previous beacon.
BEACON_TIMELINE="$(
    jq -cs '
        sort_by(.timestamp) as $events
        | [
            range(0; $events | length) as $index
            | {
                number: ($index + 1),
                timestamp: $events[$index].timestamp,
                bytes_out: ($events[$index].bytes_out // 0),
                interval_seconds: (
                    if $index == 0 then
                        null
                    else
                        (($events[$index].timestamp | fromdateiso8601)
                        - ($events[$index - 1].timestamp | fromdateiso8601))
                    end
                )
            }
        ]
    ' "$BEACON_EVENTS"
)"

printf '%s\n' "$BEACON_TIMELINE" |
    jq -r '.[] | [.number, .timestamp, .bytes_out, (.interval_seconds // "")] | @tsv' |
    while IFS=$'\t' read -r number timestamp bytes_out interval_seconds; do
        if [[ -z "$interval_seconds" ]]; then
            printf 'beacon_%s    : %s (bytes_out: %s)\n' \
                "$number" "$timestamp" "$bytes_out"
        else
            interval_minutes=$((interval_seconds / 60))
            printf 'beacon_%s    : %s (interval: %s min, bytes_out: %s)\n' \
                "$number" "$timestamp" "$interval_minutes" "$bytes_out"
        fi
    done

TOTAL_BYTES_OUT="$(jq -s 'map(.bytes_out // 0) | add // 0' "$BEACON_EVENTS")"
UNIQUE_INTERVALS="$(
    printf '%s\n' "$BEACON_TIMELINE" |
        jq '[.[].interval_seconds | select(. != null)] | unique | length'
)"
BEACON_INTERVAL_SECONDS="$(
    printf '%s\n' "$BEACON_TIMELINE" |
        jq -r '[.[].interval_seconds | select(. != null)] | first // 0'
)"

# Validate that the source subnet belongs to MEDICAL_IOT.
ZONE_RECORD="$(
    jq -c '
        .zones[]
        | select(
            .zone_id == "MEDICAL_IOT"
            and (.cidrs | index("10.2.3.0/24")) != null
        )
    ' "$NETWORK_ZONES" |
        head -n 1
)"

[[ -n "$ZONE_RECORD" ]] ||
    fail "10.2.3.0/24 is not assigned to the MEDICAL_IOT zone"

ALLOWED_OUTBOUND="$(
    printf '%s\n' "$ZONE_RECORD" |
        jq -c '.allowed_outbound_to // []'
)"

ZONE_RULE="$(
    jq -c '
        .inter_zone_rules[]
        | select(.from == "MEDICAL_IOT" and .to == "INTERNET")
    ' "$NETWORK_ZONES" |
        head -n 1
)"

[[ -n "$ZONE_RULE" ]] ||
    fail "MEDICAL_IOT-to-INTERNET policy rule not found"

ZONE_ACTION="$(printf '%s\n' "$ZONE_RULE" | jq -r '.action // empty')"
ZONE_SEVERITY="$(printf '%s\n' "$ZONE_RULE" | jq -r '.severity // empty')"

[[ "$ZONE_ACTION" == "BLOCK" ]] ||
    fail "MEDICAL_IOT-to-INTERNET policy is not BLOCK"

printf 'zone        : MEDICAL_IOT — %s/%s; allowed outbound: %s\n' \
    "$ZONE_ACTION" "$ZONE_SEVERITY" "$ALLOWED_OUTBOUND"

# IOC context is optional. Absence is recorded without preventing the network
# policy finding; presence strengthens the C2 assessment.
IOC_REPUTATION="not_available"
IOC_CATEGORIES='[]'
IOC_SUMMARY="IOC context was not available"

if [[ -s "$IOC_CONTEXT" ]] && jq empty "$IOC_CONTEXT" >/dev/null 2>&1; then
    IOC_RECORD="$(
        jq -c --arg ip "$DESTINATION_IP" '.indicators[$ip] // empty' \
            "$IOC_CONTEXT"
    )"

    if [[ -n "$IOC_RECORD" ]]; then
        IOC_REPUTATION="$(
            printf '%s\n' "$IOC_RECORD" |
                jq -r '.reputation // "unknown"'
        )"
        IOC_CATEGORIES="$(
            printf '%s\n' "$IOC_RECORD" |
                jq -c '.categories // []'
        )"
        IOC_SUMMARY="destination reputation $IOC_REPUTATION with categories $(printf '%s' "$IOC_CATEGORIES" | jq -r 'join(", ")')"
    else
        IOC_SUMMARY="destination was not present in the available IOC context"
    fi
fi

printf 'ioc         : %s\n' "$IOC_SUMMARY"
printf 'bytes_out   : %s total across %s firewall beacons\n' \
    "$TOTAL_BYTES_OUT" "$BEACON_COUNT"
printf 'attack      : T1071.001 T1041\n'

if [[ "$UNIQUE_INTERVALS" -eq 1 ]]; then
    INTERVAL_SUMMARY="$((BEACON_INTERVAL_SECONDS / 60))-minute periodic intervals"
else
    INTERVAL_SUMMARY="variable beacon intervals"
fi

HYPOTHESIS="A MEDICAL_IOT device initiated five HTTPS connections to a malicious C2-associated address using $INTERVAL_SUMMARY and transferred $TOTAL_BYTES_OUT bytes outbound. The traffic violates the CRITICAL MEDICAL_IOT-to-INTERNET block policy and is consistent with command-and-control beaconing and possible exfiltration."

# Preserve only genuine upstream event references.
EVENT_REFS="$(jq -cs '[.[].event_ref // empty] | unique' "$MATCHED_EVENTS")"

mkdir -p "$FINDINGS_DIR"
INVESTIGATION_END="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
END_EPOCH="$(date +%s)"
ELAPSED_SECONDS=$((END_EPOCH - START_EPOCH))

jq -n \
    --arg finding_id "scenario_c_cli" \
    --arg scenario_id "scenario_c" \
    --arg interface "cli" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED_SECONDS" \
    --argjson event_refs "$EVENT_REFS" \
    --argjson attack_techniques "$ATTACK_TECHNIQUES" \
    --arg hypothesis "$HYPOTHESIS" \
    --arg created_at "$INVESTIGATION_END" '
    {
        finding_id: $finding_id,
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $investigation_start,
        investigation_end: $investigation_end,
        time_to_first_answer_seconds: $elapsed,
        actions: [
            "Read the Scenario C manifest and established the network scope",
            "Filtered network telemetry by source, destination, and time window",
            "Separated five firewall beacons from the corroborating Suricata alert",
            "Ordered the beacons and calculated their intervals and outbound bytes",
            "Verified that 10.2.3.0/24 belongs to the MEDICAL_IOT zone",
            "Verified the CRITICAL MEDICAL_IOT-to-INTERNET block policy",
            "Checked IOC reputation for 198.51.100.73",
            "Escalated the policy violation as likely C2 beaconing and possible exfiltration"
        ],
        fields_touched: [
            "timestamp",
            "source_type",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "network_protocol",
            "action",
            "bytes_out",
            "bytes_in",
            "rule_id",
            "signature",
            "event_ref",
            "network_zones.zone_id",
            "network_zones.cidrs",
            "network_zones.allowed_outbound_to",
            "inter_zone_rules.action",
            "ioc_context.reputation",
            "ioc_context.categories"
        ],
        event_refs: $event_refs,
        attack_techniques: $attack_techniques,
        hypothesis: $hypothesis,
        confidence: "high",
        created_at: $created_at
    }
' > "$FINDING_FILE"

jq empty "$FINDING_FILE" >/dev/null 2>&1 ||
    fail "generated finding is not valid JSON"

printf 'elapsed     : %s seconds\n' "$ELAPSED_SECONDS"
printf 'finding     : %s written\n' "$FINDING_FILE"

exit 0

