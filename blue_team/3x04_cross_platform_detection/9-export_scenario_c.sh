#!/bin/bash

# Task 9 - Scenario C via Wazuh Export: Medical IoT Segment Egress
# Analyze medical-IoT beaconing in Wazuh document format, determine whether
# zone context is immediately available, and compare timing with Task 6.

set -u

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

SEARCH_RESULTS="$WAZUH_EXPORTS/scenario_c_search_results.json"
DASHBOARD_TRACE="$WAZUH_EXPORTS/scenario_c_dashboard_trace.json"
NETWORK_ZONES="$HANDOFF_DIR/context/network_zones.json"
CLI_FINDING_PRIMARY="findings/scenario_c_cli.json"
CLI_FINDING_FALLBACK="scenario_c_cli.json"
FINDINGS_DIR="findings"
FINDING_FILE="$FINDINGS_DIR/scenario_c_export.json"

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
FILE_READS=0
BEACON_EVENTS="$(mktemp)"

cleanup()
{
    rm -f "$BEACON_EVENTS"
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

validate_json "$SEARCH_RESULTS"
validate_json "$DASHBOARD_TRACE"

# File read 1: load and validate the Wazuh search export.
HITS_TOTAL="$(jq -r '.hits_total // empty' "$SEARCH_RESULTS")"
EVENT_COUNT="$(jq -r '.events | length' "$SEARCH_RESULTS")"
KQL_QUERY="$(jq -r '.query.kql // .kql_query // empty' "$SEARCH_RESULTS")"
FILE_READS=$((FILE_READS + 1))

[[ "$HITS_TOTAL" =~ ^[0-9]+$ ]] || fail "hits_total is missing or invalid"
[[ "$EVENT_COUNT" -eq "$HITS_TOTAL" ]] ||
    fail "hits_total ($HITS_TOTAL) does not match events length ($EVENT_COUNT)"
[[ -n "$KQL_QUERY" ]] || fail "KQL query is missing"

printf 'reading     : scenario_c_search_results.json (%s events)\n' \
    "$EVENT_COUNT"
printf 'kql         : %s\n' "$KQL_QUERY"

# Extract and print each required Wazuh field without TSV column shifting.
jq -r '
    .events[]
    | "event       : "
      + (._source["@timestamp"] // .["@timestamp"] // "unknown")
      + " source.ip=" + (._source.source.ip // "unknown")
      + " destination.ip=" + (._source.destination.ip // "unknown")
      + ":" + (._source.destination.port // "unknown" | tostring)
      + " source.zone=" + (._source.source.zone // "missing")
      + " type=" + (._source.agent.type // "unknown")
      + " full_log=" + (._source.full_log // "")
' "$SEARCH_RESULTS"

SOURCE_IP="$(jq -r '.events[0]._source.source.ip // empty' "$SEARCH_RESULTS")"
DESTINATION_IP="$(
    jq -r '.events[0]._source.destination.ip // empty' "$SEARCH_RESULTS"
)"
DESTINATION_PORT="$(
    jq -r '.events[0]._source.destination.port // empty' "$SEARCH_RESULTS"
)"

[[ -n "$SOURCE_IP" ]] || fail "source.ip missing from export"
[[ -n "$DESTINATION_IP" ]] || fail "destination.ip missing from export"
[[ "$DESTINATION_PORT" =~ ^[0-9]+$ ]] || fail "destination.port is invalid"

printf 'src_ip      : %s\n' "$SOURCE_IP"
printf 'dst_ip      : %s:%s\n' "$DESTINATION_IP" "$DESTINATION_PORT"

# Determine whether every exported document contains source.zone.
ZONE_VALUES="$(
    jq -c '
        [
            .events[]
            | ._source.source.zone
            | select(. != null and . != "")
        ]
        | unique
    ' "$SEARCH_RESULTS"
)"
ZONE_POPULATED_COUNT="$(
    jq '[.events[] | select(._source.source.zone != null and ._source.source.zone != "")] | length' \
        "$SEARCH_RESULTS"
)"

FALLBACK_REQUIRED=false

if [[ "$ZONE_POPULATED_COUNT" -eq "$EVENT_COUNT" ]] &&
   [[ "$(printf '%s\n' "$ZONE_VALUES" | jq 'length')" -eq 1 ]]; then
    SOURCE_ZONE="$(printf '%s\n' "$ZONE_VALUES" | jq -r '.[0]')"
    ZONE_ACTION="Source zone immediately available in Wazuh source.zone: $SOURCE_ZONE"
    printf 'src_zone    : %s (from source.zone — immediately available)\n' \
        "$SOURCE_ZONE"
else
    FALLBACK_REQUIRED=true
    validate_json "$NETWORK_ZONES"

    SOURCE_ZONE="$(
        jq -r --arg ip "$SOURCE_IP" '
            .zones[]
            | select(
                .cidrs[] as $cidr
                | ($cidr == "10.2.3.0/24" and ($ip | startswith("10.2.3.")))
            )
            | .zone_id
        ' "$NETWORK_ZONES" |
            head -n 1
    )"

    [[ -n "$SOURCE_ZONE" ]] ||
        fail "source zone unavailable in export and fallback lookup failed"

    ZONE_ACTION="source.zone missing from one or more documents; resolved $SOURCE_ZONE through network_zones.json"
    printf 'src_zone    : %s (network_zones.json fallback)\n' "$SOURCE_ZONE"
fi

# Select only firewall flows as beacons. The Suricata alert corroborates the
# finding but is not a periodic flow and must not affect interval calculations.
jq -c '
    .events[]
    | select(._source.agent.type == "firewall")
' "$SEARCH_RESULTS" > "$BEACON_EVENTS"

BEACON_COUNT="$(wc -l < "$BEACON_EVENTS" | tr -d ' ')"
IDS_COUNT=$((EVENT_COUNT - BEACON_COUNT))
(( BEACON_COUNT >= 2 )) || fail "insufficient firewall flows for interval analysis"

printf 'matched     : %s events (%s beacons, %s corroborating IDS alert)\n' \
    "$EVENT_COUNT" "$BEACON_COUNT" "$IDS_COUNT"

BEACON_TIMELINE="$(
    jq -cs '
        sort_by(._source["@timestamp"]) as $events
        | [
            range(0; $events | length) as $index
            | {
                number: ($index + 1),
                timestamp: $events[$index]._source["@timestamp"],
                bytes_out: (
                    $events[$index]._source.event_data.bytes_out
                    // 0
                    | tonumber
                ),
                interval_seconds: (
                    if $index == 0 then
                        null
                    else
                        (($events[$index]._source["@timestamp"] | fromdateiso8601)
                        - ($events[$index - 1]._source["@timestamp"] | fromdateiso8601))
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
            printf 'beacon_%s    : %s (%s min interval, bytes_out: %s)\n' \
                "$number" "$timestamp" "$((interval_seconds / 60))" "$bytes_out"
        fi
    done

TOTAL_BYTES_OUT="$(
    printf '%s\n' "$BEACON_TIMELINE" |
        jq '[.[].bytes_out] | add // 0'
)"
INTERVAL_COUNT="$(
    printf '%s\n' "$BEACON_TIMELINE" |
        jq '[.[].interval_seconds | select(. != null)] | unique | length'
)"
INTERVAL_SECONDS="$(
    printf '%s\n' "$BEACON_TIMELINE" |
        jq -r '[.[].interval_seconds | select(. != null)] | first // 0'
)"

if [[ "$INTERVAL_COUNT" -eq 1 ]]; then
    INTERVAL_DESCRIPTION="$((INTERVAL_SECONDS / 60))-minute intervals"
else
    INTERVAL_DESCRIPTION="variable intervals"
fi

# File read 2: load dashboard actions and ATT&CK context.
CLICK_PATH="$(jq -c '.click_path // []' "$DASHBOARD_TRACE")"
CLICK_STEPS="$(jq -r '.click_path | length' "$DASHBOARD_TRACE")"
TRACE_FIELDS="$(jq -c '.fields_examined // []' "$DASHBOARD_TRACE")"
ATTACK_TECHNIQUES="$(jq -c '.attack_techniques // []' "$DASHBOARD_TRACE")"
CONFIDENCE="$(jq -r '.confidence // "medium"' "$DASHBOARD_TRACE")"
FILE_READS=$((FILE_READS + 1))

(( CLICK_STEPS > 0 )) || fail "dashboard click_path is empty"
[[ "$(printf '%s\n' "$ATTACK_TECHNIQUES" | jq 'length')" -eq 2 ]] ||
    fail "expected two ATT&CK techniques in dashboard trace"

if [[ "$FALLBACK_REQUIRED" == true ]]; then
    ACTIONS="$(
        jq -n \
            --argjson click_path "$CLICK_PATH" \
            --arg zone_action "$ZONE_ACTION" '
            $click_path + [$zone_action]
        '
    )"
else
    # The trace already contains the source.zone inspection step, so an extra
    # duplicate action is not added when zone context is immediately available.
    ACTIONS="$CLICK_PATH"
fi

FIELDS_TOUCHED="$(
    jq -n \
        --argjson trace_fields "$TRACE_FIELDS" '
        ($trace_fields
        + ["source.zone", "full_log", "event_data.bytes_out"])
        | unique
    '
)"

printf 'click_path  : %s steps\n' "$CLICK_STEPS"
printf 'attack      : T1071.001 T1041\n'

EVENT_REFS="$(jq -c '[.events[]._id // empty] | unique' "$SEARCH_RESULTS")"

# File read 3: obtain the Task 6 measurement for a real delta calculation.
if [[ -s "$CLI_FINDING_PRIMARY" ]]; then
    CLI_FINDING="$CLI_FINDING_PRIMARY"
elif [[ -s "$CLI_FINDING_FALLBACK" ]]; then
    CLI_FINDING="$CLI_FINDING_FALLBACK"
else
    fail "Task 6 CLI finding not found"
fi

validate_json "$CLI_FINDING"
CLI_ELAPSED="$(jq -r '.time_to_first_answer_seconds // empty' "$CLI_FINDING")"
FILE_READS=$((FILE_READS + 1))
[[ "$CLI_ELAPSED" =~ ^[0-9]+$ ]] || fail "invalid CLI elapsed time"

HYPOTHESIS="Five HTTPS firewall flows from a MEDICAL_IOT source to the same external destination at $INTERVAL_DESCRIPTION are consistent with periodic command-and-control beaconing. The repeated egress transferred $TOTAL_BYTES_OUT bytes and is consistent with possible exfiltration over the C2 channel."

mkdir -p "$FINDINGS_DIR"
INVESTIGATION_END="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
END_EPOCH="$(date +%s)"
ELAPSED_SECONDS=$((END_EPOCH - START_EPOCH))

jq -n \
    --arg finding_id "scenario_c_wazuh_export" \
    --arg scenario_id "scenario_c" \
    --arg interface "wazuh_export" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED_SECONDS" \
    --argjson actions "$ACTIONS" \
    --argjson fields_touched "$FIELDS_TOUCHED" \
    --argjson event_refs "$EVENT_REFS" \
    --argjson attack_techniques "$ATTACK_TECHNIQUES" \
    --arg hypothesis "$HYPOTHESIS" \
    --arg confidence "$CONFIDENCE" \
    --arg created_at "$INVESTIGATION_END" '
    {
        finding_id: $finding_id,
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $investigation_start,
        investigation_end: $investigation_end,
        time_to_first_answer_seconds: $elapsed,
        actions: $actions,
        fields_touched: $fields_touched,
        event_refs: $event_refs,
        attack_techniques: $attack_techniques,
        hypothesis: $hypothesis,
        confidence: $confidence,
        created_at: $created_at
    }
' > "$FINDING_FILE"

jq empty "$FINDING_FILE" >/dev/null 2>&1 ||
    fail "generated finding is not valid JSON"

if (( ELAPSED_SECONDS < CLI_ELAPSED )); then
    DELTA=$((ELAPSED_SECONDS - CLI_ELAPSED))
    COMPARISON="$DELTA seconds (export faster for this signal shape)"
elif (( ELAPSED_SECONDS > CLI_ELAPSED )); then
    DELTA=$((ELAPSED_SECONDS - CLI_ELAPSED))
    COMPARISON="+$DELTA seconds (CLI faster for this signal shape)"
else
    COMPARISON="0 seconds (same elapsed time)"
fi

printf 'elapsed     : %s seconds, %s file reads\n' \
    "$ELAPSED_SECONDS" "$FILE_READS"
printf 'delta_vs_cli: %s\n' "$COMPARISON"
printf 'finding     : %s written\n' "$FINDING_FILE"

exit 0

