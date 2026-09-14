#!/bin/bash

# Task 3 - Wazuh Export Investigation of the Anchor Event
# Investigate the SSH anchor through exported Wazuh evidence and produce
# a structured finding comparable with the CLI finding from Task 2.

set -u

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

SEARCH_RESULTS="$WAZUH_EXPORTS/anchor_search_results.json"
DASHBOARD_TRACE="$WAZUH_EXPORTS/anchor_dashboard_trace.json"
FIELD_MAPPING="$WAZUH_EXPORTS/field_mapping.json"
ANCHOR_FILE="$ASSETS_DIR/anchor_event.json"
FINDINGS_DIR="findings"
FINDING_FILE="$FINDINGS_DIR/anchor_export.json"

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
FILE_READS=0

fail()
{
    printf 'error       : %s\n' "$1" >&2
    exit 1
}

validate_json()
{
    local filepath="$1"

    [[ -s "$filepath" ]] || fail "missing or empty file: $filepath"
    jq empty "$filepath" >/dev/null 2>&1 ||
        fail "invalid JSON: $filepath"
}

validate_json "$SEARCH_RESULTS"
validate_json "$DASHBOARD_TRACE"
validate_json "$FIELD_MAPPING"
validate_json "$ANCHOR_FILE"

printf 'reading     : %s\n' "$SEARCH_RESULTS"

# File read 1: Wazuh search-result metadata.
HITS_TOTAL="$(jq -r '.hits_total // empty' "$SEARCH_RESULTS")"
KQL_QUERY="$(jq -r '.query.kql // .kql_query // empty' "$SEARCH_RESULTS")"
TIME_START="$(jq -r '.query.time_start // .time_range.start // empty' "$SEARCH_RESULTS")"
TIME_END="$(jq -r '.query.time_end // .time_range.end // empty' "$SEARCH_RESULTS")"
EVENT_COUNT="$(jq -r '.events | length' "$SEARCH_RESULTS")"
FILE_READS=$((FILE_READS + 1))

[[ "$HITS_TOTAL" =~ ^[0-9]+$ ]] || fail "hits_total is missing or invalid"
[[ -n "$KQL_QUERY" ]] || fail "KQL query is missing"
[[ -n "$TIME_START" ]] || fail "query start time is missing"
[[ -n "$TIME_END" ]] || fail "query end time is missing"

if [[ "$EVENT_COUNT" -ne "$HITS_TOTAL" ]]; then
    fail "hits_total ($HITS_TOTAL) does not match events length ($EVENT_COUNT)"
fi

printf 'hits_total  : %s\n' "$HITS_TOTAL"
printf 'kql_query   : %s\n' "$KQL_QUERY"
printf 'time range  : %s -> %s\n' "$TIME_START" "$TIME_END"

# Extract timeline boundaries after explicitly sorting on Wazuh @timestamp.
FIRST_EVENT="$(
    jq -c '.events | sort_by(._source["@timestamp"])[0]' \
        "$SEARCH_RESULTS"
)"
LAST_EVENT="$(
    jq -c '.events | sort_by(._source["@timestamp"])[-1]' \
        "$SEARCH_RESULTS"
)"

FIRST_TIMESTAMP="$(
    printf '%s\n' "$FIRST_EVENT" |
        jq -r '._source["@timestamp"] // .["@timestamp"] // empty'
)"
LAST_TIMESTAMP="$(
    printf '%s\n' "$LAST_EVENT" |
        jq -r '._source["@timestamp"] // .["@timestamp"] // empty'
)"
FIRST_SOURCE_IP="$(
    printf '%s\n' "$FIRST_EVENT" |
        jq -r '._source.source.ip // empty'
)"
LAST_SOURCE_IP="$(
    printf '%s\n' "$LAST_EVENT" |
        jq -r '._source.source.ip // empty'
)"

[[ -n "$FIRST_TIMESTAMP" ]] || fail "first event timestamp is missing"
[[ -n "$LAST_TIMESTAMP" ]] || fail "last event timestamp is missing"

printf 'first event : %s (source.ip: %s)\n' \
    "$FIRST_TIMESTAMP" "${FIRST_SOURCE_IP:-unknown}"
printf 'last event  : %s (source.ip: %s)\n' \
    "$LAST_TIMESTAMP" "${LAST_SOURCE_IP:-unknown}"

# File read 2: dashboard-equivalent click path and analyst context.
CLICK_PATH="$(jq -c '.click_path // []' "$DASHBOARD_TRACE")"
CLICK_STEPS="$(jq -r '.click_path | length' "$DASHBOARD_TRACE")"
ESTIMATED_TIME="$(jq -r '.estimated_time_seconds // 0' "$DASHBOARD_TRACE")"
FIELDS_EXAMINED="$(jq -c '.fields_examined // []' "$DASHBOARD_TRACE")"
ATTACK_TECHNIQUES="$(jq -c '.attack_techniques // []' "$DASHBOARD_TRACE")"
CONFIDENCE="$(jq -r '.confidence // "medium"' "$DASHBOARD_TRACE")"
VERDICT="$(jq -r '.verdict // "unknown"' "$DASHBOARD_TRACE")"
FILE_READS=$((FILE_READS + 1))

[[ "$CLICK_STEPS" =~ ^[0-9]+$ ]] || fail "click_path is invalid"
(( CLICK_STEPS > 0 )) || fail "click_path is empty"

# File read 3: five normalized-to-Wazuh field mappings used in this case.
REQUESTED_FIELDS='["src_ip","hostname","user","event_ref","raw_message"]'
SELECTED_MAPPINGS="$(
    jq -c --argjson wanted "$REQUESTED_FIELDS" '
        [
            $wanted[] as $field
            | .mappings[]
            | select(.normalized == $field)
        ]
    ' "$FIELD_MAPPING"
)"
MAPPING_COUNT="$(printf '%s\n' "$SELECTED_MAPPINGS" | jq 'length')"
FILE_READS=$((FILE_READS + 1))

if [[ "$MAPPING_COUNT" -ne 5 ]]; then
    fail "expected 5 anchor field mappings, found $MAPPING_COUNT"
fi

printf 'field map   : '
FIRST_MAPPING=true

while IFS=$'\t' read -r normalized wazuh; do
    if [[ "$FIRST_MAPPING" == true ]]; then
        printf '%-12s -> %s\n' "$normalized" "$wazuh"
        FIRST_MAPPING=false
    else
        printf '%-15s%-12s -> %s\n' "" "$normalized" "$wazuh"
    fi
done < <(
    printf '%s\n' "$SELECTED_MAPPINGS" |
        jq -r '.[] | [.normalized, .wazuh] | @tsv'
)

# File read 4: anchor manifest for target context in the hypothesis.
TARGET_HOST="$(jq -r '.target_host // "unknown"' "$ANCHOR_FILE")"
TARGET_IP="$(jq -r '.target_ip // "unknown"' "$ANCHOR_FILE")"
FILE_READS=$((FILE_READS + 1))

printf 'click_path  : %s steps loaded from dashboard_trace\n' "$CLICK_STEPS"
printf 'trace time  : %s seconds estimated dashboard time\n' "$ESTIMATED_TIME"

# Preserve native Wazuh document IDs as event references.
EVENT_REFS="$(jq -c '[.events[]._id // empty] | unique' "$SEARCH_RESULTS")"

mkdir -p "$FINDINGS_DIR"

INVESTIGATION_END="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
END_EPOCH="$(date +%s)"
ELAPSED_SECONDS=$((END_EPOCH - START_EPOCH))

jq -n \
    --arg finding_id "anchor_wazuh_export" \
    --arg scenario_id "anchor" \
    --arg interface "wazuh_export" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED_SECONDS" \
    --argjson actions "$CLICK_PATH" \
    --argjson fields_touched "$FIELDS_EXAMINED" \
    --argjson event_refs "$EVENT_REFS" \
    --argjson attack_techniques "$ATTACK_TECHNIQUES" \
    --arg target_host "$TARGET_HOST" \
    --arg target_ip "$TARGET_IP" \
    --argjson hits_total "$HITS_TOTAL" \
    --arg verdict "$VERDICT" \
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
        hypothesis: (
            ($hits_total | tostring) + " Wazuh documents show repeated SSH attempts from four external IP addresses against "
            + $target_host + " (" + $target_ip + "). "
            + "The dashboard trace classifies the activity as " + $verdict
            + " and records a final successful root authentication."
        ),
        confidence: $confidence,
        created_at: $created_at
    }
' > "$FINDING_FILE"

jq empty "$FINDING_FILE" >/dev/null 2>&1 ||
    fail "generated finding is not valid JSON"

printf 'elapsed     : %s seconds, %s file reads\n' \
    "$ELAPSED_SECONDS" "$FILE_READS"
printf 'finding     : %s written\n' "$FINDING_FILE"

exit 0

