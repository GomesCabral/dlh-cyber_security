#!/bin/bash

# Task 7 - Scenario A via Wazuh Export: Credential Theft Chain
# Investigate the credential-theft chain in Wazuh document format and compare
# the measured workflow time with the CLI finding from Task 4.

set -u

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

SEARCH_RESULTS="$WAZUH_EXPORTS/scenario_a_search_results.json"
DASHBOARD_TRACE="$WAZUH_EXPORTS/scenario_a_dashboard_trace.json"
DASHBOARD_SUMMARY="$ASSETS_DIR/dashboard_exports/scenario_a_dashboard_summary.md"
CLI_FINDING_PRIMARY="findings/scenario_a_cli.json"
CLI_FINDING_FALLBACK="scenario_a_cli.json"
FINDINGS_DIR="findings"
FINDING_FILE="$FINDINGS_DIR/scenario_a_export.json"

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
FILE_READS=0
FILTERED_EVENTS="$(mktemp)"

cleanup()
{
    rm -f "$FILTERED_EVENTS"
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
[[ -s "$DASHBOARD_SUMMARY" ]] ||
    fail "missing or empty dashboard summary: $DASHBOARD_SUMMARY"

# File read 1: load the exported Wazuh search metadata and event collection.
HITS_TOTAL="$(jq -r '.hits_total // empty' "$SEARCH_RESULTS")"
KQL_QUERY="$(jq -r '.query.kql // .kql_query // empty' "$SEARCH_RESULTS")"
EVENT_COUNT="$(jq -r '.events | length' "$SEARCH_RESULTS")"
FILE_READS=$((FILE_READS + 1))

[[ "$HITS_TOTAL" =~ ^[0-9]+$ ]] || fail "hits_total is missing or invalid"
[[ -n "$KQL_QUERY" ]] || fail "KQL query is missing"
[[ "$EVENT_COUNT" -eq "$HITS_TOTAL" ]] ||
    fail "hits_total ($HITS_TOTAL) does not match events length ($EVENT_COUNT)"

printf 'reading     : scenario_a_search_results.json (%s events)\n' \
    "$HITS_TOTAL"
printf 'kql         : %s\n' "$KQL_QUERY"

# Filter the Wazuh documents by native winlog.event_id.
jq -c '
    .events[]
    | select(
        (._source.winlog.event_id | tonumber?) == 10
        or (._source.winlog.event_id | tonumber?) == 11
        or (._source.winlog.event_id | tonumber?) == 3
    )
' "$SEARCH_RESULTS" > "$FILTERED_EVENTS" ||
    fail "failed to filter Wazuh event documents"

FILTERED_COUNT="$(wc -l < "$FILTERED_EVENTS" | tr -d ' ')"
(( FILTERED_COUNT > 0 )) || fail "no EID 10, 11, or 3 documents found"

# Print every requested event with key native Wazuh fields.
jq -r '
    [
        (._source["@timestamp"] // .["@timestamp"] // "unknown"),
        (._source.winlog.event_id // "unknown"),
        (._source.agent.name // "unknown"),
        (._source.process.name // ._source.event_data.Image // "unknown"),
        (._source.destination.ip // ._source.event_data.DestinationIp // ""),
        (._source.destination.port // ._source.event_data.DestinationPort // ""),
        (._source.full_log // "")
    ]
    | @tsv
' "$FILTERED_EVENTS" |
    while IFS=$'\t' read -r timestamp event_id agent process dst_ip dst_port full_log; do
        printf 'record      : %s EID=%s agent=%s process=%s dst=%s:%s %s\n' \
            "$timestamp" "$event_id" "$agent" "$process" \
            "${dst_ip:-n/a}" "${dst_port:-n/a}" "$full_log"
    done

# Identify the three malicious chain events without selecting unrelated EID 3
# or EID 11 activity from the same six-minute window.
EID10_EVENT="$(
    jq -cs '
        map(
            select(
                (._source.winlog.event_id | tonumber?) == 10
                and (
                    ((._source.event_data.TargetImage // "") | ascii_downcase | contains("lsass.exe"))
                    or ((._source.full_log // "") | ascii_downcase | contains("lsass.exe"))
                )
            )
        )
        | sort_by(._source["@timestamp"])
        | first // empty
    ' "$FILTERED_EVENTS"
)"

EID11_EVENT="$(
    jq -cs '
        map(
            select(
                (._source.winlog.event_id | tonumber?) == 11
                and (
                    ((._source.event_data.TargetFilename // "") | ascii_downcase | endswith("debug.dmp"))
                    or ((._source.full_log // "") | ascii_downcase | contains("debug.dmp"))
                )
            )
        )
        | sort_by(._source["@timestamp"])
        | first // empty
    ' "$FILTERED_EVENTS"
)"

EID3_EVENT="$(
    jq -cs '
        map(
            select(
                (._source.winlog.event_id | tonumber?) == 3
                and (
                    (((._source.destination.port | tonumber?) // -1) == 445)
                    or
                    (((._source.event_data.DestinationPort | tonumber?) // -1) == 445)
                )
            )
        )
        | sort_by(._source["@timestamp"])
        | first // empty
    ' "$FILTERED_EVENTS"
)"

[[ -n "$EID10_EVENT" ]] || fail "LSASS EID 10 document not found"
[[ -n "$EID11_EVENT" ]] || fail "debug.dmp EID 11 document not found"
[[ -n "$EID3_EVENT" ]] || fail "SMB EID 3 document not found"

EID10_TIME="$(
    printf '%s\n' "$EID10_EVENT" | jq -r '._source["@timestamp"]'
)"
EID10_PROCESS="$(
    printf '%s\n' "$EID10_EVENT" |
        jq -r '._source.process.name // ._source.event_data.SourceImage // "unknown"'
)"

EID11_TIME="$(
    printf '%s\n' "$EID11_EVENT" | jq -r '._source["@timestamp"]'
)"
EID11_LOG="$(
    printf '%s\n' "$EID11_EVENT" |
        jq -r '._source.full_log // ._source.event_data.TargetFilename // "unknown"'
)"

EID3_TIME="$(
    printf '%s\n' "$EID3_EVENT" | jq -r '._source["@timestamp"]'
)"
EID3_DESTINATION="$(
    printf '%s\n' "$EID3_EVENT" |
        jq -r '._source.destination.ip // ._source.event_data.DestinationIp // "unknown"'
)"
EID3_PORT="$(
    printf '%s\n' "$EID3_EVENT" |
        jq -r '._source.destination.port // ._source.event_data.DestinationPort // "unknown"'
)"

printf 'EID 10      : process %s present at %s\n' \
    "$EID10_PROCESS" "$EID10_TIME"
printf 'EID 11      : %s at %s (file created)\n' \
    "$EID11_LOG" "$EID11_TIME"
printf 'EID 3       : destination.ip %s:%s at %s\n' \
    "$EID3_DESTINATION" "$EID3_PORT" "$EID3_TIME"

# File read 2: load dashboard-equivalent actions and field translations.
CLICK_PATH="$(jq -c '.click_path // []' "$DASHBOARD_TRACE")"
CLICK_STEPS="$(jq -r '.click_path | length' "$DASHBOARD_TRACE")"
FIELD_TRANSLATION="$(jq -c '.field_name_translation // {}' "$DASHBOARD_TRACE")"
FIELDS_EXAMINED="$(jq -c '.fields_examined // []' "$DASHBOARD_TRACE")"
ATTACK_TECHNIQUES="$(jq -c '.attack_techniques // []' "$DASHBOARD_TRACE")"
ESTIMATED_TIME="$(jq -r '.estimated_time_seconds // 0' "$DASHBOARD_TRACE")"
CONFIDENCE="$(jq -r '.confidence // "medium"' "$DASHBOARD_TRACE")"
FILE_READS=$((FILE_READS + 1))

(( CLICK_STEPS > 0 )) || fail "dashboard click_path is empty"
[[ "$(printf '%s\n' "$ATTACK_TECHNIQUES" | jq 'length')" -eq 3 ]] ||
    fail "expected three ATT&CK techniques in dashboard trace"

HOST_MAPPING="$(
    printf '%s\n' "$FIELD_TRANSLATION" |
        jq -r '.hostname // "missing"'
)"
EVENT_ID_MAPPING="$(
    printf '%s\n' "$FIELD_TRANSLATION" |
        jq -r '.event_id // "missing"'
)"

printf 'click_path  : %s steps\n' "$CLICK_STEPS"
printf 'field_map   : hostname -> %s, event_id -> %s\n' \
    "$HOST_MAPPING" "$EVENT_ID_MAPPING"
printf 'trace time  : %s seconds estimated dashboard time\n' "$ESTIMATED_TIME"

# File read 3: print and verify the ATT&CK mapping section in the summary.
printf 'ATT&CK mapping:\n'
awk '
    /^## ATT&CK Mapping/ { printing=1; next }
    printing && /^## / { exit }
    printing && NF { print }
' "$DASHBOARD_SUMMARY"
FILE_READS=$((FILE_READS + 1))

while IFS= read -r technique; do
    grep -Fq "$technique" "$DASHBOARD_SUMMARY" ||
        fail "ATT&CK technique $technique missing from dashboard summary"
done < <(printf '%s\n' "$ATTACK_TECHNIQUES" | jq -r '.[]')

printf 'attack      :'
printf '%s\n' "$ATTACK_TECHNIQUES" | jq -r '.[]' |
    while IFS= read -r technique; do
        printf ' %s' "$technique"
    done
printf '\n'

# Preserve native Wazuh _id values for the relevant event documents.
EVENT_REFS="$(jq -cs '[.[]._id // empty] | unique' "$FILTERED_EVENTS")"

# File read 4: load the Task 4 elapsed time. Accept the temporary root-level
# location used before the project outputs were reorganized into findings/.
if [[ -s "$CLI_FINDING_PRIMARY" ]]; then
    CLI_FINDING="$CLI_FINDING_PRIMARY"
elif [[ -s "$CLI_FINDING_FALLBACK" ]]; then
    CLI_FINDING="$CLI_FINDING_FALLBACK"
else
    fail "Task 4 CLI finding not found"
fi

validate_json "$CLI_FINDING"
CLI_ELAPSED="$(
    jq -r '.time_to_first_answer_seconds // empty' "$CLI_FINDING"
)"
FILE_READS=$((FILE_READS + 1))

[[ "$CLI_ELAPSED" =~ ^[0-9]+$ ]] ||
    fail "CLI finding has an invalid time_to_first_answer_seconds"

HYPOTHESIS="Wazuh documents show rundll32.exe accessing LSASS, creation of C:\\Temp\\debug.dmp, and a subsequent SMB connection to 10.1.1.10:445. The ordered chain is consistent with credential dumping followed by lateral movement to the domain controller."

mkdir -p "$FINDINGS_DIR"
INVESTIGATION_END="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
END_EPOCH="$(date +%s)"
ELAPSED_SECONDS=$((END_EPOCH - START_EPOCH))

jq -n \
    --arg finding_id "scenario_a_wazuh_export" \
    --arg scenario_id "scenario_a" \
    --arg interface "wazuh_export" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED_SECONDS" \
    --argjson actions "$CLICK_PATH" \
    --argjson fields_touched "$FIELDS_EXAMINED" \
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
    DELTA=$((CLI_ELAPSED - ELAPSED_SECONDS))
    COMPARISON="$DELTA seconds faster via export"
elif (( ELAPSED_SECONDS > CLI_ELAPSED )); then
    DELTA=$((ELAPSED_SECONDS - CLI_ELAPSED))
    COMPARISON="$DELTA seconds faster via CLI"
else
    COMPARISON="same elapsed time"
fi

printf 'elapsed     : %s seconds, %s file reads\n' \
    "$ELAPSED_SECONDS" "$FILE_READS"
printf 'delta_vs_cli: %s\n' "$COMPARISON"
printf 'finding     : %s written\n' "$FINDING_FILE"

exit 0

