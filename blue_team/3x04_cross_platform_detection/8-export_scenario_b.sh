#!/bin/bash

# Task 8 - Scenario B via Wazuh Export: Off-Hours Privileged Logon
# Investigate the PHI workstation logon through exported Wazuh documents and
# record whether asset classification required an inventory fallback.

set -u

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

SEARCH_RESULTS="$WAZUH_EXPORTS/scenario_b_search_results.json"
DASHBOARD_TRACE="$WAZUH_EXPORTS/scenario_b_dashboard_trace.json"
ASSET_INVENTORY="$HANDOFF_DIR/context/asset_inventory.json"
CLI_FINDING_PRIMARY="findings/scenario_b_cli.json"
CLI_FINDING_FALLBACK="scenario_b_cli.json"
FINDINGS_DIR="findings"
FINDING_FILE="$FINDINGS_DIR/scenario_b_export.json"

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

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

# Read Wazuh search metadata and verify the exported event array.
HITS_TOTAL="$(jq -r '.hits_total // empty' "$SEARCH_RESULTS")"
EVENT_COUNT="$(jq -r '.events | length' "$SEARCH_RESULTS")"
KQL_QUERY="$(jq -r '.query.kql // .kql_query // empty' "$SEARCH_RESULTS")"

[[ "$HITS_TOTAL" =~ ^[0-9]+$ ]] || fail "hits_total is missing or invalid"
[[ "$EVENT_COUNT" -eq "$HITS_TOTAL" ]] ||
    fail "hits_total ($HITS_TOTAL) does not match events length ($EVENT_COUNT)"

printf 'reading     : scenario_b_search_results.json (%s events)\n' \
    "$EVENT_COUNT"
printf 'kql         : %s\n' "$KQL_QUERY"

# Print the required Wazuh fields for every exported event. Direct jq string
# formatting prevents null fields from shifting columns in a TSV table.
jq -r '
    .events[]
    | "event       : "
      + (._source["@timestamp"] // .["@timestamp"] // "unknown")
      + " agent=" + (._source.agent.name // "unknown")
      + " user=" + (._source.user.name // "n/a")
      + " EID=" + (._source.winlog.event_id // "unknown" | tostring)
      + " labels=" + (._source.agent.labels // {} | tojson)
' "$SEARCH_RESULTS"

# Extract the host and primary user from the relevant logon event.
HOST="$(
    jq -r '
        [
            .events[]
            | select((._source.winlog.event_id | tonumber?) == 4624)
            | ._source.agent.name
            | select(. != null and . != "")
        ]
        | first // empty
    ' "$SEARCH_RESULTS"
)"
USER_NAME="$(
    jq -r '
        [
            .events[]
            | select((._source.winlog.event_id | tonumber?) == 4624)
            | ._source.user.name
            | select(. != null and . != "")
        ]
        | first // empty
    ' "$SEARCH_RESULTS"
)"
LOGON_TIMESTAMP="$(
    jq -r '
        [
            .events[]
            | select(
                (._source.winlog.event_id | tonumber?) == 4624
                and (._source.event_data.LogonType | tonumber?) == 10
            )
        ]
        | sort_by(._source["@timestamp"])
        | first
        | ._source["@timestamp"] // empty
    ' "$SEARCH_RESULTS"
)"

[[ -n "$HOST" ]] || fail "host not found in Wazuh events"
[[ -n "$USER_NAME" ]] || fail "user not found in Wazuh logon event"
[[ -n "$LOGON_TIMESTAMP" ]] || fail "RemoteInteractive logon timestamp not found"

printf 'host        : %s (from agent.name)\n' "$HOST"
printf 'user        : %s (from user.name)\n' "$USER_NAME"

# Determine whether Wazuh labels contain data classification.
DATA_CLASSIFICATION="$(
    jq -r '
        [
            .events[]
            | ._source.agent.labels.data_classification
            | select(. != null and . != "")
        ]
        | unique
        | first // empty
    ' "$SEARCH_RESULTS"
)"

FALLBACK_REQUIRED=false
FALLBACK_ACTION="Data classification resolved directly from agent.labels"

if [[ -n "$DATA_CLASSIFICATION" ]]; then
    DATA_SOURCE="agent.labels"
else
    FALLBACK_REQUIRED=true
    validate_json "$ASSET_INVENTORY"

    ASSET_RECORD="$(
        jq -c --arg host "$HOST" '
            .assets[]
            | select(.hostname == $host)
        ' "$ASSET_INVENTORY" |
            head -n 1
    )"

    [[ -n "$ASSET_RECORD" ]] ||
        fail "host $HOST not found in asset inventory fallback"

    DATA_CLASSIFICATION="$(
        printf '%s\n' "$ASSET_RECORD" |
            jq -r '.data_classification // empty'
    )"
    [[ -n "$DATA_CLASSIFICATION" ]] ||
        fail "data_classification missing from asset inventory"

    DATA_SOURCE="asset_inventory.json fallback"
    FALLBACK_ACTION="Data classification absent from agent.labels; checked asset_inventory.json and resolved PHI"
fi

printf 'data_class  : %s (from %s)\n' \
    "$DATA_CLASSIFICATION" "$DATA_SOURCE"

# Determine whether the logon occurred outside 06:00-18:00 UTC.
LOGON_HOUR="$(date -u -d "$LOGON_TIMESTAMP" +'%H')"
LOGON_MINUTE="$(date -u -d "$LOGON_TIMESTAMP" +'%M')"
LOGON_HOUR_NUMBER=$((10#$LOGON_HOUR))

if (( LOGON_HOUR_NUMBER < 6 || LOGON_HOUR_NUMBER >= 18 )); then
    OFF_HOURS=true
    printf 'off_hours   : %s:%sZ outside 06:00-18:00 window\n' \
        "$LOGON_HOUR" "$LOGON_MINUTE"
else
    OFF_HOURS=false
    printf 'off_hours   : no (%s:%sZ is inside 06:00-18:00)\n' \
        "$LOGON_HOUR" "$LOGON_MINUTE"
fi

# Load the dashboard-equivalent analyst actions.
CLICK_PATH="$(jq -c '.click_path // []' "$DASHBOARD_TRACE")"
CLICK_STEPS="$(jq -r '.click_path | length' "$DASHBOARD_TRACE")"
TRACE_FIELDS="$(jq -c '.fields_examined // []' "$DASHBOARD_TRACE")"
TRACE_TECHNIQUES="$(jq -c '.attack_techniques // []' "$DASHBOARD_TRACE")"
CONFIDENCE="$(jq -r '.confidence // "medium"' "$DASHBOARD_TRACE")"

(( CLICK_STEPS > 0 )) || fail "dashboard click_path is empty"
printf 'click_path  : %s steps\n' "$CLICK_STEPS"

# Add the inventory pivot to the ordered dashboard action history only when
# Wazuh agent.labels does not contain the classification.
ACTIONS="$(
    jq -n \
        --argjson click_path "$CLICK_PATH" \
        --arg fallback_action "$FALLBACK_ACTION" '
        $click_path + [$fallback_action]
    '
)"

# The task requires these two techniques. T1530 remains trace context but is
# outside the locked technique list requested for this finding.
ATTACK_TECHNIQUES="$(
    printf '%s\n' "$TRACE_TECHNIQUES" |
        jq '[.[] | select(. == "T1078.002" or . == "T1059.001")] | unique'
)"

[[ "$(printf '%s\n' "$ATTACK_TECHNIQUES" | jq 'length')" -eq 2 ]] ||
    fail "required ATT&CK techniques missing from dashboard trace"

printf 'attack      : T1078.002 T1059.001\n'

# Add the fallback field to fields_touched when a separate inventory lookup was
# necessary.
FIELDS_TOUCHED="$(
    jq -n \
        --argjson trace_fields "$TRACE_FIELDS" \
        --argjson fallback_required "$FALLBACK_REQUIRED" '
        if $fallback_required then
            ($trace_fields
            + ["agent.labels", "asset_inventory.data_classification"])
            | unique
        else
            ($trace_fields + ["agent.labels.data_classification"])
            | unique
        end
    '
)"

EVENT_REFS="$(jq -c '[.events[]._id // empty] | unique' "$SEARCH_RESULTS")"

if [[ "$OFF_HOURS" == true ]]; then
    HYPOTHESIS="An off-hours RemoteInteractive logon by p.morales on a PHI workstation was followed by special privileges and PowerShell with ExecutionPolicy Bypass. Although the user is authorized for EHR access, the timing and execution behavior require escalation to confirm whether the session was legitimate."
else
    HYPOTHESIS="A privileged RemoteInteractive logon by p.morales on a PHI workstation was followed by special privileges and PowerShell with ExecutionPolicy Bypass. The execution behavior requires escalation to confirm whether the session was legitimate."
fi

# Load the CLI timing for the comparison required by the task.
if [[ -s "$CLI_FINDING_PRIMARY" ]]; then
    CLI_FINDING="$CLI_FINDING_PRIMARY"
elif [[ -s "$CLI_FINDING_FALLBACK" ]]; then
    CLI_FINDING="$CLI_FINDING_FALLBACK"
else
    fail "Task 5 CLI finding not found"
fi

validate_json "$CLI_FINDING"
CLI_ELAPSED="$(jq -r '.time_to_first_answer_seconds // empty' "$CLI_FINDING")"
[[ "$CLI_ELAPSED" =~ ^[0-9]+$ ]] || fail "invalid CLI elapsed time"

mkdir -p "$FINDINGS_DIR"
INVESTIGATION_END="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
END_EPOCH="$(date +%s)"
ELAPSED_SECONDS=$((END_EPOCH - START_EPOCH))

jq -n \
    --arg finding_id "scenario_b_wazuh_export" \
    --arg scenario_id "scenario_b" \
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
    DELTA=$((CLI_ELAPSED - ELAPSED_SECONDS))
    COMPARISON="$DELTA seconds faster via export"
elif (( ELAPSED_SECONDS > CLI_ELAPSED )); then
    DELTA=$((ELAPSED_SECONDS - CLI_ELAPSED))
    COMPARISON="$DELTA seconds faster via CLI"
else
    COMPARISON="same elapsed time"
fi

printf 'fallback    : %s\n' "$FALLBACK_ACTION"
printf 'elapsed     : %s seconds\n' "$ELAPSED_SECONDS"
printf 'delta_vs_cli: %s\n' "$COMPARISON"
printf 'finding     : %s written\n' "$FINDING_FILE"

exit 0

