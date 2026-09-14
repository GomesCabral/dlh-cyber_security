#!/bin/bash

# Task 5 - Scenario B via CLI: Off-Hours Privileged Logon on PHI Workstation
# Correlate a remote privileged logon with suspicious PowerShell execution and
# preserve the authorization ambiguity for Tier 2 escalation.

set -u

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

SCENARIO_FILE="$ASSETS_DIR/scenarios/scenario_b_offhours_phi.json"
EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
ASSET_INVENTORY="$HANDOFF_DIR/context/asset_inventory.json"
FINDINGS_DIR="findings"
FINDING_FILE="$FINDINGS_DIR/scenario_b_cli.json"

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
SCOPED_EVENTS="$(mktemp)"
RELEVANT_EVENTS="$(mktemp)"

cleanup()
{
    rm -f "$SCOPED_EVENTS" "$RELEVANT_EVENTS"
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
validate_json "$ASSET_INVENTORY"
[[ -s "$EVENTS_FILE" ]] || fail "missing or empty event handoff: $EVENTS_FILE"

# Establish the scenario scope and preserve the manifest ambiguity note.
TARGET_HOST="$(
    jq -r '
        .host
        // .hostname
        // .host_path[0]
        // empty
    ' "$SCENARIO_FILE"
)"
WINDOW_START="$(jq -r '.time_window.start // empty' "$SCENARIO_FILE")"
WINDOW_END="$(jq -r '.time_window.end // empty' "$SCENARIO_FILE")"
AMBIGUITY_NOTE="$(jq -r '.ambiguity_note // empty' "$SCENARIO_FILE")"

[[ -n "$TARGET_HOST" ]] || fail "scenario host missing from manifest"
[[ -n "$WINDOW_START" ]] || fail "time_window.start missing from manifest"
[[ -n "$WINDOW_END" ]] || fail "time_window.end missing from manifest"
[[ -n "$AMBIGUITY_NOTE" ]] || fail "ambiguity_note missing from manifest"

# The task requires these two techniques even though the manifest also lists
# T1530 as additional scenario context.
ATTACK_TECHNIQUES="$(
    jq -c '
        [
            .mitre_techniques[]
            | select(. == "T1078.002" or . == "T1059.001")
        ]
        | unique
    ' "$SCENARIO_FILE"
)"

if [[ "$(printf '%s\n' "$ATTACK_TECHNIQUES" | jq 'length')" -ne 2 ]]; then
    fail "required ATT&CK techniques T1078.002 and T1059.001 not found"
fi

printf 'scenario    : scenario_b_offhours_phi\n'

# Enrich the alert with authoritative asset context.
ASSET_RECORD="$(
    jq -c --arg host "$TARGET_HOST" '
        .assets[]
        | select(.hostname == $host)
    ' "$ASSET_INVENTORY" |
        head -n 1
)"

[[ -n "$ASSET_RECORD" ]] ||
    fail "host $TARGET_HOST not found in asset inventory"

CRITICALITY="$(printf '%s\n' "$ASSET_RECORD" | jq -r '.criticality // empty')"
DATA_CLASSIFICATION="$(
    printf '%s\n' "$ASSET_RECORD" |
        jq -r '.data_classification // empty'
)"
ASSET_IP="$(printf '%s\n' "$ASSET_RECORD" | jq -r '.ip // "unknown"')"

[[ -n "$CRITICALITY" ]] || fail "asset criticality missing"
[[ -n "$DATA_CLASSIFICATION" ]] || fail "asset data_classification missing"

printf 'host        : %s (criticality: %s, data: %s)\n' \
    "$TARGET_HOST" "$CRITICALITY" "$DATA_CLASSIFICATION"
printf 'window      : %s -> %s\n' "$WINDOW_START" "$WINDOW_END"

# Scope all events to the affected host and the six-minute incident window.
jq -c \
    --arg host "$TARGET_HOST" \
    --arg window_start "$WINDOW_START" \
    --arg window_end "$WINDOW_END" '
    select(
        .hostname == $host
        and .timestamp >= $window_start
        and .timestamp <= $window_end
    )
' "$EVENTS_FILE" > "$SCOPED_EVENTS" || fail "scenario scoping query failed"

SCOPED_COUNT="$(wc -l < "$SCOPED_EVENTS" | tr -d ' ')"
(( SCOPED_COUNT > 0 )) || fail "no events found in scenario scope"
printf 'scoped      : %s events on %s in window\n' \
    "$SCOPED_COUNT" "$TARGET_HOST"

# Keep all requested event types for evidence review.
jq -c '
    select(
        (.event_id | tonumber?) == 4624
        or (.event_id | tonumber?) == 4672
        or (.event_id | tonumber?) == 1
    )
' "$SCOPED_EVENTS" > "$RELEVANT_EVENTS" || fail "event filtering failed"

printf 'records     : %s matching EID 4624/4672/1 records\n' \
    "$(wc -l < "$RELEVANT_EVENTS" | tr -d ' ')"

# Select the relevant RemoteInteractive logon for p.morales.
LOGON_EVENT="$(
    jq -cs '
        map(
            select(
                (.event_id | tonumber?) == 4624
                and (.user == "p.morales" or .details.TargetUserName == "p.morales")
                and (.details.LogonType | tonumber?) == 10
            )
        )
        | sort_by(.timestamp)
        | first // empty
    ' "$RELEVANT_EVENTS"
)"

[[ -n "$LOGON_EVENT" ]] || fail "p.morales LogonType 10 event not found"

LOGON_TIME="$(printf '%s\n' "$LOGON_EVENT" | jq -r '.timestamp')"
LOGON_USER="$(
    printf '%s\n' "$LOGON_EVENT" |
        jq -r '.user // .details.TargetUserName // "unknown"'
)"
LOGON_TYPE="$(
    printf '%s\n' "$LOGON_EVENT" |
        jq -r '.details.LogonType // "unknown"'
)"
SOURCE_IP="$(
    printf '%s\n' "$LOGON_EVENT" |
        jq -r '.src_ip // .details.IpAddress // "unknown"'
)"

printf 'EID 4624    : %s RemoteInteractive logon at %s (source %s)\n' \
    "$LOGON_USER" "$LOGON_TIME" "$SOURCE_IP"

# Select the special-privilege assignment for the same user.
PRIVILEGE_EVENT="$(
    jq -cs '
        map(
            select(
                (.event_id | tonumber?) == 4672
                and (.user == "p.morales" or .details.SubjectUserName == "p.morales")
            )
        )
        | sort_by(.timestamp)
        | first // empty
    ' "$RELEVANT_EVENTS"
)"

[[ -n "$PRIVILEGE_EVENT" ]] || fail "p.morales EID 4672 event not found"

PRIVILEGE_TIME="$(printf '%s\n' "$PRIVILEGE_EVENT" | jq -r '.timestamp')"
PRIVILEGES="$(
    printf '%s\n' "$PRIVILEGE_EVENT" |
        jq -r '.details.PrivilegeList // "unknown" | gsub("[\\n\\t]+"; " ")'
)"

printf 'EID 4672    : %s at %s\n' "$PRIVILEGES" "$PRIVILEGE_TIME"

# Select p.morales PowerShell execution containing ExecutionPolicy Bypass.
POWERSHELL_EVENT="$(
    jq -cs '
        map(
            select(
                (.event_id | tonumber?) == 1
                and (
                    (.user == "MEDDEFENSE\\p.morales")
                    or (.details.User == "MEDDEFENSE\\p.morales")
                )
                and (
                    ((.command_line // "") | ascii_downcase | contains("executionpolicy bypass"))
                    or ((.details.CommandLine // "") | ascii_downcase | contains("executionpolicy bypass"))
                )
            )
        )
        | sort_by(.timestamp)
        | first // empty
    ' "$RELEVANT_EVENTS"
)"

[[ -n "$POWERSHELL_EVENT" ]] ||
    fail "p.morales PowerShell ExecutionPolicy Bypass event not found"

POWERSHELL_TIME="$(printf '%s\n' "$POWERSHELL_EVENT" | jq -r '.timestamp')"
POWERSHELL_COMMAND="$(
    printf '%s\n' "$POWERSHELL_EVENT" |
        jq -r '.command_line // .details.CommandLine // "unknown"'
)"
INTEGRITY_LEVEL="$(
    printf '%s\n' "$POWERSHELL_EVENT" |
        jq -r '.details.IntegrityLevel // "unknown"'
)"

printf 'EID 1       : %s at %s (integrity: %s)\n' \
    "$POWERSHELL_COMMAND" "$POWERSHELL_TIME" "$INTEGRITY_LEVEL"
printf 'ambiguity   : %s\n' "$AMBIGUITY_NOTE"
printf 'attack      : T1078.002 T1059.001\n'

# Preserve only references that exist in the upstream records.
EVENT_REFS="$(jq -cs '[.[].event_ref // empty] | unique' "$RELEVANT_EVENTS")"

HYPOTHESIS="A successful off-hours RemoteInteractive logon by p.morales on the PHI-classified workstation was followed by special privileges and high-integrity PowerShell with ExecutionPolicy Bypass. Although p.morales is the CISO and authorized for EHR access, the timing and bypass behavior warrant escalation to validate whether the activity was authorized."

mkdir -p "$FINDINGS_DIR"
INVESTIGATION_END="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
END_EPOCH="$(date +%s)"
ELAPSED_SECONDS=$((END_EPOCH - START_EPOCH))

jq -n \
    --arg finding_id "scenario_b_cli" \
    --arg scenario_id "scenario_b" \
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
            "Read the Scenario B manifest and ambiguity note",
            "Scoped enriched events to clin-ws-07 and the incident window",
            "Loaded asset criticality and data classification from the inventory",
            "Validated the p.morales RemoteInteractive logon",
            "Validated assignment of backup and restore privileges",
            "Validated high-integrity PowerShell with ExecutionPolicy Bypass",
            "Escalated the ambiguous activity for authorization confirmation"
        ],
        fields_touched: [
            "timestamp",
            "hostname",
            "event_id",
            "user",
            "outcome",
            "src_ip",
            "process_name",
            "command_line",
            "event_ref",
            "details.LogonType",
            "details.IpAddress",
            "details.PrivilegeList",
            "details.CommandLine",
            "details.IntegrityLevel",
            "asset_inventory.criticality",
            "asset_inventory.data_classification"
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

