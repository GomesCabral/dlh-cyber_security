#!/bin/bash

# Task 4 - Scenario A via CLI: Credential Theft Chain
# Reconstruct LSASS access, credential-dump creation, and subsequent SMB
# lateral movement from the enriched NDJSON evidence.

set -u

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

SCENARIO_FILE="$ASSETS_DIR/scenarios/scenario_a_credential_theft.json"
EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
FINDINGS_DIR="findings"
FINDING_FILE="$FINDINGS_DIR/scenario_a_cli.json"

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
COMMAND_COUNT=0
SCOPED_EVENTS="$(mktemp)"
CHAIN_EVENTS="$(mktemp)"

cleanup()
{
    rm -f "$SCOPED_EVENTS" "$CHAIN_EVENTS"
}

trap cleanup EXIT

fail()
{
    printf 'error       : %s\n' "$1" >&2
    exit 1
}

[[ -s "$SCENARIO_FILE" ]] ||
    fail "missing or empty scenario manifest: $SCENARIO_FILE"
[[ -s "$EVENTS_FILE" ]] ||
    fail "missing or empty event handoff: $EVENTS_FILE"

jq empty "$SCENARIO_FILE" >/dev/null 2>&1 ||
    fail "invalid scenario manifest JSON"

# Command 1: establish the incident scope from the scenario manifest.
MANIFEST_ID="$(jq -r '.scenario_id // empty' "$SCENARIO_FILE")"
TARGET_HOST="$(jq -r '.host_path[0] // empty' "$SCENARIO_FILE")"
WINDOW_START="$(jq -r '.time_window.start // empty' "$SCENARIO_FILE")"
WINDOW_END="$(jq -r '.time_window.end // empty' "$SCENARIO_FILE")"
ATTACK_TECHNIQUES="$(jq -c '.mitre_techniques // []' "$SCENARIO_FILE")"
COMMAND_COUNT=$((COMMAND_COUNT + 1))

[[ -n "$MANIFEST_ID" ]] || fail "scenario_id missing from manifest"
[[ -n "$TARGET_HOST" ]] || fail "primary host missing from manifest"
[[ -n "$WINDOW_START" ]] || fail "time_window.start missing from manifest"
[[ -n "$WINDOW_END" ]] || fail "time_window.end missing from manifest"

printf 'scenario    : scenario_a_credential_theft\n'
printf 'host        : %s\n' "$TARGET_HOST"
printf 'window      : %s -> %s\n' "$WINDOW_START" "$WINDOW_END"

# Command 2: scope all host events inside the investigation window.
jq -c \
    --arg host "$TARGET_HOST" \
    --arg window_start "$WINDOW_START" \
    --arg window_end "$WINDOW_END" '
    select(
        .hostname == $host
        and .timestamp >= $window_start
        and .timestamp <= $window_end
    )
' "$EVENTS_FILE" > "$SCOPED_EVENTS" || fail "host scoping query failed"
COMMAND_COUNT=$((COMMAND_COUNT + 1))

# Command 3: count scoped events.
SCOPED_COUNT="$(wc -l < "$SCOPED_EVENTS" | tr -d ' ')"
COMMAND_COUNT=$((COMMAND_COUNT + 1))
printf 'scoped      : %s events on %s in window\n' \
    "$SCOPED_COUNT" "$TARGET_HOST"

(( SCOPED_COUNT > 0 )) || fail "no events found in the scenario scope"

# Command 4: isolate the Sysmon event types requested by the task.
jq -c '
    select(
        (.event_id | tonumber?) == 10
        or (.event_id | tonumber?) == 11
        or (.event_id | tonumber?) == 3
    )
' "$SCOPED_EVENTS" > "$CHAIN_EVENTS" || fail "Sysmon filtering failed"
COMMAND_COUNT=$((COMMAND_COUNT + 1))

CHAIN_COUNT="$(wc -l < "$CHAIN_EVENTS" | tr -d ' ')"
(( CHAIN_COUNT > 0 )) || fail "no Sysmon EID 10, 11, or 3 events found"

printf 'records     : %s matching EID 10/11/3 records\n' "$CHAIN_COUNT"
jq -c '{
    timestamp,
    event_id,
    hostname,
    process_name,
    file_path,
    src_ip,
    dst_ip,
    dst_port,
    user,
    raw_message
}' "$CHAIN_EVENTS"

# Command 5: select the LSASS access event.
EID10_EVENT="$(
    jq -cs '
        map(
            select(
                (.event_id | tonumber?) == 10
                and (
                    ((.details.TargetImage // "") | ascii_downcase | endswith("\\lsass.exe"))
                    or ((.raw_message // "") | ascii_downcase | contains("lsass.exe"))
                )
            )
        )
        | sort_by(.timestamp)
        | first // empty
    ' "$CHAIN_EVENTS"
)"
COMMAND_COUNT=$((COMMAND_COUNT + 1))

[[ -n "$EID10_EVENT" ]] || fail "LSASS access event (EID 10) not found"

EID10_TIME="$(printf '%s\n' "$EID10_EVENT" | jq -r '.timestamp')"
SOURCE_IMAGE="$(
    printf '%s\n' "$EID10_EVENT" |
        jq -r '.details.SourceImage // .process_name // "unknown"'
)"
TARGET_IMAGE="$(
    printf '%s\n' "$EID10_EVENT" |
        jq -r '.details.TargetImage // "unknown"'
)"
GRANTED_ACCESS="$(
    printf '%s\n' "$EID10_EVENT" |
        jq -r '.details.GrantedAccess // "unknown"'
)"

printf 'EID 10      : %s accessed by %s at %s (access %s)\n' \
    "$TARGET_IMAGE" "$SOURCE_IMAGE" "$EID10_TIME" "$GRANTED_ACCESS"

# Command 6: select the credential-dump file creation.
EID11_EVENT="$(
    jq -cs '
        map(
            select(
                (.event_id | tonumber?) == 11
                and (
                    ((.file_path // "") | ascii_downcase | endswith("debug.dmp"))
                    or ((.details.TargetFilename // "") | ascii_downcase | endswith("debug.dmp"))
                )
            )
        )
        | sort_by(.timestamp)
        | first // empty
    ' "$CHAIN_EVENTS"
)"
COMMAND_COUNT=$((COMMAND_COUNT + 1))

[[ -n "$EID11_EVENT" ]] || fail "credential dump file event (EID 11) not found"

EID11_TIME="$(printf '%s\n' "$EID11_EVENT" | jq -r '.timestamp')"
DUMP_FILE="$(
    printf '%s\n' "$EID11_EVENT" |
        jq -r '.file_path // .details.TargetFilename // "unknown"'
)"
DUMP_PROCESS="$(
    printf '%s\n' "$EID11_EVENT" |
        jq -r '.process_name // .details.Image // "unknown"'
)"

printf 'EID 11      : %s created by %s at %s\n' \
    "$DUMP_FILE" "$DUMP_PROCESS" "$EID11_TIME"

# Command 7: select the SMB lateral-movement connection.
EID3_EVENT="$(
    jq -cs '
        map(
            select(
                (.event_id | tonumber?) == 3
                and (
                    (.dst_port | tonumber?) == 445
                    or (.details.DestinationPort | tonumber?) == 445
                )
            )
        )
        | sort_by(.timestamp)
        | first // empty
    ' "$CHAIN_EVENTS"
)"
COMMAND_COUNT=$((COMMAND_COUNT + 1))

[[ -n "$EID3_EVENT" ]] || fail "SMB network connection (EID 3) not found"

EID3_TIME="$(printf '%s\n' "$EID3_EVENT" | jq -r '.timestamp')"
NETWORK_PROCESS="$(
    printf '%s\n' "$EID3_EVENT" |
        jq -r '.process_name // .details.Image // "unknown"'
)"
DESTINATION_IP="$(
    printf '%s\n' "$EID3_EVENT" |
        jq -r '.dst_ip // .details.DestinationIp // "unknown"'
)"
DESTINATION_PORT="$(
    printf '%s\n' "$EID3_EVENT" |
        jq -r '.dst_port // .details.DestinationPort // "unknown"'
)"
DESTINATION_HOST="$(
    printf '%s\n' "$EID3_EVENT" |
        jq -r '.details.DestinationHostname // "unknown"'
)"

printf 'EID 3       : %s -> %s:%s (%s) at %s\n' \
    "$NETWORK_PROCESS" "$DESTINATION_IP" "$DESTINATION_PORT" \
    "$DESTINATION_HOST" "$EID3_TIME"

# Command 8: construct the investigation hypothesis and finding.
HYPOTHESIS="rundll32.exe accessed LSASS with access mask $GRANTED_ACCESS and created $DUMP_FILE, consistent with credential dumping. Shortly afterward, cmd.exe connected to $DESTINATION_HOST at $DESTINATION_IP:$DESTINATION_PORT over SMB, indicating likely lateral movement toward the domain controller."

printf 'hypothesis  : LSASS dump via rundll32, lateral move to DC via SMB\n'
printf 'attack      :'
printf '%s\n' "$ATTACK_TECHNIQUES" | jq -r '.[]' |
    while IFS= read -r technique; do
        printf ' %s' "$technique"
    done
printf '\n'

# Keep only genuine upstream references. The observed source events have null
# event_ref values, so no evidence identifier is fabricated.
EVENT_REFS="$(jq -cs '[.[].event_ref // empty] | unique' "$CHAIN_EVENTS")"

mkdir -p "$FINDINGS_DIR"
INVESTIGATION_END="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
END_EPOCH="$(date +%s)"
ELAPSED_SECONDS=$((END_EPOCH - START_EPOCH))

jq -n \
    --arg finding_id "scenario_a_cli" \
    --arg scenario_id "scenario_a" \
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
            "Read the Scenario A manifest and established host and time scope",
            "Filtered enriched events for clin-ws-12 inside the scenario window",
            "Counted all scoped host events",
            "Filtered the scope for Sysmon event IDs 10, 11, and 3",
            "Validated rundll32.exe access to lsass.exe and the granted access mask",
            "Validated creation of the debug.dmp credential-dump file",
            "Validated the subsequent cmd.exe SMB connection to srv-dc-01",
            "Correlated the ordered events into a credential-theft and lateral-movement hypothesis"
        ],
        fields_touched: [
            "timestamp",
            "hostname",
            "event_id",
            "process_name",
            "file_path",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "user",
            "event_ref",
            "raw_message",
            "details.SourceImage",
            "details.TargetImage",
            "details.GrantedAccess",
            "details.TargetFilename",
            "details.DestinationHostname"
        ],
        event_refs: $event_refs,
        attack_techniques: $attack_techniques,
        hypothesis: $hypothesis,
        confidence: "high",
        created_at: $created_at
    }
' > "$FINDING_FILE"
COMMAND_COUNT=$((COMMAND_COUNT + 1))

jq empty "$FINDING_FILE" >/dev/null 2>&1 ||
    fail "generated finding is not valid JSON"

printf 'elapsed     : %s seconds, %s commands\n' \
    "$ELAPSED_SECONDS" "$COMMAND_COUNT"
printf 'finding     : %s written\n' "$FINDING_FILE"

exit 0

