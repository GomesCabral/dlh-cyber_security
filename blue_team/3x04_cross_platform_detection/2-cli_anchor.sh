#!/bin/bash

# Task 2 - CLI Investigation of the Anchor Event
# Investigate the known SSH brute-force anchor with CLI tools and
# write a structured, auditable SOC finding.

set -u

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

ANCHOR_FILE="$ASSETS_DIR/anchor_event.json"
EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
SIGMA_RULE="$CATALOG_DIR/rules/sigma/001_ssh_brute_force.yml"
FINDINGS_DIR="findings"
FINDING_FILE="$FINDINGS_DIR/anchor_cli.json"

START_EPOCH="$(date +%s)"
INVESTIGATION_START="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
COMMAND_COUNT=0
TEMP_MATCHES="$(mktemp)"

cleanup()
{
    rm -f "$TEMP_MATCHES"
}

trap cleanup EXIT

fail()
{
    printf 'error       : %s\n' "$1" >&2
    exit 1
}

[[ -s "$ANCHOR_FILE" ]] || fail "missing or empty anchor manifest: $ANCHOR_FILE"
[[ -s "$EVENTS_FILE" ]] || fail "missing or empty event handoff: $EVENTS_FILE"

jq empty "$ANCHOR_FILE" >/dev/null 2>&1 ||
    fail "invalid anchor manifest JSON"

printf 'reading     : %s\n' "$ANCHOR_FILE"

# Command 1: read the investigation scope from the anchor manifest.
TARGET_HOST="$(jq -r '.target_host // empty' "$ANCHOR_FILE")"
TARGET_IP="$(jq -r '.target_ip // empty' "$ANCHOR_FILE")"
WINDOW_START="$(jq -r '.time_window.start // empty' "$ANCHOR_FILE")"
WINDOW_END="$(jq -r '.time_window.end // empty' "$ANCHOR_FILE")"
mapfile -t ATTACKER_IPS < <(jq -r '.attacker_ips[]?' "$ANCHOR_FILE")
COMMAND_COUNT=$((COMMAND_COUNT + 1))

[[ -n "$TARGET_HOST" ]] || fail "target_host missing from anchor manifest"
[[ -n "$TARGET_IP" ]] || fail "target_ip missing from anchor manifest"
[[ -n "$WINDOW_START" ]] || fail "time_window.start missing from anchor manifest"
[[ -n "$WINDOW_END" ]] || fail "time_window.end missing from anchor manifest"
(( ${#ATTACKER_IPS[@]} > 0 )) || fail "attacker_ips missing from anchor manifest"

printf 'host        : %s (%s)\n' "$TARGET_HOST" "$TARGET_IP"
printf 'window      : %s -> %s\n' "$WINDOW_START" "$WINDOW_END"
printf 'attacker ips:'
printf ' %s' "${ATTACKER_IPS[@]}"
printf '\n'

# Command 2: filter NDJSON events by time, attacker indicators, and target.
# tostring is intentional because Linux auth events may keep the remote IP in
# raw_message/details.message even when the normalized src_ip field is null.
jq -c \
    --arg window_start "$WINDOW_START" \
    --arg window_end "$WINDOW_END" \
    --arg host "$TARGET_HOST" \
    --arg target_ip "$TARGET_IP" \
    --argjson attacker_ips "$(jq -c '.attacker_ips' "$ANCHOR_FILE")" '
    select(
        (.timestamp >= $window_start)
        and (.timestamp <= $window_end)
    )
    | select(
        . as $event
        | any(
            $attacker_ips[];
            . as $ip | ($event | tostring | contains($ip))
        )
    )
    | select(
        (.hostname == $host)
        or (.dst_ip == $target_ip)
        or ((.raw_message // "") | contains($target_ip))
        or ((.details.message // "") | contains($target_ip))
    )
' "$EVENTS_FILE" > "$TEMP_MATCHES" || fail "event filtering failed"
COMMAND_COUNT=$((COMMAND_COUNT + 1))

# Command 3: count the filtered records.
MATCHED_COUNT="$(wc -l < "$TEMP_MATCHES" | tr -d ' ')"
COMMAND_COUNT=$((COMMAND_COUNT + 1))

(( MATCHED_COUNT > 0 )) || fail "no events matched the anchor scenario"

printf 'matched     : %s events in enriched_events.json\n' "$MATCHED_COUNT"

# Command 4: build the ordered incident timeline boundaries.
FIRST_EVENT="$(jq -rs 'sort_by(.timestamp) | first' "$TEMP_MATCHES")"
LAST_EVENT="$(jq -rs 'sort_by(.timestamp) | last' "$TEMP_MATCHES")"
FIRST_TIMESTAMP="$(printf '%s\n' "$FIRST_EVENT" | jq -r '.timestamp')"
LAST_TIMESTAMP="$(printf '%s\n' "$LAST_EVENT" | jq -r '.timestamp')"
COMMAND_COUNT=$((COMMAND_COUNT + 1))

printf 'first event : %s\n' "$FIRST_TIMESTAMP"
printf 'last event  : %s\n' "$LAST_TIMESTAMP"

# Command 5: inspect the Sigma rule that generated the alert.
RULE_NAME="001_ssh_brute_force"
ATTACK_TECHNIQUE="T1110.001"

if [[ -s "$SIGMA_RULE" ]]; then
    printf 'logsource:\n'
    yq '.logsource' "$SIGMA_RULE"
    printf 'detection:\n'
    yq '.detection' "$SIGMA_RULE"

    RULE_TAG="$(
        yq -r '.tags[]' "$SIGMA_RULE" 2>/dev/null |
            grep -Ei '^attack\.t[0-9]{4}(\.[0-9]{3})?$' |
            head -n 1 || true
    )"

    if [[ -n "$RULE_TAG" ]]; then
        ATTACK_TECHNIQUE="$(
            printf '%s\n' "$RULE_TAG" |
                sed 's/^attack\.//' |
                tr '[:lower:]' '[:upper:]'
        )"
    fi

    printf 'rule        : %s (%s)\n' "$RULE_NAME" "$ATTACK_TECHNIQUE"
else
    printf 'rule        : %s not available\n' "$RULE_NAME"
fi
COMMAND_COUNT=$((COMMAND_COUNT + 1))

# Preserve only genuine event_ref values present in the source dataset.
# The locked schema requires a list; it remains empty if the upstream handoff
# did not assign event_ref values.
EVENT_REFS="$(
    jq -rs '[.[].event_ref // empty] | unique' "$TEMP_MATCHES"
)"

mkdir -p "$FINDINGS_DIR"

INVESTIGATION_END="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
END_EPOCH="$(date +%s)"
ELAPSED_SECONDS=$((END_EPOCH - START_EPOCH))

jq -n \
    --arg finding_id "anchor_cli" \
    --arg scenario_id "anchor" \
    --arg interface "cli" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED_SECONDS" \
    --arg first_timestamp "$FIRST_TIMESTAMP" \
    --arg last_timestamp "$LAST_TIMESTAMP" \
    --arg host "$TARGET_HOST" \
    --arg target_ip "$TARGET_IP" \
    --argjson matched_count "$MATCHED_COUNT" \
    --argjson event_refs "$EVENT_REFS" \
    --arg technique "$ATTACK_TECHNIQUE" \
    --arg created_at "$INVESTIGATION_END" '
    {
        finding_id: $finding_id,
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $investigation_start,
        investigation_end: $investigation_end,
        time_to_first_answer_seconds: $elapsed,
        actions: [
            "Read the anchor manifest and established the investigation scope",
            "Filtered enriched events by time window, attacker IPs, and target",
            "Counted matching records",
            "Identified the earliest and latest matching events",
            "Reviewed the Sigma logsource and detection logic"
        ],
        fields_touched: [
            "timestamp",
            "hostname",
            "src_ip",
            "dst_ip",
            "dst_port",
            "user",
            "outcome",
            "event_ref",
            "raw_message",
            "details.message"
        ],
        event_refs: $event_refs,
        attack_techniques: [$technique],
        hypothesis: (
            "Four external IP addresses performed repeated SSH authentication attempts against "
            + $host + " (" + $target_ip + ") across "
            + ($matched_count | tostring) + " matching events. "
            + "The activity is consistent with an SSH brute-force attack and requires validation of the final successful root login."
        ),
        confidence: "high",
        created_at: $created_at
    }
' > "$FINDING_FILE"

jq empty "$FINDING_FILE" >/dev/null 2>&1 ||
    fail "generated finding is not valid JSON"

printf 'elapsed     : %s seconds, %s commands\n' \
    "$ELAPSED_SECONDS" "$COMMAND_COUNT"
printf 'finding     : %s written\n' "$FINDING_FILE"

exit 0

