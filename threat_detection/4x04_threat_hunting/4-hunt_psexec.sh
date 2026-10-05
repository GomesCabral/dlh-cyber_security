#!/bin/bash

# Task 4 - Hunt H1: PsExec Lateral Movement
# MITRE ATT&CK T1021.002

set -euo pipefail

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
BASELINE="baseline/robert_kim_activity.json"
SCHEDULE="reference/admin_schedule.txt"

for file in "$ALERTS" "$SYSMON" "$BASELINE" "$SCHEDULE"; do
    if [[ ! -f "$file" ]]; then
        echo "[ERROR] Missing file: $file" >&2
        exit 1
    fi
done

if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required." >&2
    exit 1
fi

TMP_EVENTS=$(mktemp)
trap 'rm -f "$TMP_EVENTS"' EXIT

# Use the alerts export as the primary event source.
# Extract Sysmon Process Create events where Image or CommandLine
# contains PsExec.
jq -c '
    select(.data.win.system.eventID == "1")
    | select(
        ((.data.win.eventdata.image // "") | test("psexec"; "i"))
        or
        ((.data.win.eventdata.commandLine // "") | test("psexec"; "i"))
    )
' "$ALERTS" > "$TMP_EVENTS"

TOTAL=$(wc -l < "$TMP_EVENTS")

BASELINE_COUNT=0
ANOMALOUS_COUNT=0
INDEX=0

echo "================================================================"
echo "   HUNT EXECUTION - H1: Lateral Movement via PsExec"
echo "   Technique: T1021.002 SMB/Windows Admin Shares"
echo "================================================================"
echo

# First pass: classify events.
while IFS= read -r event; do

    SOURCE=$(jq -r '.agent.name // "unknown"' <<< "$event")
    USER=$(jq -r '.data.win.eventdata.user // "unknown"' <<< "$event")
    TIMESTAMP=$(jq -r '.timestamp // "unknown"' <<< "$event")

    # Dataset timestamps are UTC.
    # May 2026 Central Time = UTC-5.
    UTC_HOUR=$(printf '%s' "$TIMESTAMP" | cut -c12-13)
    LOCAL_HOUR=$(( (10#$UTC_HOUR + 19) % 24 ))

    DATE=$(printf '%s' "$TIMESTAMP" | cut -c1-10)
    DAY=$(date -u -d "$DATE" +%u)

    ANOMALY=0

    if [[ "$SOURCE" != "WS-ADMIN-01" ]]; then
        ANOMALY=1
    fi

    if [[ "$USER" != 'MEDDEFENSE\robert.kim' ]]; then
        ANOMALY=1
    fi

    if (( LOCAL_HOUR < 8 || LOCAL_HOUR >= 18 )); then
        ANOMALY=1
    fi

    # Saturday=6, Sunday=7
    if (( DAY >= 6 )); then
        ANOMALY=1
    fi

    if (( ANOMALY == 0 )); then
        BASELINE_COUNT=$((BASELINE_COUNT + 1))
    else
        ANOMALOUS_COUNT=$((ANOMALOUS_COUNT + 1))
    fi

done < "$TMP_EVENTS"

echo "QUERY RESULTS:"
printf "  Total PsExec events in 14 days: %s\n" "$TOTAL"
printf "  Baseline:                       %s\n" "$BASELINE_COUNT"
printf "  ANOMALOUS:                      %s\n" "$ANOMALOUS_COUNT"

echo
echo "ANOMALOUS EVENTS:"

# Second pass: print evidence for anomalous events.
while IFS= read -r event; do

    TIMESTAMP=$(jq -r '.timestamp // "unknown"' <<< "$event")
    SOURCE=$(jq -r '.agent.name // "unknown"' <<< "$event")
    USER=$(jq -r '.data.win.eventdata.user // "unknown"' <<< "$event")
    COMMAND=$(jq -r '.data.win.eventdata.commandLine // "unknown"' <<< "$event")
    PID=$(jq -r '.data.win.eventdata.processId // "N/A"' <<< "$event")
    TARGET=$(jq -r '.hunt_meta.target_host // "unknown"' <<< "$event")

    UTC_HOUR=$(printf '%s' "$TIMESTAMP" | cut -c12-13)
    LOCAL_HOUR=$(( (10#$UTC_HOUR + 19) % 24 ))

    DATE=$(printf '%s' "$TIMESTAMP" | cut -c1-10)
    DAY=$(date -u -d "$DATE" +%u)

    ANOMALY=0

    if [[ "$SOURCE" != "WS-ADMIN-01" ]]; then
        ANOMALY=1
    fi

    if [[ "$USER" != 'MEDDEFENSE\robert.kim' ]]; then
        ANOMALY=1
    fi

    if (( LOCAL_HOUR < 8 || LOCAL_HOUR >= 18 )); then
        ANOMALY=1
    fi

    if (( DAY >= 6 )); then
        ANOMALY=1
    fi

    if (( ANOMALY == 1 )); then

        INDEX=$((INDEX + 1))

        echo
        printf "  [A%s] %s\n" "$INDEX" "$TIMESTAMP"
        printf "    Source:  %s\n" "$SOURCE"
        printf "    User:    %s\n" "$USER"
        printf "    Command: %s\n" "$COMMAND"
        printf "    Target:  %s\n" "$TARGET"
        printf "    PID:     %s\n" "$PID"

        echo "    ANOMALY FLAGS:"

        if [[ "$SOURCE" != "WS-ADMIN-01" ]]; then
            echo "      [!] Source host is NOT WS-ADMIN-01"
        fi

        if [[ "$USER" != 'MEDDEFENSE\robert.kim' ]]; then
            echo "      [!] User is NOT Robert Kim"
        fi

        if [[ "$USER" =~ \\svc_ ]]; then
            echo "      [!] User is a service account"
        fi

        if (( LOCAL_HOUR < 8 || LOCAL_HOUR >= 18 )); then
            echo "      [!] Time is outside business hours"
        fi

        if (( DAY >= 6 )); then
            echo "      [!] Activity occurred during weekend"
        fi

        if [[ "$TARGET" == *"-DB"* ]]; then
            echo "      [!] Target is a database server"
        fi
    fi

done < "$TMP_EVENTS"

echo
echo "FINDING:"

if (( ANOMALOUS_COUNT > 0 )); then
    echo "  Status: POSITIVE - HIGH CONFIDENCE"
    echo "  Evidence: PsExec activity deviates from Robert Kim's documented baseline"
    echo "  Assessment: Potential unauthorized lateral movement"
    echo "  Recommendation: ESCALATE and correlate with authentication,"
    echo "                  WMI, PSRemoting and credential-access activity"
else
    echo "  Status: NEGATIVE"
    echo "  Evidence: All observed PsExec activity matches the documented baseline"
    echo "  Recommendation: No escalation for H1"
fi

echo
echo "================================================================"