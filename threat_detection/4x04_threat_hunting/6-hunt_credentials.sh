#!/bin/bash

# Task 6 - Hunt H2: Credential Access
# MITRE ATT&CK T1003.001 - LSASS Memory

set -euo pipefail

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
SERVICE_ACCOUNTS="reference/service_accounts.txt"

for file in "$ALERTS" "$SYSMON" "$SERVICE_ACCOUNTS"; do
    if [[ ! -f "$file" ]]; then
        echo "[ERROR] Missing file: $file" >&2
        exit 1
    fi
done

command -v jq >/dev/null 2>&1 || {
    echo "[ERROR] jq is required." >&2
    exit 1
}

LSASS_EVENTS=$(mktemp)
ANOMALOUS_LSASS=$(mktemp)
SVC_EVENTS=$(mktemp)
LATERAL_EVENTS=$(mktemp)

trap 'rm -f "$LSASS_EVENTS" "$ANOMALOUS_LSASS" "$SVC_EVENTS" "$LATERAL_EVENTS"' EXIT

# ------------------------------------------------------------
# 1. Find Sysmon Event ID 10 access to LSASS
# ------------------------------------------------------------

jq -c '
    select(.data.win.system.eventID == "10")
    | select(
        (.data.win.eventdata.targetImage // "")
        | test("lsass\\.exe$"; "i")
    )
' "$SYSMON" > "$LSASS_EVENTS"

TOTAL_LSASS=$(wc -l < "$LSASS_EVENTS")

# ------------------------------------------------------------
# 2. Separate expected/system processes from unusual processes
# ------------------------------------------------------------

jq -c '
    select(
        (
            .data.win.eventdata.sourceImage // ""
            | test(
                "\\\\(csrss|services|svchost|MsMpEng|WmiPrvSE|wininit)\\.exe$";
                "i"
            )
        ) | not
    )
    | select(
        (.data.win.eventdata.grantedAccess // "")
        | test("0x0010|0x1010"; "i")
    )
' "$LSASS_EVENTS" > "$ANOMALOUS_LSASS"

ANOMALOUS_COUNT=$(wc -l < "$ANOMALOUS_LSASS")
LEGIT_COUNT=$((TOTAL_LSASS - ANOMALOUS_COUNT))

# ------------------------------------------------------------
# 3. Find svc_healthsync authentication events
# ------------------------------------------------------------

jq -c '
    select(.data.win.system.eventID == "4624")
    | select(
        (.data.win.eventdata.targetUserName // "")
        == "svc_healthsync"
    )
    | select(
        (.data.win.eventdata.workstationName // "")
        | test("^WS-"; "i")
    )
' "$ALERTS" > "$SVC_EVENTS"

SVC_COUNT=$(wc -l < "$SVC_EVENTS")

# ------------------------------------------------------------
# 4. Find later lateral movement using svc_healthsync
# ------------------------------------------------------------

jq -c '
    select(.data.win.system.eventID == "1")
    | select(
        (
            .data.win.eventdata.user // ""
            | test("svc_healthsync"; "i")
        )
        or
        (
            .data.win.eventdata.commandLine // ""
            | test("svc_healthsync"; "i")
        )
    )
    | select(
        (
            .data.win.eventdata.image // ""
            | test("psexec|wmic|powershell"; "i")
        )
        or
        (
            .data.win.eventdata.commandLine // ""
            | test(
                "psexec|wmic|Invoke-WmiMethod|Enter-PSSession|New-PSSession|Invoke-Command";
                "i"
            )
        )
    )
' "$SYSMON" > "$LATERAL_EVENTS"

LATERAL_COUNT=$(wc -l < "$LATERAL_EVENTS")

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

echo "================================================================"
echo "   HUNT EXECUTION - H2: Credential Access (LSASS)"
echo "   Technique: T1003.001 LSASS Memory"
echo "================================================================"
echo

echo "LSASS ACCESS EVENTS:"
printf "  Total LSASS access events: %s\n" "$TOTAL_LSASS"
printf "  System/legitimate:         %s\n" "$LEGIT_COUNT"
printf "  ANOMALOUS:                 %s\n" "$ANOMALOUS_COUNT"

INDEX=0

while IFS= read -r event; do

    INDEX=$((INDEX + 1))

    TIMESTAMP=$(jq -r '.timestamp // "unknown"' <<< "$event")
    HOST=$(jq -r '.agent.name // "unknown"' <<< "$event")
    SOURCE=$(jq -r '.data.win.eventdata.sourceImage // "unknown"' <<< "$event")
    SOURCE_USER=$(jq -r '.data.win.eventdata.sourceUser // "unknown"' <<< "$event")
    TARGET=$(jq -r '.data.win.eventdata.targetImage // "unknown"' <<< "$event")
    ACCESS=$(jq -r '.data.win.eventdata.grantedAccess // "unknown"' <<< "$event")
    PID=$(jq -r '.data.win.eventdata.sourceProcessId // "unknown"' <<< "$event")

    echo
    printf "  [A%s] %s\n" "$INDEX" "$TIMESTAMP"
    printf "    Host:           %s\n" "$HOST"
    printf "    User:           %s\n" "$SOURCE_USER"
    printf "    Source Process: %s\n" "$SOURCE"
    printf "    Source PID:     %s\n" "$PID"
    printf "    Target:         %s\n" "$TARGET"
    printf "    Access Mask:    %s\n" "$ACCESS"
    echo "    [!] Unusual process accessed LSASS memory"
    echo "    [!] Memory-read access mask detected"
    echo "    -> Consistent with credential dumping"

done < "$ANOMALOUS_LSASS"

echo
echo "CREDENTIAL USAGE CORRELATION:"
echo "  svc_healthsync authentication from workstations:"

while IFS= read -r event; do

    TIMESTAMP=$(jq -r '.timestamp // "unknown"' <<< "$event")
    SOURCE=$(jq -r '.data.win.eventdata.workstationName // "unknown"' <<< "$event")
    TARGET=$(jq -r '.agent.name // "unknown"' <<< "$event")
    LOGON_TYPE=$(jq -r '.data.win.eventdata.logonType // "unknown"' <<< "$event")
    AUTH=$(jq -r '.data.win.eventdata.authenticationPackageName // "unknown"' <<< "$event")

    printf "    %s %s -> %s | Type %s | %s\n" \
        "$TIMESTAMP" \
        "$SOURCE" \
        "$TARGET" \
        "$LOGON_TYPE" \
        "$AUTH"

done < "$SVC_EVENTS"

echo
echo "LATERAL MOVEMENT CORRELATION:"
echo "  svc_healthsync administrative activity:"

while IFS= read -r event; do

    TIMESTAMP=$(jq -r '.timestamp // "unknown"' <<< "$event")
    SOURCE=$(jq -r '.agent.name // "unknown"' <<< "$event")
    TOOL=$(jq -r '.hunt_meta.tool // "unknown"' <<< "$event")
    TARGET=$(jq -r '.hunt_meta.target_host // "unknown"' <<< "$event")
    COMMAND=$(jq -r '.data.win.eventdata.commandLine // "unknown"' <<< "$event")

    printf "\n    %s\n" "$TIMESTAMP"
    printf "      Source:  %s\n" "$SOURCE"
    printf "      Tool:    %s\n" "$TOOL"
    printf "      Target:  %s\n" "$TARGET"
    printf "      Command: %s\n" "$COMMAND"

done < "$LATERAL_EVENTS"

echo
echo "CREDENTIAL THEFT TIMELINE:"

{
    jq -r '
        [
            .timestamp,
            "LSASS ACCESS",
            .agent.name,
            (.data.win.eventdata.sourceImage // "unknown")
        ] | @tsv
    ' "$ANOMALOUS_LSASS"

    jq -r '
        [
            .timestamp,
            "SVC AUTH",
            (.data.win.eventdata.workstationName // "unknown"),
            (.agent.name // "unknown")
        ] | @tsv
    ' "$SVC_EVENTS"

    jq -r '
        [
            .timestamp,
            (.hunt_meta.tool // "LATERAL MOVEMENT"),
            (.agent.name // "unknown"),
            (.hunt_meta.target_host // "unknown")
        ] | @tsv
    ' "$LATERAL_EVENTS"

} | sort | awk -F '\t' '
{
    printf "  %-29s %-18s %-15s -> %s\n", $1, $2, $3, $4
}'

echo
echo "FINDING:"

if (( ANOMALOUS_COUNT > 0 && SVC_COUNT > 0 && LATERAL_COUNT > 0 )); then

    echo "  Status: POSITIVE - HIGH CONFIDENCE"
    echo "  Evidence:"
    echo "    - Suspicious process accessed LSASS memory"
    echo "    - svc_healthsync later authenticated from a workstation"
    echo "    - svc_healthsync was subsequently used for lateral movement"
    echo
    echo "  Assessment:"
    echo "    Credential dumping is strongly correlated with later"
    echo "    unauthorized service-account use."
    echo
    echo "  Recommendation: ESCALATE"

elif (( ANOMALOUS_COUNT > 0 )); then

    echo "  Status: POSITIVE - MEDIUM CONFIDENCE"
    echo "  Evidence: Suspicious LSASS memory access detected"
    echo "  Recommendation: Investigate credential use and lateral movement"

else

    echo "  Status: NEGATIVE"
    echo "  Evidence: No anomalous LSASS memory access identified"

fi

echo
echo "================================================================"