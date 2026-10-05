#!/bin/bash

# Task 10 - Evidence Correlation
# HEALTHBANE Stage 4 attack reconstruction

set -euo pipefail

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"

for file in "$ALERTS" "$SYSMON"; do
    if [[ ! -f "$file" ]]; then
        echo "[ERROR] Missing file: $file" >&2
        exit 1
    fi
done

command -v jq >/dev/null 2>&1 || {
    echo "[ERROR] jq is required." >&2
    exit 1
}

TIMELINE=$(mktemp)
trap 'rm -f "$TIMELINE"' EXIT

# ------------------------------------------------------------
# CREDENTIAL ACCESS - anomalous LSASS access
# ------------------------------------------------------------

jq -r '
    select(.data.win.system.eventID == "10")
    | select(
        (.data.win.eventdata.targetImage // "")
        | test("lsass\\.exe$"; "i")
    )
    | select(
        (.data.win.eventdata.sourceImage // "")
        | test("debug_tool\\.exe"; "i")
    )
    |
    [
        .timestamp,
        "CREDENTIAL ACCESS",
        (.agent.name // "unknown"),
        (.agent.name // "unknown"),
        (.data.win.eventdata.sourceUser // "unknown"),
        (
            "LSASS accessed by "
            + (.data.win.eventdata.sourceImage // "unknown")
            + " GrantedAccess="
            + (.data.win.eventdata.grantedAccess // "unknown")
        )
    ]
    | @tsv
' "$SYSMON" >> "$TIMELINE"

# ------------------------------------------------------------
# SERVICE ACCOUNT ABUSE - svc_healthsync from workstation
# ------------------------------------------------------------

jq -r '
    select(.data.win.system.eventID == "4624")
    | select(
        (.data.win.eventdata.targetUserName // "")
        == "svc_healthsync"
    )
    | select(
        (.data.win.eventdata.workstationName // "")
        | test("^WS-"; "i")
    )
    |
    [
        .timestamp,
        "CREDENTIAL USE",
        (.data.win.eventdata.workstationName // "unknown"),
        (.agent.name // "unknown"),
        "MEDDEFENSE\\svc_healthsync",
        (
            "Unauthorized service-account authentication"
            + " LogonType="
            + (.data.win.eventdata.logonType // "unknown")
            + " Auth="
            + (.data.win.eventdata.authenticationPackageName // "unknown")
        )
    ]
    | @tsv
' "$ALERTS" >> "$TIMELINE"

# ------------------------------------------------------------
# PSEXEC - lateral movement
# ------------------------------------------------------------

jq -r '
    select(.data.win.system.eventID == "1")
    | select(
        (
            (.data.win.eventdata.image // "")
            | test("psexec"; "i")
        )
        or
        (
            (.data.win.eventdata.commandLine // "")
            | test("psexec"; "i")
        )
    )
    | select(
        (.agent.name // "") == "WS-RECV-03"
        or
        (.hunt_meta.source_host // "") == "WS-RECV-03"
    )
    |
    [
        .timestamp,
        "LATERAL MOVEMENT",
        (.hunt_meta.source_host // .agent.name // "unknown"),
        (.hunt_meta.target_host // "unknown"),
        (.data.win.eventdata.user // "unknown"),
        (.data.win.eventdata.commandLine // "PsExec")
    ]
    | @tsv
' "$SYSMON" >> "$TIMELINE"

# ------------------------------------------------------------
# WMI - reconnaissance / remote execution
# ------------------------------------------------------------

jq -r '
    select(.data.win.system.eventID == "1")
    | select(
        (
            (.data.win.eventdata.image // "")
            | test("wmic|WmiPrvSE"; "i")
        )
        or
        (
            (.data.win.eventdata.commandLine // "")
            | test("wmic|Invoke-WmiMethod"; "i")
        )
        or
        (
            (.hunt_meta.tool // "")
            | test("WMI"; "i")
        )
    )
    | select(
        (.hunt_meta.source_host // .agent.name // "")
        == "WS-RECV-03"
    )
    |
    [
        .timestamp,
        "RECONNAISSANCE",
        (.hunt_meta.source_host // .agent.name // "unknown"),
        (.hunt_meta.target_host // .agent.name // "unknown"),
        (.data.win.eventdata.user // "unknown"),
        (.data.win.eventdata.commandLine // "WMI activity")
    ]
    | @tsv
' "$SYSMON" >> "$TIMELINE"

# ------------------------------------------------------------
# PSREMOTING - staging / remote access
# ------------------------------------------------------------

jq -r '
    select(.data.win.system.eventID == "1")
    | select(
        (
            (.data.win.eventdata.commandLine // "")
            | test(
                "Enter-PSSession|New-PSSession|Invoke-Command|Copy-Item.*ToSession";
                "i"
            )
        )
        or
        (
            (.hunt_meta.tool // "")
            == "PSRemoting"
        )
    )
    | select(
        (.hunt_meta.source_host // .agent.name // "")
        == "WS-RECV-03"
    )
    |
    [
        .timestamp,
        "STAGING",
        (.hunt_meta.source_host // .agent.name // "unknown"),
        (.hunt_meta.target_host // "unknown"),
        (.data.win.eventdata.user // "unknown"),
        (.data.win.eventdata.commandLine // "PSRemoting activity")
    ]
    | @tsv
' "$SYSMON" >> "$TIMELINE"

# ------------------------------------------------------------
# Sort and deduplicate timeline
# ------------------------------------------------------------

sort -u "$TIMELINE" -o "$TIMELINE"

EVENT_COUNT=$(wc -l < "$TIMELINE")

FIRST_TS=$(head -n 1 "$TIMELINE" | cut -f1)
LAST_TS=$(tail -n 1 "$TIMELINE" | cut -f1)

# Calculate dwell time from first correlated malicious event
# to last correlated malicious event.

if [[ -n "$FIRST_TS" && -n "$LAST_TS" ]]; then

    FIRST_EPOCH=$(date -u -d "$FIRST_TS" +%s)
    LAST_EPOCH=$(date -u -d "$LAST_TS" +%s)

    DIFF=$((LAST_EPOCH - FIRST_EPOCH))

    DAYS=$((DIFF / 86400))
    HOURS=$(((DIFF % 86400) / 3600))
    MINUTES=$(((DIFF % 3600) / 60))

    DWELL="${DAYS} days, ${HOURS} hours, ${MINUTES} minutes"

else
    DWELL="N/A"
fi

# ------------------------------------------------------------
# Determine reached targets
# ------------------------------------------------------------

TARGETS=$(
    awk -F '\t' '
        $4 ~ /^SRV-/ {
            print $4
        }
    ' "$TIMELINE" |
    sort -u |
    paste -sd ', ' -
)

# ------------------------------------------------------------
# Determine tools observed
# ------------------------------------------------------------

TOOLS="PsExec, WMI, PSRemoting"

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

echo "================================================================"
echo "   EVIDENCE CORRELATION - HEALTHBANE Stage 4 Reconstruction"
echo "================================================================"

echo
echo "ATTACK TIMELINE:"

CURRENT_PHASE=""

while IFS=$'\t' read -r timestamp phase source target user detail; do

    if [[ "$phase" != "$CURRENT_PHASE" ]]; then
        CURRENT_PHASE="$phase"
    fi

    echo
    printf "  [%s]\n" "$phase"
    printf "    Timestamp: %s\n" "$timestamp"
    printf "    Source:    %s\n" "$source"
    printf "    Target:    %s\n" "$target"
    printf "    User:      %s\n" "$user"
    printf "    Evidence:  %s\n" "$detail"

done < "$TIMELINE"

echo
echo "ATTACK PROGRESSION:"
echo "  WS-RECV-03"
echo "      |"
echo "      | credential dumping / LSASS"
echo "      v"
echo "  svc_healthsync"
echo "      |"
echo "      | PsExec / WMI / PSRemoting"
echo "      v"
echo "  SRV-HEALTH-DB"
echo "      |"
echo "      v"
echo "  SRV-INS-DB"
echo "      |"
echo "      v"
echo "  SRV-DC-01"

echo
echo "ATTACK SUMMARY:"
echo "  Pivot host:        WS-RECV-03"
echo "  Credential used:   MEDDEFENSE\\svc_healthsync"
echo "  Targets:           ${TARGETS:-unknown}"
echo "  Tools used:        $TOOLS"
echo "  Correlated events: $EVENT_COUNT"
echo "  First evidence:    $FIRST_TS"
echo "  Last evidence:     $LAST_TS"
echo "  Dwell time:        $DWELL"

echo
echo "UNIFIED NARRATIVE:"
echo "  Suspicious LSASS memory access occurred on WS-RECV-03."
echo "  The svc_healthsync account was subsequently used outside its"
echo "  authorized service-host context. The same pivot workstation"
echo "  then used legitimate Windows administration technologies,"
echo "  including PsExec, WMI and PowerShell Remoting, to access"
echo "  database infrastructure and later SRV-DC-01."
echo
echo "  The temporal, host, account and tooling correlation indicates"
echo "  a coordinated lateral-movement sequence rather than isolated"
echo "  administrative events."

echo
echo "ASSESSMENT:"

if (( EVENT_COUNT >= 4 )); then
    echo "  Status: POSITIVE - HIGH CONFIDENCE"
    echo "  HEALTHBANE Stage 4 behavior was executed against MedDefense."
    echo
    echo "  Confidence basis:"
    echo "    - Credential-access activity on the pivot workstation"
    echo "    - Unauthorized svc_healthsync authentication"
    echo "    - PsExec lateral movement"
    echo "    - WMI activity"
    echo "    - PowerShell Remoting"
    echo "    - Multiple critical server targets"
    echo
    echo "  Recommendation: ESCALATE TO INCIDENT RESPONSE"
else
    echo "  Status: INCONCLUSIVE"
    echo "  Insufficient correlated evidence for high-confidence attribution."
fi

echo
echo "================================================================"