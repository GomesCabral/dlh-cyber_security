#!/bin/bash

# Task 12 - Detection Gap Analysis
# HEALTHBANE Stage 4

set -euo pipefail

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
BASELINE="baseline/robert_kim_activity.json"
SCHEDULE="reference/admin_schedule.txt"
SERVICE_ACCOUNTS="reference/service_accounts.txt"

for file in \
    "$ALERTS" \
    "$SYSMON" \
    "$BASELINE" \
    "$SCHEDULE" \
    "$SERVICE_ACCOUNTS"
do
    if [[ ! -f "$file" ]]; then
        echo "[ERROR] Missing file: $file" >&2
        exit 1
    fi
done

command -v jq >/dev/null 2>&1 || {
    echo "[ERROR] jq is required." >&2
    exit 1
}

# ------------------------------------------------------------
# Verify whether the required telemetry exists
# ------------------------------------------------------------

PSEXEC_EVENTS=$(
    jq -s '
        [
            .[]
            | select(.data.win.system.eventID == "1")
            | select(
                ((.data.win.eventdata.image // "") | test("psexec"; "i"))
                or
                ((.data.win.eventdata.commandLine // "") | test("psexec"; "i"))
            )
        ] | length
    ' "$SYSMON"
)

LSASS_EVENTS=$(
    jq -s '
        [
            .[]
            | select(.data.win.system.eventID == "10")
            | select(
                (.data.win.eventdata.targetImage // "")
                | test("lsass\\.exe$"; "i")
            )
        ] | length
    ' "$SYSMON"
)

WMI_EVENTS=$(
    jq -s '
        [
            .[]
            | select(.data.win.system.eventID == "1")
            | select(
                ((.data.win.eventdata.image // "") | test("wmic|WmiPrvSE"; "i"))
                or
                ((.data.win.eventdata.commandLine // "")
                    | test("wmic|Invoke-WmiMethod"; "i"))
                or
                ((.hunt_meta.tool // "") | test("WMI"; "i"))
            )
        ] | length
    ' "$SYSMON"
)

PSREMOTE_EVENTS=$(
    jq -s '
        [
            .[]
            | select(.data.win.system.eventID == "1")
            | select(
                (.data.win.eventdata.commandLine // "")
                | test(
                    "Enter-PSSession|New-PSSession|Invoke-Command|Copy-Item.*ToSession";
                    "i"
                )
            )
        ] | length
    ' "$SYSMON"
)

SVC_EVENTS=$(
    jq -s '
        [
            .[]
            | select(.data.win.system.eventID == "4624")
            | select(
                (.data.win.eventdata.targetUserName // "")
                | test("^svc_"; "i")
            )
        ] | length
    ' "$ALERTS"
)

NTLM_SVC_EVENTS=$(
    jq -s '
        [
            .[]
            | select(.data.win.system.eventID == "4624")
            | select(
                (.data.win.eventdata.targetUserName // "")
                | test("^svc_"; "i")
            )
            | select(
                (.data.win.eventdata.authenticationPackageName // "")
                | test("^NTLM$"; "i")
            )
        ] | length
    ' "$ALERTS"
)

# ------------------------------------------------------------
# Helper
# ------------------------------------------------------------

telemetry_status()
{
    local count="$1"

    if (( count > 0 )); then
        echo "AVAILABLE (${count} matching events)"
    else
        echo "NOT OBSERVED"
    fi
}

echo "================================================================"
echo "   DETECTION GAP ANALYSIS - Stage 4 Techniques"
echo "================================================================"

echo
echo "GAP 1: T1021.002 PsExec Lateral Movement"
echo "  Hunt Finding:"
echo "    PsExec was executed from a non-admin workstation using"
echo "    svc_healthsync against server infrastructure."
echo
echo "  Why Missed: Missing behavioral rule"
echo "  Data Source: Sysmon Event 1 - Process Creation"
echo "  Telemetry: $(telemetry_status "$PSEXEC_EVENTS")"
echo
echo "  Required Detection Logic:"
echo "    - Image or CommandLine contains PsExec"
echo "    - Compare source host against WS-ADMIN-01"
echo "    - Compare user against MEDDEFENSE\\robert.kim"
echo "    - Check approved administrative schedule"
echo "    - Increase severity for service-account usage"
echo "    - Increase severity for database/DC targets"
echo
echo "  Allowlist:"
echo "    Robert Kim from WS-ADMIN-01 during documented maintenance"
echo "    windows and against authorized server targets."
echo
echo "  Required Rule:"
echo "    Alert when PsExec originates from a non-admin workstation,"
echo "    unauthorized account or outside the approved baseline."
echo
echo "  Priority: P1"

echo
echo "----------------------------------------------------------------"

echo
echo "GAP 2: T1003.001 LSASS Credential Access"
echo "  Hunt Finding:"
echo "    C:\\Windows\\Temp\\debug_tool.exe accessed lsass.exe with"
echo "    memory-read access."
echo
echo "  Why Missed: Missing rule"
echo "  Data Source: Sysmon Event 10 - Process Access"
echo "  Telemetry: $(telemetry_status "$LSASS_EVENTS")"
echo
echo "  Required Detection Logic:"
echo "    - TargetImage ends with \\lsass.exe"
echo "    - Inspect SourceImage"
echo "    - Inspect GrantedAccess"
echo "    - Flag memory-read masks such as 0x0010 / 0x1010"
echo "    - Exclude known legitimate/system processes"
echo "    - Increase severity for executables from Temp/Public/ProgramData"
echo
echo "  Allowlist:"
echo "    Known Windows/security processes with documented LSASS access."
echo
echo "  Required Rule:"
echo "    Alert when a non-allowlisted process accesses lsass.exe,"
echo "    especially with memory-read rights."
echo
echo "  Priority: P1"

echo
echo "----------------------------------------------------------------"

echo
echo "GAP 3: T1047 WMI Remote Execution"
echo "  Hunt Finding:"
echo "    WMI activity was associated with unauthorized remote"
echo "    administration and lateral movement."
echo
echo "  Why Missed: Missing behavioral/context rule"
echo "  Data Source: Sysmon Event 1 - Process Creation"
echo "  Telemetry: $(telemetry_status "$WMI_EVENTS")"
echo
echo "  Required Detection Logic:"
echo "    - Detect wmic.exe / Invoke-WmiMethod"
echo "    - Detect WmiPrvSE.exe spawning cmd.exe or powershell.exe"
echo "    - Compare source against approved admin workstation"
echo "    - Compare account against Robert Kim baseline"
echo "    - Check target role, especially database servers and DCs"
echo "    - Check approved WMI maintenance windows"
echo
echo "  Allowlist:"
echo "    Robert Kim's documented WMI inventory activity from"
echo "    WS-ADMIN-01 during authorized periods."
echo
echo "  Required Rule:"
echo "    Alert on remote WMI execution from unauthorized hosts/users"
echo "    or WmiPrvSE spawning command shells in anomalous context."
echo
echo "  Priority: P1"

echo
echo "----------------------------------------------------------------"

echo
echo "GAP 4: T1021.006 PowerShell Remoting"
echo "  Hunt Finding:"
echo "    PowerShell Remoting was used from the pivot workstation"
echo "    against server infrastructure using svc_healthsync."
echo
echo "  Why Missed: Missing behavioral rule / insufficient context"
echo "  Data Source:"
echo "    - Sysmon Event 1"
echo "    - PowerShell operational/script logging where available"
echo "  Telemetry: $(telemetry_status "$PSREMOTE_EVENTS")"
echo
echo "  Required Detection Logic:"
echo "    - Enter-PSSession"
echo "    - New-PSSession"
echo "    - Invoke-Command"
echo "    - Copy-Item with -ToSession"
echo "    - Source host must match approved admin baseline"
echo "    - User must match approved administrative identity"
echo "    - Increase severity for service accounts"
echo
echo "  Allowlist:"
echo "    Approved Robert Kim PSRemoting sessions from WS-ADMIN-01"
echo "    during documented maintenance windows."
echo
echo "  Required Rule:"
echo "    Alert on PSRemoting initiated from non-admin workstations,"
echo "    by service accounts, or outside approved windows."
echo
echo "  Priority: P1"

echo
echo "----------------------------------------------------------------"

echo
echo "GAP 5: T1078.002 Service Account Misuse"
echo "  Hunt Finding:"
echo "    svc_healthsync authenticated from a workstation instead of"
echo "    its authorized service host and was associated with lateral"
echo "    movement."
echo
echo "  Why Missed: Missing identity-context rule"
echo "  Data Source: Windows Event 4624 - Successful Logon"
echo "  Telemetry: $(telemetry_status "$SVC_EVENTS")"
echo
echo "  Required Detection Logic:"
echo "    - TargetUserName matches svc_*"
echo "    - Compare WorkstationName against service account matrix"
echo "    - Detect workstation sources (WS-*)"
echo "    - Detect interactive Logon Types 2, 10 and 11"
echo "    - Detect unexpected Type 3 source hosts"
echo "    - Detect NTLM where Kerberos is expected"
echo
echo "  Allowlist:"
echo "    Each service account may authenticate only from hosts and"
echo "    contexts documented in reference/service_accounts.txt."
echo
echo "  Required Rule:"
echo "    Alert whenever a service account violates its authorization"
echo "    matrix."
echo
echo "  Priority: P1"

echo
echo "----------------------------------------------------------------"

echo
echo "GAP 6: T1550.002 Pass-the-Hash / NTLM-style Activity"
echo "  Hunt Finding:"
echo "    svc_healthsync generated NTLM Type 3 authentication from"
echo "    workstation WS-RECV-03 before lateral movement."
echo
echo "  Why Missed: Missing correlation rule"
echo "  Data Source: Windows Event 4624"
echo "  Telemetry: $(telemetry_status "$NTLM_SVC_EVENTS")"
echo
echo "  Required Detection Logic:"
echo "    - LogonType = 3"
echo "    - AuthenticationPackageName = NTLM"
echo "    - TargetUserName is a service account"
echo "    - Source WorkstationName begins WS-*"
echo "    - Source host is not authorized by service-account matrix"
echo "    - Correlate with PsExec/WMI/PSRemoting immediately afterward"
echo
echo "  Allowlist:"
echo "    Documented service-to-service authentication only."
echo
echo "  Required Rule:"
echo "    Alert on NTLM network authentication by service accounts"
echo "    from workstation endpoints and correlate with remote"
echo "    administration activity."
echo
echo "  Priority: P1"
echo
echo "  ATT&CK Note:"
echo "    This pattern supports pass-the-hash-style investigation,"
echo "    but NTLM alone does not prove Pass-the-Hash."

echo
echo "================================================================"
echo "   SUMMARY"
echo "================================================================"
echo
echo "  P1 Detection Gaps:"
echo "    T1021.002  PsExec Lateral Movement"
echo "    T1003.001  LSASS Credential Access"
echo "    T1047      WMI"
echo "    T1021.006  PowerShell Remoting"
echo "    T1078.002  Service Account Misuse"
echo "    T1550.002  Pass-the-Hash-style NTLM activity"
echo
echo "  Overall Assessment:"
echo "    The hunt demonstrated that the required telemetry was"
echo "    largely present in the SIEM. The primary weakness was"
echo "    missing behavioral and correlation detection logic."
echo
echo "    Existing telemetry showed the individual attack actions,"
echo "    but those actions were not automatically connected to"
echo "    administrative baselines, service-account authorization"
echo "    rules and subsequent lateral movement."
echo
echo "  Conclusion:"
echo "    Proactive threat hunting exposed detection gaps that should"
echo "    now be converted into automated detection rules."
echo
echo "================================================================"