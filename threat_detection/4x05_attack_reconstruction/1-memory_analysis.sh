#!/bin/bash
#
# 4x05 - Attack Reconstruction
# Task 1 - Memory Artifact Analysis
#
# Analyzes the consolidated volatile-memory findings from WS-RECV-03
# and cross-references indicators against the HEALTHBANE IOC database.
#

set -euo pipefail

MEMORY="ir_evidence/memory_artifacts.txt"
IOC_DB="reference/healthbane_ioc_master.json"

for file in "$MEMORY" "$IOC_DB"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Required file not found: $file" >&2
        exit 1
    fi
done

for cmd in jq grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $cmd" >&2
        exit 1
    fi
done

ioc_known() {
    local value="$1"

    if jq -e --arg value "$value" '
        .iocs[]?
        | select(
            ((.value // "") | ascii_downcase)
            == ($value | ascii_downcase)
        )
    ' "$IOC_DB" >/dev/null 2>&1; then
        return 0
    fi

    return 1
}

ioc_details() {
    local value="$1"

    jq -r --arg value "$value" '
        .iocs[]?
        | select(
            ((.value // "") | ascii_downcase)
            == ($value | ascii_downcase)
        )
        | "IOC ID: \(.id) | Category: \(.category // "unknown") | Confidence: \(.confidence // "unknown")"
    ' "$IOC_DB" | head -n 1
}

classify_indicator() {
    local value="$1"
    local variant_pattern="${2:-}"

    if ioc_known "$value"; then
        printf '%s' "KNOWN"
        return
    fi

    if [[ -n "$variant_pattern" ]] &&
       grep -Eqi "$variant_pattern" "$IOC_DB"; then
        printf '%s' "MODIFIED"
        return
    fi

    printf '%s' "NEW"
}

SVCHOST_STATUS="$(classify_indicator "svchost_update.exe" "svchost.*update|healthsync")"
SYNC_STATUS="$(classify_indicator "sync_healthdata.ps1" "sync.*healthdata|healthdata.*ps1")"
DEBUG_STATUS="$(classify_indicator "debug_tool.exe" "debug.*tool|lsass")"
KNOWN_C2_STATUS="$(classify_indicator "185.220.101.45")"
SECONDARY_C2_STATUS="$(classify_indicator "203.0.113.47")"

KNOWN_COUNT=0
NEW_COUNT=0
MODIFIED_COUNT=0

count_status() {
    case "$1" in
        KNOWN)
            KNOWN_COUNT=$((KNOWN_COUNT + 1))
            ;;
        NEW)
            NEW_COUNT=$((NEW_COUNT + 1))
            ;;
        MODIFIED)
            MODIFIED_COUNT=$((MODIFIED_COUNT + 1))
            ;;
    esac
}

count_status "$SVCHOST_STATUS"
count_status "$SYNC_STATUS"
count_status "$DEBUG_STATUS"
count_status "$KNOWN_C2_STATUS"
count_status "$SECONDARY_C2_STATUS"

echo "================================================================"
echo "   MEMORY ARTIFACT ANALYSIS - WS-RECV-03"
echo "   Source: $MEMORY"
echo "================================================================"
echo

echo "CAPTURE CONTEXT:"
echo "  Host:       WS-RECV-03"
echo "  IP:         10.10.3.21"
echo "  Captured:   2026-05-15 14:18:42 CDT / 19:18:42 UTC"
echo "  Evidence:   Volatile memory / Volatility analysis"
echo

echo "PROCESS ANALYSIS:"
echo

cat <<EOF
  [LEGITIMATE]
    Process: lsass.exe
    PID: 648
    User: SYSTEM
    Source: Section 2 - pslist / pstree
    Status: LEGITIMATE system process
    Note: The process itself is legitimate; suspicious access TO it
          is analyzed separately below.

  [SUSPICIOUS]
    Process: svchost_update.exe
    PID: 3712
    User: MEDDEFENSE\\records03
    Path:
      C:\\Users\\records03\\AppData\\Roaming\\Microsoft\\HealthSync\\svchost_update.exe
    Source: Section 2 - pslist / pstree
    IOC Status: $SVCHOST_STATUS
    ATT&CK:
      T1547.001 Registry Run Keys / Startup Folder
      T1071.001 Web Protocols
    Finding:
      HEALTHBANE Stage 2 RAT was still resident in memory at capture.
      Its in-memory hash matches the sample analyzed during 4x03.

  [SUSPICIOUS]
    Process: powershell.exe
    PID: 8472
    Parent PID: 3712 (svchost_update.exe)
    User: MEDDEFENSE\\records03
    Source: Sections 2, 4 and 6
    ATT&CK:
      T1059.001 PowerShell
      T1005 Data from Local System
      T1560.001 Archive Collected Data
      T1074.001 Local Data Staging
    Finding:
      Hidden PowerShell executed an encoded command that invoked:
      sync_healthdata.ps1
    Script IOC Status: $SYNC_STATUS
    Execution time: 2026-05-15 02:00 CDT

    Decoded behavior:
      sync_healthdata.ps1 obtains configuration from
      sync.healthbane-c2.net and performs database collection /
      staging operations.

  [EXITED BUT RECOVERED FROM MEMORY]
    Process: debug_tool.exe
    Source: Section 7 - recovered stale handle structures
    IOC Status: $DEBUG_STATUS
    ATT&CK: T1003.001 OS Credential Dumping: LSASS Memory
    Finding:
      Process had a 0x1010 handle to lsass.exe and wrote
      C:\\Windows\\Temp\\out.dat.
EOF

echo
echo "NETWORK CONNECTIONS AT CAPTURE:"
echo

cat <<EOF
  [KNOWN C2]
    Source:      WS-RECV-03 / 10.10.3.21
    Process:     svchost_update.exe (PID 3712)
    Destination: 185.220.101.45:443
    IOC Status:  $KNOWN_C2_STATUS
    ATT&CK:      T1071.001 Web Protocols
EOF

if ioc_known "185.220.101.45"; then
    echo "    $(ioc_details "185.220.101.45")"
fi

echo

cat <<EOF
  [SECONDARY C2 CANDIDATE]
    Source:      WS-RECV-03 / 10.10.3.21
    Process:     svchost_update.exe (PID 3712)
    Destination: 203.0.113.47:8443
    IOC Status:  $SECONDARY_C2_STATUS
    ATT&CK:      T1571 Non-Standard Port
    Confidence:  PROBABLE from memory evidence alone
    Finding:
      The same RAT process responsible for the known HEALTHBANE
      C2 connection also maintained a live connection to this
      previously unidentified endpoint.

    Reconstruction note:
      Memory establishes the live process-to-connection relationship.
      Firewall evidence must independently corroborate the connection
      before the secondary C2 claim is raised to CONFIRMED.
EOF

echo
echo "CREDENTIAL ACCESS INDICATORS:"
echo

cat <<EOF
  [*] Artifact: debug_tool.exe -> lsass.exe
      Source location: Section 7 - recovered process handles
      Target PID: 648 (lsass.exe)
      Granted access: 0x1010
      Output artifact: C:\\Windows\\Temp\\out.dat
      ATT&CK: T1003.001 OS Credential Dumping: LSASS Memory
      IOC Status: $DEBUG_STATUS

      Assessment:
        0x1010 includes PROCESS_VM_READ capability and is consistent
        with the credential-access activity identified during 4x04.

        This memory evidence independently corroborates the previous
        4x04 LSASS-access finding.

  [*] Loaded-module review:
      svchost_update.exe:
        No unusual third-party DLLs identified.

      powershell.exe:
        System.Data.SqlClient.dll
        System.IO.Compression.dll
        Microsoft.PowerShell.Management.dll

      ldrmodules:
        No reflective DLL-loading discrepancies identified.

      Assessment:
        Credential access is supported by the recovered
        debug_tool.exe LSASS handle, not by evidence of reflective
        credential-dumping DLL injection.
EOF

echo
echo "PERSISTENCE MECHANISMS:"
echo

cat <<EOF
  [KNOWN PERSISTENCE]
    Registry value:
      HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\HealthSync

    Action:
      C:\\Users\\records03\\AppData\\Roaming\\Microsoft\\HealthSync\\svchost_update.exe

    Last Write:
      2026-04-22 06:14:47 UTC

    ATT&CK:
      T1547.001 Registry Run Keys / Startup Folder

    Status:
      KNOWN - matches the persistence mechanism identified in 4x03.

  [NEW PERSISTENCE]
    Scheduled Task:
      HealthSync Update Service

    Registry source:
      HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\
      {E7B26F4C-7C39-4F7E-B6A8-2D3C1E9F0A8D}

    Trigger:
      Daily at 02:00

    Action:
      Base64-encoded PowerShell command that downloads and
      executes a payload from HEALTHBANE infrastructure.

    Created:
      2026-05-07 06:47:33 UTC
      2026-05-07 01:47:33 CDT

    ATT&CK:
      T1053.005 Scheduled Task/Job: Scheduled Task

    IOC Status:
      NEW

    Confidence:
      PROBABLE from memory evidence alone.

    Correlation requirement:
      The on-disk Scheduled Task XML should be used as the
      independent second source to raise the persistence finding
      to CONFIRMED.
EOF

NEW_COUNT=$((NEW_COUNT + 1))

echo
echo "ADDITIONAL MEMORY FINDING:"
echo

cat <<'EOF'
  [NEW] Windows Defender exclusion

    Path excluded:
      C:\Windows\Temp

    Timestamp:
      2026-05-04 18:11 CDT

    ATT&CK:
      T1562.001 Impair Defenses

    Significance:
      The exclusion was added before the first credential-dumping
      activity and provides evidence of defense evasion.

    Classification:
      NEW relative to the previous hunt.
EOF

NEW_COUNT=$((NEW_COUNT + 1))

echo
echo "IOC CROSS-REFERENCE SUMMARY:"
echo "  KNOWN indicators:    $KNOWN_COUNT"
echo "  MODIFIED indicators: $MODIFIED_COUNT"
echo "  NEW indicators:      $NEW_COUNT"
echo

echo "ATT&CK TECHNIQUES IDENTIFIED:"
cat <<'EOF'
  T1547.001  Registry Run Keys / Startup Folder
  T1071.001  Web Protocols
  T1059.001  PowerShell
  T1003.001  LSASS Memory
  T1571      Non-Standard Port
  T1053.005  Scheduled Task/Job: Scheduled Task
  T1562.001  Impair Defenses
  T1005      Data from Local System
  T1074.001  Local Data Staging
  T1560.001  Archive Collected Data
EOF

echo
echo "RECONSTRUCTION ASSESSMENT:"
cat <<'EOF'
  CONFIRMED:
    - HEALTHBANE Stage 2 RAT remained resident on WS-RECV-03.
    - Previously observed LSASS access is corroborated by memory.
    - Existing Run-key persistence is corroborated by memory.

  PROBABLE:
    - 203.0.113.47:8443 is a secondary HEALTHBANE C2 endpoint.
      Memory provides strong process-level evidence, but firewall
      correlation is required for independent confirmation.

  NEW:
    - Scheduled Task persistence: HealthSync Update Service.
    - Defender exclusion affecting C:\Windows\Temp.
    - Direct execution evidence for sync_healthdata.ps1 on
      WS-RECV-03.

  IMPORTANT:
    Memory evidence is point-in-time evidence. Findings requiring
    historical duration, transmission volume or exact file creation
    history must be correlated with firewall and disk evidence.
EOF

echo
echo "================================================================"
echo "   Memory analysis complete."
echo "================================================================"