#!/bin/bash
#
# 4x05 - Attack Reconstruction
# Task 7 - Stage 4 Reconstruction
#
# Reconstructs HEALTHBANE Stage 4:
# credential access, lateral movement, persistence,
# data collection/staging, anti-forensics and containment.
#

set -euo pipefail

HUNT="previous_findings/4x04_hunting_report.txt"
MEMORY="ir_evidence/memory_artifacts.txt"
DISK="ir_evidence/disk_forensics_report.txt"
FIREWALL="ir_evidence/firewall_sessions_ws_recv_03.json"
IR_NOTES="ir_evidence/ir_team_notes.txt"
TOPOLOGY="reference/network_topology.txt"
ASSETS="reference/meddefense_asset_inventory.txt"

FILES=(
    "$HUNT"
    "$MEMORY"
    "$DISK"
    "$FIREWALL"
    "$IR_NOTES"
    "$TOPOLOGY"
    "$ASSETS"
)

for file in "${FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Required evidence source missing: $file" >&2
        exit 1
    fi
done

for cmd in jq grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command missing: $cmd" >&2
        exit 1
    fi
done

line() {
    printf '%*s\n' 64 '' | tr ' ' '='
}

# ------------------------------------------------------------------
# Firewall facts
# ------------------------------------------------------------------

FW_LATERAL="$(
    jq -r '.summary.by_classification.LATERAL_MOVEMENT.session_count // 0' \
        "$FIREWALL"
)"

PRIMARY_C2="$(
    jq -r '.summary.by_classification.KNOWN_C2.destinations[0] // "UNKNOWN"' \
        "$FIREWALL"
)"

PRIMARY_C2_COUNT="$(
    jq -r '.summary.by_classification.KNOWN_C2.session_count // 0' \
        "$FIREWALL"
)"

SECONDARY_C2="$(
    jq -r \
        '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.destinations[0]
         // "UNKNOWN"' \
        "$FIREWALL"
)"

SECONDARY_FIRST="$(
    jq -r \
        '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.first_seen_in_window
         // "UNKNOWN"' \
        "$FIREWALL"
)"

EXFIL_COUNT="$(
    jq -r '.summary.by_classification.EXFIL_BURST.session_count // 0' \
        "$FIREWALL"
)"

EXFIL_BYTES="$(
    jq -r '.summary.by_classification.EXFIL_BURST.total_bytes_out // 0' \
        "$FIREWALL"
)"

# ------------------------------------------------------------------
# Header
# ------------------------------------------------------------------

line
echo "   ATTACK RECONSTRUCTION: Stage 4"
echo "   Lateral Movement, Data Staging, and Containment"
line
echo

echo "Primary pivot:"
echo "  WS-RECV-03 (10.10.3.21)"
echo
echo "Local execution context:"
echo "  MEDDEFENSE\\records03"
echo
echo "Compromised service account:"
echo "  MEDDEFENSE\\svc_healthsync"
echo
echo "Stage-4 window reconstructed:"
echo "  2026-05-04 through 2026-05-15"
echo

# ------------------------------------------------------------------
# Credential access
# ------------------------------------------------------------------

line
echo "1. CREDENTIAL ACCESS"
line
echo

cat <<'EOF'
[2026-05-04 18:11:08 CDT] Defender exclusion added

  Host:
    WS-RECV-03

  User context:
    records03 elevated token

  Change:
    Windows Defender exclusion:
      C:\Windows\Temp

  Operational significance:
    The exclusion was created BEFORE the LSASS dumper was written
    into the same directory.

  ATT&CK:
    T1562.001 - Impair Defenses

  Evidence:
    IR Memory - Defender configuration
    IR Disk   - SOFTWARE hive + $MFT timeline

  Confidence:
    CONFIRMED
EOF

echo

cat <<'EOF'
[2026-05-05 03:21:48-03:22:34 CDT] Credential dump #1

  Source:
    WS-RECV-03

  Local user context:
    MEDDEFENSE\records03

  Tool:
    C:\Windows\Temp\debug_tool.exe

  Target:
    LSASS process memory

  Output:
    C:\Windows\Temp\out.dat

  Sequence:
    03:21:48  debug_tool.exe written
    03:22:14  debug_tool.exe executed
    03:22:18  out.dat created
    03:22:34  LSASS dump write completed

  ATT&CK:
    T1003.001 - OS Credential Dumping: LSASS Memory

  Evidence:
    4x04 H4 - Sysmon process-access evidence
    IR Memory - residual LSASS access evidence
    IR Disk - Prefetch + $MFT + recovered out.dat

  Confidence:
    CONFIRMED - convergent evidence
EOF

echo

cat <<'EOF'
CREDENTIAL RECOVERY RESULT:

  Recovered out.dat:
    ~11 MB recovered from ~23 MB original dump.

  Credential strings:
    "svc_healthsync" appears four times in the recovered portion.

  Conclusion:
    svc_healthsync was present in the LSASS material acquired by
    debug_tool.exe.

  This provides the missing link between:

      LSASS dump
          |
          v
      svc_healthsync credential material
          |
          v
      unauthorized NTLM authentication
          |
          v
      PsExec / WMI / PowerShell Remoting

  Confidence:
    CONFIRMED that svc_healthsync credential material was harvested.

  Important limitation:
    The evidence strongly supports later credential reuse, but an
    NTLM authentication event by itself does not prove the exact
    credential representation used.

    Therefore exact Pass-the-Hash mechanics remain more cautiously
    assessed than the credential theft itself.
EOF

echo

cat <<'EOF'
[2026-05-12 02:45 CDT] Credential dump #2

  Host:
    WS-RECV-03

  Tool:
    debug_tool.exe

  Target:
    LSASS

  Output:
    out.dat overwritten

  Evidence:
    4x04 H4
    Disk Prefetch
    $MFT timeline

  Interpretation:
    The attacker re-dumped LSASS seven days after the first dump.

  Possible reason:
    Credential re-acquisition after suspected or actual rotation.

  Confidence:
    CONFIRMED for the dump.
    POSSIBLE for the reason it was repeated.
EOF

echo

echo "ADDITIONAL CREDENTIALS:"
echo
cat <<'EOF'
  CONFIRMED compromised service account:
    svc_healthsync

  No additional service-account credential is established by the
  supplied Stage-4 evidence at the same confidence level.

  records03:
    This is the local execution context on WS-RECV-03, not evidence
    that it was harvested as a second service-account credential.

  dmarsh:
    Previously harvested during Stage 1, but that is a separate
    credential-compromise event.

  Conclusion:
    Do NOT invent additional Stage-4 compromised credentials from
    usernames merely observed in memory or authentication logs.
EOF

echo

# ------------------------------------------------------------------
# Lateral movement
# ------------------------------------------------------------------

line
echo "2. LATERAL MOVEMENT CHAIN"
line
echo

cat <<'EOF'
[2026-05-06] PIVOT #1
  WS-RECV-03
       |
       | svc_healthsync / NTLM
       | PsExec -> WMI -> PowerShell Remoting
       v
  SRV-HEALTH-DB

  Canonical disk execution:
    02:11:42 CDT  PsExec64.exe
    02:13:11 CDT  WMIC.exe
    02:13:48 CDT  WMIC.exe
    02:36:14 CDT  stage1.ps1 copied toward SRV-HEALTH-DB

  Hunt timeline:
    approximately 02:12 CDT first PsExec session.

  Tools:
    PsExec64.exe
    WMI
    Enter-PSSession / PowerShell Remoting
    Copy-Item

  Credential:
    MEDDEFENSE\svc_healthsync

  ATT&CK:
    T1021.002 - SMB / Windows Admin Shares
    T1047     - Windows Management Instrumentation
    T1021.006 - Windows Remote Management
    T1078.002 - Domain Accounts

  Evidence:
    4x04 Wazuh/Sysmon hunt
    IR Disk Prefetch + $MFT
    IR Firewall cross-VLAN sessions

  Confidence:
    CONFIRMED
EOF

echo

cat <<'EOF'
[2026-05-09] PIVOT #2
  WS-RECV-03
       |
       | svc_healthsync / NTLM
       | PsExec -> WMI -> PowerShell Remoting
       v
  SRV-INS-DB

  Disk evidence:
    02:46:11 CDT  PsExec64.exe
    02:49:22 CDT  WMIC.exe
    02:50:08 CDT  WMIC.exe

  4x04 hunt:
    same unauthorized svc_healthsync + NTLM behavior.

  Credential:
    MEDDEFENSE\svc_healthsync

  ATT&CK:
    T1021.002
    T1047
    T1021.006
    T1078.002

  Evidence:
    4x04 Hunt
    IR Disk
    IR Firewall

  Confidence:
    CONFIRMED
EOF

echo

cat <<'EOF'
[2026-05-13] PIVOT #3
  WS-RECV-03
       |
       | svc_healthsync / NTLM
       | PsExec -> WMI -> PowerShell Remoting
       v
  SRV-DC-01

  Disk evidence:
    02:08:56 CDT  PsExec64.exe
    02:11:11 CDT  WMIC.exe

  Follow-on:
    PowerShell Remoting
    Get-ADUser enumeration

  Result:
    AD enumeration data later appears as query_results.csv.

  ATT&CK:
    T1021.002
    T1047
    T1021.006
    T1078.002

  Evidence:
    4x04 Hunt
    IR Disk
    IR Firewall

  Confidence:
    CONFIRMED
EOF

echo

echo "FIREWALL CORROBORATION:"
echo
echo "  Cross-VLAN lateral-movement sessions: $FW_LATERAL"
echo
echo "  Targets:"
echo "    SRV-HEALTH-DB"
echo "    SRV-INS-DB"
echo "    SRV-DC-01"
echo
echo "  Network services observed:"
echo "    TCP/445       SMB / PsExec"
echo "    TCP/135+RPC   WMI"
echo "    TCP/5985      WinRM / PowerShell Remoting"
echo

echo "COMPLETE PIVOT PATH:"
echo
cat <<'EOF'
  WS-RECV-03
      |
      |-- 06 May --> SRV-HEALTH-DB
      |
      |-- 09 May --> SRV-INS-DB
      |
      `-- 13 May --> SRV-DC-01
EOF

echo

# ------------------------------------------------------------------
# What hunt missed
# ------------------------------------------------------------------

line
echo "3. WHAT THE 4x04 HUNT MISSED"
line
echo

cat <<'EOF'
The hunt correctly discovered:

  [FOUND] LSASS credential dumping
  [FOUND] svc_healthsync misuse
  [FOUND] PsExec
  [FOUND] WMI
  [FOUND] PowerShell Remoting
  [FOUND] WS-RECV-03 as the Stage-4 pivot

The hunt did NOT query for or could not establish:

  [MISSED] Defender exclusion
           T1562.001

  [MISSED] Scheduled-task persistence
           T1053.005

  [MISSED] Local data staging
           T1074.001

  [MISSED] Archive collected data
           T1560.001

  [MISSED] File deletion
           T1070.004

  [MISSED] Windows Security log clearing
           T1070.001

  [MISSED] Secondary attacker endpoint
           203.0.113.47:8443

  [MISSED] Exact contents of the staged database data

  [MISSED] Successful exfiltration of the staged datasets

Important:
  These were mostly VISIBILITY / HUNT-SCOPE gaps.

  They do not mean the activity did not exist when 4x04 ran.
EOF

echo

# ------------------------------------------------------------------
# Persistence
# ------------------------------------------------------------------

line
echo "4. PERSISTENCE"
line
echo

cat <<EOF
[2026-05-07 01:47:33 CDT]

Scheduled Task:
  HealthSync Update Service

Created by:
  MEDDEFENSE\\records03

Trigger:
  Daily at 02:00

Execution:
  PowerShell / sync_healthdata.ps1

ATT&CK:
  T1053.005 - Scheduled Task/Job

Evidence:
  Memory:
    TaskCache registry evidence.

  Disk:
    Full task XML.
    SCHTASKS.EXE prefetch.
    \$MFT task-file creation.

Observed execution:
  Daily PowerShell executions at approximately 02:00.

Disk Prefetch confirms executions including:
  2026-05-08 02:00:11
  2026-05-09 02:00:14
  2026-05-10 02:00:14
  2026-05-11 02:00:11
  2026-05-12 02:00:14
  2026-05-13 02:00:08
  2026-05-14 02:00:11
  2026-05-15 02:00:14

Confidence:
  CONFIRMED
EOF

echo

echo "SECONDARY COMMUNICATION CHANNEL:"
echo
echo "  Endpoint: $SECONDARY_C2"
echo "  First observed: $SECONDARY_FIRST"
echo
echo "  Appears approximately 38 seconds after scheduled-task creation."
echo
echo "  Malicious association: CONFIRMED by Memory + Firewall."
echo "  Exact fallback/secondary C2 role: PROBABLE."
echo

# ------------------------------------------------------------------
# Data access
# ------------------------------------------------------------------

line
echo "5. DATA ACCESS AND STAGING"
line
echo

cat <<'EOF'
DATA FLOW RECONSTRUCTION:

  Database / directory servers
             |
             | remote access / query
             v
       WS-RECV-03
             |
             | CSV output
             v
  C:\Users\Public\Tmp\
             |
             | archive / staging
             v
  staging_export_*.zip
             |
             | HTTPS C2
             v
       External C2

Conclusion:
  Data was pulled back from the target systems and staged locally
  on WS-RECV-03.

  It was NOT merely archived on the database servers.
EOF

echo

cat <<'EOF'
[2026-05-08] PATIENT DATA

  Source system:
    SRV-HEALTH-DB

  Database:
    health_records

  Query result:
    out_20260508023559.csv

  Local staging host:
    WS-RECV-03

  Local staging directory:
    C:\Users\Public\Tmp\

  CSV:
    14,211,304 bytes
    47,138 patient records

  Archive:
    staging_export_001.zip
    14,219,484 bytes

  Archive created:
    02:36:34 CDT

  Deleted:
    02:38:14 CDT

  ATT&CK:
    T1005      - Data from Local System / collected data
    T1074.001  - Local Data Staging
    T1560.001  - Archive Collected Data
    T1070.004  - File Deletion

  Confidence:
    CONFIRMED
EOF

echo

cat <<'EOF'
[2026-05-11] INSURANCE DATA

  Source system:
    SRV-INS-DB

  Query result:
    out_20260511031408.csv

  Local staging host:
    WS-RECV-03

  Local staging directory:
    C:\Users\Public\Tmp\

  Archive:
    staging_export_002.zip
    11,802,944 bytes

  Records:
    51,002 insurance/member records

  CSV created:
    03:14:42 CDT

  Archive created:
    03:15:09 CDT

  Files deleted:
    03:17:01 CDT

  ATT&CK:
    T1005
    T1074.001
    T1560.001
    T1070.004

  Confidence:
    CONFIRMED
EOF

echo

cat <<'EOF'
[2026-05-13] ACTIVE DIRECTORY COLLECTION

  Source:
    SRV-DC-01

  Activity:
    Get-ADUser enumeration

  Local output:
    C:\Users\Public\Tmp\query_results.csv

  Created:
    02:31:18 CDT

  Deleted:
    02:34:05 CDT

  Records:
    1,184 AD account records

  Evidence:
    4x04 PSRemoting / Get-ADUser finding
    Disk recovered CSV
    Firewall transfer correlation

  Confidence:
    CONFIRMED
EOF

echo

# ------------------------------------------------------------------
# Exfiltration
# ------------------------------------------------------------------

line
echo "6. EXFILTRATION STATUS"
line
echo

echo "Firewall exfiltration bursts: $EXFIL_COUNT"
echo "Total matched outbound bytes: $EXFIL_BYTES"
echo "Primary destination: $PRIMARY_C2"
echo

cat <<'EOF'
The Stage-4 hunt could not determine whether staged data left
MedDefense.

The 4x05 IR evidence resolves that question.

  Disk:
    proves the files existed and identifies their contents.

  Firewall:
    records outbound transfers whose byte counts match the
    recovered staging artifacts.

Confirmed examples:

  2026-05-08
    staging_export_001.zip
    14,219,484 bytes

        exact byte match

    14,219,484 bytes outbound to known C2


  2026-05-11
    staging_export_002.zip
    11,802,944 bytes

        exact byte match

    11,802,944 bytes outbound to known C2


  2026-05-13
    query_results.csv
    8,419,232 bytes

        exact byte match

    8,419,232 bytes outbound to known C2


EXFILTRATION STATUS:
  CONFIRMED

Sensitive-data impact:
  47,138 patient records
  51,002 insurance/member records

Sensitive patient + insurance total:
  98,140 records

Additional:
  1,184 AD records used for reconnaissance.
EOF

echo

# ------------------------------------------------------------------
# Anti-forensics
# ------------------------------------------------------------------

line
echo "7. ANTI-FORENSICS AND OPERATIONAL SECURITY"
line
echo

cat <<'EOF'
[1] DEFENDER EXCLUSION

  C:\Windows\Temp excluded before debug_tool.exe deployment.

  Technique:
    T1562.001 - Impair Defenses

  Result:
    Credential-dumping utility could execute from the excluded path.


[2] RAPID FILE DELETION

  Attacker-created staging files were deleted minutes after use.

  Examples:
    staging_export_001.zip
    staging_export_002.zip
    query_results.csv
    out.dat
    hb_cfg.json

  Technique:
    T1070.004 - File Deletion


[3] WINDOWS SECURITY LOG CLEARING

  2026-05-09 03:00 CDT:
    Security log gap begins.

  2026-05-09 03:01:42 CDT:
    Security.evtx deleted/recreated.

  2026-05-09 03:12:02 CDT:
    New Security log entries resume.

  Gap:
    approximately 12 minutes.

  Technique:
    T1070.001 - Clear Windows Event Logs

  Evidence:
    Disk $MFT + recreated Security.evtx
    Memory clear_logs:true configuration

  Confidence:
    CONFIRMED


[4] LIVING OFF THE LAND

  PsExec
  WMI
  PowerShell
  WinRM

  These are legitimate administration technologies.

  Attacker advantage:
    Tool identity alone resembles normal IT administration.

  What exposed the attacker:
    CONTEXT.

      Wrong source:
        WS-RECV-03 instead of WS-ADMIN-01

      Wrong identity:
        svc_healthsync from a workstation

      Wrong authentication:
        NTLM instead of expected Kerberos

      Wrong time:
        01:00-04:00 CDT

      Wrong targets:
        sensitive servers reached from a records workstation


OPSEC ASSESSMENT:

  The attacker demonstrated basic operational discipline:

    - legitimate administration tools
    - off-hours execution
    - Defender exclusion
    - scheduled automation
    - rapid deletion
    - Security-log clearing
    - secondary communication channel

  But anti-forensics was incomplete.

  They did NOT delete:

    - USN Journal
    - Prefetch
    - Volume Shadow Copies
    - $MFT evidence

  Consequently disk forensics reconstructed much of the operation.
EOF

echo

# ------------------------------------------------------------------
# Containment
# ------------------------------------------------------------------

line
echo "8. CONTAINMENT MOMENT"
line
echo

cat <<'EOF'
Threat-hunt result:

  4x04 identified anomalous Stage-4 behavior on WS-RECV-03.

Key recommendation:

  R1:
    Immediately isolate WS-RECV-03.
    Capture volatile memory before shutdown.
    Image disk.
EOF

echo

cat <<'EOF'
[2026-05-15 13:42 CDT / 18:42 UTC]

  WS-RECV-03 ISOLATED

  Method:
    Access-layer switch ACL / port shutdown.

  Result:
    Host became console-only.
    No further successful outbound network traffic.

  Evidence:
    IR Team Notes
    Firewall sessions

  Confidence:
    CONFIRMED
EOF

echo

cat <<'EOF'
[2026-05-15 14:18:42 CDT]

  LIVE MEMORY CAPTURED

  Tool:
    WinPmem 4.0.1

  Important:
    Host remained powered but network-isolated.

  Result:
    Preserved live process and connection state, including the
    secondary 203.0.113.47:8443 connection evidence.
EOF

echo

cat <<'EOF'
[2026-05-15 19:45 CDT]

  DISK IMAGE ACQUIRED

  Tool:
    FTK Imager 4.7.1.4

  Result:
    Deleted staging artifacts, persistence, Prefetch, $MFT and
    anti-forensic evidence were preserved for reconstruction.
EOF

echo

echo "FIREWALL AFTER CONTAINMENT:"
echo
echo "  Previously observed C2 sessions: $PRIMARY_C2_COUNT"
echo
echo "  RAT continued attempting its approximately 5-minute beacons."
echo "  Post-isolation attempts were denied."
echo

# ------------------------------------------------------------------
# Critical containment interpretation
# ------------------------------------------------------------------

line
echo "9. DID THE HUNT INTERRUPT EXFILTRATION?"
line
echo

cat <<'EOF'
NO -- not before the major confirmed datasets had already left.

By the time WS-RECV-03 was isolated:

  [08 May]
    47,138 patient records had already been exfiltrated.

  [11 May]
    51,002 insurance/member records had already been exfiltrated.

  [13 May]
    1,184 AD account records had already been transmitted.

Therefore the correct reconstruction is:

  4x04 hunt
       |
       v
  detected the continuing intrusion
       |
       v
  triggered incident response
       |
       v
  stopped FURTHER attacker activity

It did NOT prevent the already-completed exfiltration events.

This distinction is critical for the final impact assessment.
EOF

echo

# ------------------------------------------------------------------
# What would happen next
# ------------------------------------------------------------------

line
echo "10. LIKELY NEXT ATTACKER ACTION"
line
echo

cat <<'EOF'
Evidence-supported assessment:

  At containment time:

    - RAT was still running.
    - Primary C2 was still beaconing.
    - Scheduled task was still executing daily.
    - Secondary attacker-associated channel existed.
    - The attacker had reached SRV-DC-01.
    - A second LSASS dump had recently occurred.
    - Patient and insurance datasets had already been stolen.

Therefore, without containment, continued attacker access is
PROBABLE.

Likely next actions include:

  - continued scheduled collection/exfiltration;
  - additional AD/domain reconnaissance;
  - use of newly acquired credential material;
  - additional lateral movement;
  - collection from other accessible systems;
  - continued deletion/log-clearing after operations.

Confidence:
  PROBABLE for continued activity.

Important:
  The supplied evidence does NOT establish exactly which server,
  dataset or credential the attacker would have targeted next.

  Any more specific prediction would be speculation.
EOF

echo

# ------------------------------------------------------------------
# Stage 4 timeline
# ------------------------------------------------------------------

line
echo "11. STAGE-4 RECONSTRUCTED TIMELINE"
line
echo

cat <<'EOF'
04 May 18:11
  Defender exclusion added
       |
       v
05 May 03:22
  debug_tool.exe -> LSASS -> out.dat
  svc_healthsync credential material recovered
       |
       v
06 May 02:11+
  WS-RECV-03 -> SRV-HEALTH-DB
  PsExec -> WMI -> PSRemoting
       |
       v
07 May 01:47
  HealthSync Update Service created
  daily 02:00 persistence
       |
       +---- 38 sec ----> secondary C2 appears
       |
       v
08 May
  HEALTH-DB data -> WS-RECV-03
  47,138 patient records
  CSV -> ZIP -> exfil -> deletion
       |
       v
09 May
  WS-RECV-03 -> SRV-INS-DB
  PsExec -> WMI -> PSRemoting
  Security log cleared
       |
       v
11 May
  INS-DB data -> WS-RECV-03
  51,002 insurance/member records
  CSV -> ZIP -> exfil -> deletion
       |
       v
12 May 02:45
  Second LSASS dump
       |
       v
13 May
  WS-RECV-03 -> SRV-DC-01
  PsExec -> WMI -> PSRemoting
  Get-ADUser
  1,184 AD records -> exfil
       |
       v
15 May 02:00
  Scheduled task still executing
       |
       v
15 May 13:42
  WS-RECV-03 ISOLATED
       |
       v
14:18
  Live memory captured
       |
       v
19:45
  Disk image completed
EOF

echo

# ------------------------------------------------------------------
# ATT&CK
# ------------------------------------------------------------------

line
echo "12. ATT&CK MAPPING"
line
echo

cat <<'EOF'
Credential Access:
  T1003.001  OS Credential Dumping: LSASS Memory

Defense Evasion:
  T1562.001  Impair Defenses
  T1070.001  Clear Windows Event Logs
  T1070.004  File Deletion

Persistence:
  T1053.005  Scheduled Task/Job
  T1547.001  Registry Run Keys / Startup Folder

Valid Account:
  T1078.002  Domain Accounts

Lateral Movement / Execution:
  T1021.002  SMB / Windows Admin Shares
  T1047      Windows Management Instrumentation
  T1021.006  Windows Remote Management

Credential Reuse:
  T1550.002  Pass-the-Hash
              Strongly supported by the project evidence;
              exact hash-reuse mechanism should retain the
              documented forensic qualification.

Collection / Staging:
  T1005      Data from Local System
  T1074.001  Local Data Staging
  T1560.001  Archive Collected Data

Command and Control / Exfiltration:
  T1071.001  Web Protocols
  T1041      Exfiltration Over C2 Channel
EOF

echo

# ------------------------------------------------------------------
# Final assessment
# ------------------------------------------------------------------

line
echo "STAGE 4 FINAL ASSESSMENT"
line
echo

cat <<'EOF'
CONFIRMED:

  - WS-RECV-03 was the Stage-4 pivot host.
  - debug_tool.exe accessed LSASS.
  - svc_healthsync credential material was recovered from the dump.
  - svc_healthsync was abused from WS-RECV-03 using NTLM.
  - SRV-HEALTH-DB was reached.
  - SRV-INS-DB was reached.
  - SRV-DC-01 was reached.
  - PsExec, WMI and PowerShell Remoting were used.
  - Scheduled-task persistence was established.
  - Patient data was collected and staged on WS-RECV-03.
  - Insurance/member data was collected and staged on WS-RECV-03.
  - AD enumeration data was collected.
  - Staged sensitive data was successfully exfiltrated.
  - Attacker-created staging artifacts were deleted.
  - Windows Security logging was cleared.
  - C2 remained operational until containment.
  - Isolation stopped further successful outbound communication.

PROBABLE:

  - svc_healthsync was reused via Pass-the-Hash specifically.
  - 203.0.113.47:8443 functioned as fallback/secondary C2.
  - Continued collection and lateral movement would have occurred
    without containment.

NOT ESTABLISHED:

  - Additional Stage-4 service-account credentials beyond
    svc_healthsync.
  - The exact next server/data source the attacker intended to target.
  - That the threat hunt prevented the already completed May 8,
    May 11 and May 13 exfiltration events.

OVERALL STAGE-4 CONFIDENCE:
  HIGH
EOF

echo
line
echo "   Stage 4 reconstruction complete."
line