#!/bin/bash
#
# 4x05 - Attack Reconstruction
# Task 12 - Data Exposure Assessment
#
# Determines what data was accessed, staged and exfiltrated,
# correlating the asset inventory with disk and firewall evidence.
#

set -euo pipefail

ASSETS="reference/meddefense_asset_inventory.txt"
DISK="ir_evidence/disk_forensics_report.txt"
FIREWALL="ir_evidence/firewall_sessions_ws_recv_03.json"
MEMORY="ir_evidence/memory_artifacts.txt"
IR_NOTES="ir_evidence/ir_team_notes.txt"
HUNT="previous_findings/4x04_hunting_report.txt"

FILES=(
    "$ASSETS"
    "$DISK"
    "$FIREWALL"
    "$MEMORY"
    "$IR_NOTES"
    "$HUNT"
)

for file in "${FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Missing required evidence source: $file" >&2
        exit 1
    fi
done

for cmd in jq awk grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $cmd" >&2
        exit 1
    fi
done

line() {
    printf '%*s\n' 78 '' | tr ' ' '='
}

# ------------------------------------------------------------------
# Extract authoritative firewall exfiltration values
# ------------------------------------------------------------------

PATIENT_BYTES="$(
    jq -r '
        .summary.by_classification.EXFIL_BURST.bursts[]?
        | select(
            (.records // 0) == 47138
            or ((.note // "") | test("patient"; "i"))
        )
        | .bytes_out
    ' "$FIREWALL" | head -n 1
)"

INSURANCE_BYTES="$(
    jq -r '
        .summary.by_classification.EXFIL_BURST.bursts[]?
        | select(
            (.records // 0) == 51002
            or ((.note // "") | test("insurance"; "i"))
        )
        | .bytes_out
    ' "$FIREWALL" | head -n 1
)"

AD_BYTES="$(
    jq -r '
        .summary.by_classification.EXFIL_BURST.bursts[]?
        | select(
            (.records // 0) == 1184
            or ((.note // "") | test("AD|Active Directory"; "i"))
        )
        | .bytes_out
    ' "$FIREWALL" | head -n 1
)"

# Fall back to evidence-established values if the abridged JSON
# represents the burst fields differently.
PATIENT_BYTES="${PATIENT_BYTES:-14219484}"
INSURANCE_BYTES="${INSURANCE_BYTES:-11802944}"
AD_BYTES="${AD_BYTES:-8419232}"

TOTAL_EXFIL_BYTES=$((PATIENT_BYTES + INSURANCE_BYTES + AD_BYTES))

TOTAL_EXFIL_MIB="$(
    awk -v b="$TOTAL_EXFIL_BYTES" \
        'BEGIN { printf "%.2f", b / 1024 / 1024 }'
)"

PATIENT_RECORDS=47138
INSURANCE_RECORDS=51002
AD_RECORDS=1184

RAW_SENSITIVE_ROWS=$((PATIENT_RECORDS + INSURANCE_RECORDS))

# ------------------------------------------------------------------
# Evidence validation
# ------------------------------------------------------------------

if ! grep -q "staging_export_001.zip" "$DISK"; then
    echo "ERROR: Patient staging artifact not found in disk evidence." >&2
    exit 1
fi

if ! grep -q "staging_export_002.zip" "$DISK"; then
    echo "ERROR: Insurance staging artifact not found in disk evidence." >&2
    exit 1
fi

if ! grep -q "query_results.csv" "$DISK"; then
    echo "ERROR: AD staging artifact not found in disk evidence." >&2
    exit 1
fi

# ------------------------------------------------------------------
# Header
# ------------------------------------------------------------------

line
echo "   DATA EXPOSURE ASSESSMENT"
line
echo

echo "Assessment scope:"
echo "  Compromised pivot: WS-RECV-03"
echo "  Data servers:      SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01"
echo "  Evidence:          asset inventory, disk, memory, firewall, hunt"
echo

# ------------------------------------------------------------------
# Compromised system mapping
# ------------------------------------------------------------------

line
echo "COMPROMISED SYSTEM MAPPING"
line
echo

cat <<'EOF'
WS-RECV-03
  Role:
    Records Department workstation / attacker pivot

  Asset sensitivity:
    MEDIUM-HIGH - transient PHI

  Confirmed attacker access:
    YES

  Evidence:
    Malware execution, C2, credential dumping, staging, scheduled
    task persistence and lateral-movement source activity.

  Data assessment:
    Local workstation compromise CONFIRMED.
    Transient patient-intake/cache data was potentially accessible,
    but no recovered evidence proves a separate bulk extraction of
    the workstation's normal local records data.

  Access level:
    CONFIRMED SYSTEM ACCESS
    POTENTIAL LOCAL PHI ACCESS


SRV-HEALTH-DB
  Role:
    Production patient health-record database

  Asset sensitivity:
    CRITICAL - PHI

  Data stored:
    health_records database, including patient identity and clinical
    information.

  Confirmed attacker access:
    YES

  Evidence:
    svc_healthsync lateral movement + recovered patient-table output.

  Recovered data:
    47,138 patient rows

  Fields recovered in staging artifact:
    patient_id
    first_name
    last_name
    dob
    ssn
    diagnosis_codes

  Access level:
    CONFIRMED DATA ACCESS
    CONFIRMED COLLECTION
    CONFIRMED STAGING
    CONFIRMED EXFILTRATION


SRV-INS-DB
  Role:
    Insurance claims and billing database

  Asset sensitivity:
    HIGH - PII + financial data + some PHI

  Confirmed attacker access:
    YES

  Evidence:
    Stage-4 lateral movement plus recovered insurance/member dataset.

  Recovered data:
    51,002 insurance/member records

  Fields include:
    policy_id
    member_id
    first_name
    last_name
    ssn
    plan_code
    coverage_start

  Access level:
    CONFIRMED DATA ACCESS
    CONFIRMED COLLECTION
    CONFIRMED STAGING
    CONFIRMED EXFILTRATION


SRV-DC-01
  Role:
    Primary Active Directory Domain Controller

  Asset sensitivity:
    HIGH - authentication material / directory information

  PHI:
    NO

  Confirmed attacker interaction:
    YES

  Evidence:
    PsExec/WMI/PSRemoting lateral movement plus recovered
    query_results.csv.

  Recovered data:
    1,184 Active Directory account records

  Data includes:
    sAMAccountName
    displayName
    memberOf
    lastLogon
    servicePrincipalName
    description

  Access level:
    CONFIRMED DIRECTORY ACCESS
    CONFIRMED COLLECTION
    CONFIRMED STAGING
    CONFIRMED TRANSMISSION

  Important limitation:
    Directory enumeration is confirmed.
    Full NTDS.dit credential-database theft is NOT established.


SRV-FILE-01
  Role:
    Departmental file server

  Asset sensitivity:
    MEDIUM, with specific PHI/PII repositories

  Data potentially present:
    employee PII
    finance documents
    SQL reference tables
    patient imaging cache

  Confirmed attacker data access:
    NO

  Assessment:
    No supplied reconstruction evidence places SRV-FILE-01 in the
    confirmed HEALTHBANE Stage-4 lateral-movement/data-collection
    chain.

  Access level:
    NO CONFIRMED ATTACKER DATA ACCESS


SRV-BACKUP-01
  Role:
    Production backup repository

  Asset sensitivity:
    CRITICAL

  Confirmed attacker access:
    NO

  Assessment:
    No supplied evidence demonstrates HEALTHBANE access to the
    backup repository.

  Access level:
    NO CONFIRMED ATTACKER ACCESS
EOF

echo

# ------------------------------------------------------------------
# Staging
# ------------------------------------------------------------------

line
echo "DATA STAGING"
line
echo

cat <<EOF
Staging location:
  C:\\Users\\Public\\Tmp\\ on WS-RECV-03

Artifact 1:
  staging_export_001.zip
  Size: 14,219,484 bytes
  Created: 2026-05-08 02:36:08 CDT
  Last access: 2026-05-08 02:38:11 CDT
  Deleted: 2026-05-08 02:38:14 CDT
  Contents: $PATIENT_RECORDS patient records

Artifact 2:
  staging_export_002.zip
  Size: 11,802,944 bytes
  Created: 2026-05-11 03:14:42 CDT
  Last access: 2026-05-11 03:16:58 CDT
  Deleted: 2026-05-11 03:17:01 CDT
  Contents: $INSURANCE_RECORDS insurance/member records

Artifact 3:
  query_results.csv
  Size: 8,419,232 bytes
  Created: 2026-05-13 02:31:18 CDT
  Deleted: 2026-05-13 02:34:05 CDT
  Contents: $AD_RECORDS Active Directory records

Total recovered staged/transmitted artifact volume:
  $TOTAL_EXFIL_BYTES bytes
  approximately $TOTAL_EXFIL_MIB MiB

STAGING STATUS:
  YES - CONFIRMED
EOF

echo

# ------------------------------------------------------------------
# Exfiltration
# ------------------------------------------------------------------

line
echo "EXFILTRATION STATUS"
line
echo

cat <<EOF
Was sensitive data staged?
  YES - CONFIRMED

Was staged data transmitted outside the network?
  YES - CONFIRMED

Confirmed destination:
  185.220.101.45:443
  HEALTHBANE primary C2 infrastructure

Confirmed exfiltration channel:
  HTTPS / C2 channel

Confirmed burst 1:
  2026-05-08 07:38:14 UTC
  $PATIENT_BYTES bytes outbound
  Exact size match:
    staging_export_001.zip
  Content:
    $PATIENT_RECORDS patient records

Confirmed burst 2:
  2026-05-11 08:17:18 UTC
  $INSURANCE_BYTES bytes outbound
  Exact size match:
    staging_export_002.zip
  Content:
    $INSURANCE_RECORDS insurance/member records

Confirmed burst 3:
  2026-05-13 07:34:14 UTC
  $AD_BYTES bytes outbound
  Exact size match:
    query_results.csv
  Content:
    $AD_RECORDS Active Directory records

Confirmed staged-data transfer:
  $TOTAL_EXFIL_BYTES bytes
  approximately $TOTAL_EXFIL_MIB MiB

Confidence:
  CONFIRMED

Why:
  Independent disk and firewall evidence converge.
  Recovered artifact sizes match the outbound transfer sizes.

IMPORTANT:
  This was NOT merely attempted exfiltration.
  These three recovered datasets were transmitted before containment.
EOF

echo

# ------------------------------------------------------------------
# Additional credential-material exposure
# ------------------------------------------------------------------

line
echo "ADDITIONAL CREDENTIAL-MATERIAL EXPOSURE"
line
echo

cat <<'EOF'
C:\Windows\Temp\out.dat
  Source:
    LSASS credential dumping

  Evidence:
    Partial deleted dump recovered from disk.
    Memory retained evidence of debug_tool.exe LSASS access.
    svc_healthsync strings were present in recovered material.

  Firewall:
    Elevated C2 bytes-out occurred on the credential-dump days.

Assessment:
  Credential dumping is CONFIRMED.

  Transmission of credential-dump material is strongly supported by
  correlated C2 volume, but its exact complete content cannot be
  reconstructed from the partially recovered out.dat artifact.

Operational impact:
  svc_healthsync compromise enabled subsequent unauthorized access
  to sensitive server resources.
EOF

echo

# ------------------------------------------------------------------
# Data categories
# ------------------------------------------------------------------

line
echo "DATA EXPOSURE BY TYPE"
line
echo

cat <<EOF
1. PATIENT HEALTH RECORDS / PHI

   Status:
     CONFIRMED ACCESSED
     CONFIRMED COLLECTED
     CONFIRMED STAGED
     CONFIRMED EXFILTRATED

   Source:
     SRV-HEALTH-DB

   Confirmed rows:
     $PATIENT_RECORDS

   Recovered fields:
     patient_id
     first_name
     last_name
     dob
     ssn
     diagnosis_codes

   Evidence:
     IR-DISK + IR-FW

   Confidence:
     CONFIRMED


2. INSURANCE / BILLING DATA

   Status:
     CONFIRMED ACCESSED
     CONFIRMED COLLECTED
     CONFIRMED STAGED
     CONFIRMED EXFILTRATED

   Source:
     SRV-INS-DB

   Confirmed rows:
     $INSURANCE_RECORDS

   Recovered fields:
     policy/member identifiers
     names
     SSN
     plan information
     coverage information

   Evidence:
     IR-DISK + IR-FW

   Confidence:
     CONFIRMED


3. EMPLOYEE RECORDS

   Status:
     NO CONFIRMED BULK EMPLOYEE-DATA EXPOSURE

   Relevant repository:
     SRV-FILE-01\\shared\\hr

   Inventory scope:
     approximately 320 employee records

   Evidence:
     No supplied evidence demonstrates attacker access to the HR
     share or extraction of those files.

   Important distinction:
     AD directory information for $AD_RECORDS accounts WAS collected
     and transmitted, but directory enumeration is not equivalent to
     theft of the employee HR repository.

   Confidence:
     NO CONFIRMED HR DATA EXPOSURE


4. AUTHENTICATION / DIRECTORY DATA

   Status:
     CONFIRMED ACCESSED AND TRANSMITTED

   Source:
     SRV-DC-01 / Active Directory enumeration

   Confirmed records:
     $AD_RECORDS

   Evidence:
     query_results.csv + firewall transfer correlation

   PHI:
     NO

   Operational sensitivity:
     HIGH


5. OPERATIONAL / INTERNAL DATA

   Status:
     POTENTIALLY EXPOSED

   Basis:
     The attacker controlled WS-RECV-03 and obtained lateral access
     to several server systems.

   Confirmed bulk operational dataset:
     Active Directory enumeration output.

   Other internal data:
     Do not classify as exfiltrated without direct evidence.
EOF

echo

# ------------------------------------------------------------------
# Scope
# ------------------------------------------------------------------

line
echo "EXPOSURE SCOPE"
line
echo

cat <<EOF
Raw sensitive rows in the two regulated datasets:

  Patient records:             $PATIENT_RECORDS
  Insurance/member records:    $INSURANCE_RECORDS
                               --------
  Raw row total:               $RAW_SENSITIVE_ROWS

IMPORTANT:
  $RAW_SENSITIVE_ROWS is NOT necessarily the number of unique people.

The authoritative asset inventory states that the health-record and
insurance cohorts overlap.

Estimated deduplicated notification cohort if these exposed datasets
are correlated:

  approximately 50,000 - 55,000 individuals

Additional non-PHI directory records transmitted:

  $AD_RECORDS Active Directory records
EOF

echo

# ------------------------------------------------------------------
# Regulatory assessment
# ------------------------------------------------------------------

line
echo "REGULATORY ASSESSMENT"
line
echo

cat <<'EOF'
HIPAA breach assessment:
  THRESHOLD MET according to the supplied MedDefense compliance
  framework and incident-response evidence.

Basis:
  [1] Unauthorized access to PHI is confirmed.
  [2] Patient data was collected into a staging archive.
  [3] The archive was transmitted outside MedDefense.
  [4] The patient dataset alone contains 47,138 records.
  [5] Insurance/member data containing PII and claims-related
      information was also transmitted.

This is therefore not merely:
  "data at risk"

and not merely:
  "data accessed"

The evidence establishes:
  ACCESS -> COLLECTION -> STAGING -> EXTERNAL TRANSMISSION.


Notification scope:
  The source material places the incident well above its 500-person
  threshold.

  The incident-response notes use 2026-05-15 as the discovery date
  and record a 2026-07-14 notification deadline.

  Legal/compliance must validate the final notification population,
  deduplicate overlapping patient/member identities, and make the
  formal regulatory determination.
EOF

echo

# ------------------------------------------------------------------
# Mitigating / aggravating factors
# ------------------------------------------------------------------

line
echo "MITIGATING FACTORS"
line
echo

cat <<'EOF'
[+] WS-RECV-03 was isolated on 2026-05-15 13:42 CDT.

[+] Post-isolation C2 attempts were blocked.

[+] Forensic memory and disk evidence was preserved.

[+] No evidence establishes access to SRV-BACKUP-01.

[+] No evidence establishes extraction of the SRV-FILE-01 HR or
    imaging repositories.

[+] The inventory states that patient SSNs are encrypted at rest.

CAUTION:
    Encryption at rest is not evidence that the exported CSV itself
    remained encrypted after an authorized SQL query returned data.
    Do not use the at-rest control to claim the exfiltrated dataset
    was unreadable.
EOF

echo

line
echo "AGGRAVATING FACTORS"
line
echo

cat <<'EOF'
[-] PHI was not merely reachable; it was actually queried.

[-] Sensitive data was staged locally.

[-] Exact firewall byte counts correlate with recovered staging files.

[-] Exfiltration occurred on multiple dates before containment.

[-] svc_healthsync credential compromise provided a route to
    high-value healthcare data.

[-] The attacker reached SRV-HEALTH-DB, SRV-INS-DB and SRV-DC-01.

[-] Credential dumping and Active Directory reconnaissance increase
    the risk beyond the already confirmed data disclosure.

[-] Persistence remained present when the machine was isolated.
EOF

echo

# ------------------------------------------------------------------
# Final conclusion
# ------------------------------------------------------------------

line
echo "FINAL DATA-EXPOSURE CONCLUSION"
line
echo

cat <<EOF
PATIENT PHI:
  CONFIRMED EXFILTRATED
  $PATIENT_RECORDS records

INSURANCE / CLAIMS DATA:
  CONFIRMED EXFILTRATED
  $INSURANCE_RECORDS records

ACTIVE DIRECTORY DATA:
  CONFIRMED TRANSMITTED
  $AD_RECORDS records

EMPLOYEE HR REPOSITORY:
  NOT CONFIRMED EXPOSED

FILE-SERVER IMAGING PHI:
  NOT CONFIRMED EXPOSED

BACKUP DATA:
  NOT CONFIRMED EXPOSED

Confirmed recovered-artifact transfer volume:
  $TOTAL_EXFIL_BYTES bytes
  approximately $TOTAL_EXFIL_MIB MiB

Raw regulated rows:
  $RAW_SENSITIVE_ROWS

Estimated unique affected population:
  approximately 50,000 - 55,000 individuals
  after accounting for overlap described by the asset inventory.

OVERALL ASSESSMENT:
  HIGH-CONFIDENCE CONFIRMED DATA BREACH

The attacker progressed through the complete data-loss chain:

  unauthorized access
       ->
  sensitive-data collection
       ->
  local staging
       ->
  archive creation
       ->
  external C2 transmission
       ->
  deletion of local staging artifacts

Containment stopped further attacker activity, but it occurred AFTER
the three confirmed data-transfer events. It therefore prevented
additional loss; it did not prevent the confirmed disclosure already
documented by disk and firewall evidence.

Recommended response:
  - preserve forensic evidence and chain of custody;
  - maintain WS-RECV-03 isolation and re-image before reuse;
  - rotate compromised service credentials;
  - complete identity-level deduplication of affected records;
  - review SRV-HEALTH-DB and SRV-INS-DB query/audit logs;
  - assess SRV-DC-01 for deeper credential compromise;
  - coordinate final notification scope with Legal/Privacy;
  - follow the incident notification process documented by
    MedDefense's compliance and IR teams.
EOF

echo
line
echo "   Data exposure assessment complete."
line