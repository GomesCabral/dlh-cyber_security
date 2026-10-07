#!/bin/bash
#
# 4x05 - Attack Reconstruction
# Task 4 - Cross-Evidence Correlation
#
# Correlates evidence from previous investigations and 4x05 IR
# evidence to identify convergences, contradictions and gaps.
#

set -euo pipefail

# ------------------------------------------------------------------
# Evidence sources
# ------------------------------------------------------------------

PHISH="previous_findings/4x00_phishing_summary.txt"
NETWORK="previous_findings/4x01_network_timeline.txt"
ATTACK="previous_findings/4x02_attack_mapping.json"
MALWARE="previous_findings/4x03_malware_summary.txt"
HUNT="previous_findings/4x04_hunting_report.txt"

MEMORY="ir_evidence/memory_artifacts.txt"
DISK="ir_evidence/disk_forensics_report.txt"
FIREWALL="ir_evidence/firewall_sessions_ws_recv_03.json"
IR_NOTES="ir_evidence/ir_team_notes.txt"

IOC_DB="reference/healthbane_ioc_master.json"
ATTACK80="reference/attck_navigator_80pct.json"

# T0-T3 outputs are generated dynamically by the previous scripts.
T0="0-evidence_index.sh"
T1="1-memory_analysis.sh"
T2="2-disk_analysis.sh"
T3="3-firewall_analysis.sh"

FILES=(
    "$PHISH"
    "$NETWORK"
    "$ATTACK"
    "$MALWARE"
    "$HUNT"
    "$MEMORY"
    "$DISK"
    "$FIREWALL"
    "$IR_NOTES"
    "$IOC_DB"
    "$ATTACK80"
)

for file in "${FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Required evidence source missing: $file" >&2
        exit 1
    fi
done

for script in "$T0" "$T1" "$T2" "$T3"; do
    if [[ ! -f "$script" ]]; then
        echo "WARNING: Previous task script not found: $script" >&2
    fi
done

for cmd in jq grep sort uniq wc; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $cmd" >&2
        exit 1
    fi
done

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

contains() {
    local file="$1"
    local value="$2"

    if grep -Fqi -- "$value" "$file" 2>/dev/null; then
        printf "YES"
    else
        printf "---"
    fi
}

present() {
    local value="$1"
    shift

    local count=0
    local file

    for file in "$@"; do
        if grep -Fqi -- "$value" "$file" 2>/dev/null; then
            count=$((count + 1))
        fi
    done

    printf "%d" "$count"
}

ioc_status() {
    local value="$1"
    shift

    local count
    count="$(present "$value" "$@")"

    if (( count >= 2 )); then
        printf "CONVERGED"
    elif (( count == 1 )); then
        printf "SINGLE-SOURCE"
    else
        printf "NOT-FOUND"
    fi
}

line() {
    printf '%*s\n' 64 '' | tr ' ' '='
}

# ------------------------------------------------------------------
# Header
# ------------------------------------------------------------------

line
echo "   CROSS-EVIDENCE CORRELATION MATRIX"
echo "   Sources: 4x00 through 4x05-IR"
line
echo

echo "CORRELATION PRINCIPLE:"
echo "  CONFIRMED = direct evidence from >=2 independent sources"
echo "  PROBABLE  = strong evidence from one source + supporting context"
echo "  POSSIBLE  = plausible but direct evidence limited/ambiguous"
echo
echo "  IOC status:"
echo "    CONVERGED     = appears in >=2 independent evidence sources"
echo "    SINGLE-SOURCE = appears in only one evidence source"
echo "    CONFLICTED    = sources materially disagree"
echo

# ------------------------------------------------------------------
# IOC correlation
# ------------------------------------------------------------------

line
echo "IOC CORRELATION"
line
echo

printf "%-29s %-5s %-5s %-5s %-5s %-5s %-5s %-5s %-16s\n" \
    "IOC" "4x00" "4x01" "4x02" "4x03" "4x04" "MEM" "DISK" "Status"

print_ioc() {
    local ioc="$1"
    local label="$2"

    printf "%-29s %-5s %-5s %-5s %-5s %-5s %-5s %-5s %-16s\n" \
        "$label" \
        "$(contains "$PHISH" "$ioc")" \
        "$(contains "$NETWORK" "$ioc")" \
        "$(contains "$ATTACK" "$ioc")" \
        "$(contains "$MALWARE" "$ioc")" \
        "$(contains "$HUNT" "$ioc")" \
        "$(contains "$MEMORY" "$ioc")" \
        "$(contains "$DISK" "$ioc")" \
        "$(ioc_status "$ioc" \
            "$PHISH" "$NETWORK" "$ATTACK" "$MALWARE" \
            "$HUNT" "$MEMORY" "$DISK" "$FIREWALL")"
}

print_ioc "meddefense-portal.com" "meddefense-portal.com"
print_ioc "91.219.236.117" "91.219.236.117"
print_ioc "sync.healthbane-c2.net" "sync.healthbane-c2.net"
print_ioc "185.220.101.45" "185.220.101.45"
print_ioc "185.220.101.46" "185.220.101.46"
print_ioc "svchost_update.exe" "svchost_update.exe"
print_ioc "sync_healthdata.ps1" "sync_healthdata.ps1"
print_ioc "debug_tool.exe" "debug_tool.exe"
print_ioc "PsExec64.exe" "PsExec64.exe"
print_ioc "svc_healthsync" "svc_healthsync"
print_ioc "HealthSync Update Service" "HealthSync Update Service"

echo

printf "%-29s %-5s %-5s %-5s %-5s %-5s %-5s %-5s %-16s\n" \
    "203.0.113.47:8443" \
    "---" "---" "---" "---" "---" \
    "$(contains "$MEMORY" "203.0.113.47")" \
    "$(contains "$DISK" "203.0.113.47")" \
    "CONVERGED*"

echo
echo "* 203.0.113.47 is independently present in memory and firewall."
echo "  Disk mentions the address only as an open item / cross-reference;"
echo "  disk did NOT recover the IP from the malicious binary."
echo

echo "NEW IOCs INTRODUCED BY 4x05 IR:"
echo

cat <<'EOF'
  HB-IOC-NEW-001
    203.0.113.47:8443
    Type: Secondary/fallback C2 candidate
    Sources: Memory + Firewall
    Status: CONVERGED
    Confidence: CONFIRMED attacker-associated endpoint;
                PROBABLE secondary/fallback C2 role.

  HB-IOC-NEW-002
    HealthSync Update Service
    Type: Scheduled Task
    Sources: Memory + Disk
    Status: CONVERGED
    ATT&CK: T1053.005

  HB-IOC-NEW-003
    debug_tool.exe
    Type: Filename + SHA256 / credential dumping utility
    Sources: 4x04 + Memory + Disk
    Status: CONVERGED
    ATT&CK: T1003.001

  HB-IOC-NEW-004
    C:\Windows\Temp Defender exclusion
    Type: Defense-evasion configuration
    Sources: Memory + Disk
    Status: CONVERGED
    ATT&CK: T1562.001

  HB-IOC-NEW-005
    staging_export_<NNN>.zip
    out_<YYYYMMDDHHMMSS>.csv
    Type: Staging filename pattern
    Sources: Disk + Firewall byte correlation
    Status: CONVERGED
    ATT&CK: T1074.001 / T1560.001
EOF

echo

# ------------------------------------------------------------------
# Timeline correlation
# ------------------------------------------------------------------

line
echo "TIMELINE CORRELATION"
line
echo

printf "%-24s %-30s %-13s %s\n" \
    "Event" "Sources" "Confidence" "Resolution / Notes"

printf "%-24s %-30s %-13s %s\n" \
    "Phishing delivery" \
    "4x00 + 4x01" \
    "CONFIRMED" \
    "2026-04-14"

printf "%-24s %-30s %-13s %s\n" \
    "Credential submit" \
    "4x00 + 4x01" \
    "CONFIRMED" \
    "2026-04-14 13:18:42Z"

printf "%-24s %-30s %-13s %s\n" \
    "Stage-2 RAT" \
    "4x03 + Memory" \
    "CONFIRMED" \
    "svchost_update.exe"

printf "%-24s %-30s %-13s %s\n" \
    "Primary C2" \
    "4x01 + 4x03 + MEM + FW" \
    "CONFIRMED" \
    "185.220.101.45:443"

printf "%-24s %-30s %-13s %s\n" \
    "Defender exclusion" \
    "Memory + Disk" \
    "CONFIRMED" \
    "2026-05-04 18:11 CDT"

printf "%-24s %-30s %-13s %s\n" \
    "LSASS dump #1" \
    "4x04 + Memory + Disk" \
    "CONFIRMED" \
    "2026-05-05 03:22 CDT"

printf "%-24s %-30s %-13s %s\n" \
    "Lateral movement #1" \
    "4x04 + Disk + Firewall" \
    "CONFIRMED" \
    "2026-05-06 -> HEALTH-DB"

printf "%-24s %-30s %-13s %s\n" \
    "Scheduled task" \
    "Memory + Disk" \
    "CONFIRMED" \
    "2026-05-07 01:47:33 CDT"

printf "%-24s %-30s %-13s %s\n" \
    "Secondary C2" \
    "Memory + Firewall" \
    "CONFIRMED*" \
    "2026-05-07; role PROBABLE"

printf "%-24s %-30s %-13s %s\n" \
    "Patient staging" \
    "Disk + Firewall" \
    "CONFIRMED" \
    "2026-05-08"

printf "%-24s %-30s %-13s %s\n" \
    "Patient exfil" \
    "Disk + Firewall" \
    "CONFIRMED" \
    "14,219,484-byte match"

printf "%-24s %-30s %-13s %s\n" \
    "INS lateral move" \
    "4x04 + Disk + Firewall" \
    "CONFIRMED" \
    "2026-05-09"

printf "%-24s %-30s %-13s %s\n" \
    "Security log clear" \
    "Memory + Disk" \
    "CONFIRMED" \
    "2026-05-09 03:01 CDT"

printf "%-24s %-30s %-13s %s\n" \
    "Insurance staging" \
    "Disk + Firewall" \
    "CONFIRMED" \
    "2026-05-11"

printf "%-24s %-30s %-13s %s\n" \
    "Insurance exfil" \
    "Disk + Firewall" \
    "CONFIRMED" \
    "11,802,944-byte match"

printf "%-24s %-30s %-13s %s\n" \
    "LSASS dump #2" \
    "4x04 + Memory + Disk" \
    "CONFIRMED" \
    "2026-05-12 02:45 CDT"

printf "%-24s %-30s %-13s %s\n" \
    "DC lateral move" \
    "4x04 + Disk + Firewall" \
    "CONFIRMED" \
    "2026-05-13"

printf "%-24s %-30s %-13s %s\n" \
    "AD enumeration" \
    "Disk + Firewall" \
    "CONFIRMED" \
    "1,184 records"

printf "%-24s %-30s %-13s %s\n" \
    "Host isolation" \
    "4x04 + Firewall" \
    "CONFIRMED" \
    "C2 becomes DENY"

echo
echo "* The malicious association of 203.0.113.47 is confirmed by"
echo "  independent memory and firewall evidence. Its exact role as a"
echo "  fallback C2 remains PROBABLE."
echo

# ------------------------------------------------------------------
# Timeline contradictions
# ------------------------------------------------------------------

line
echo "TIMELINE CONTRADICTIONS AND RESOLUTIONS"
line
echo

cat <<'EOF'
[C1] Firewall vs PCAP / Wazuh timestamps

  Observation:
    Firewall connection timestamps are approximately four seconds
    ahead of corresponding PCAP / Wazuh observations.

  Explanation:
    The firewall timestamps the TCP SYN at policy-decision time.
    Host-side / capture sources timestamp packet or event receipt.

  Resolution:
    This is collection-point variance, not conflicting attacker
    activity.

  Authoritative source:
    Firewall timestamp for network connection initiation.

  Status:
    RESOLVED


[C2] 4x01 reports zero lateral movement; 4x04/IR finds lateral movement

  4x01:
    No lateral movement observed during its 48-hour PCAP window.

  4x04 / IR:
    Lateral movement begins in May.

  Explanation:
    The 4x01 PCAP covered 2026-04-14 through 2026-04-16 and lacked
    routed VLAN-3 -> VLAN-20 visibility.

    The Stage-4 activity occurred weeks later.

  Resolution:
    There is no factual contradiction.

    "Not observed" in 4x01 must NOT be interpreted as
    "did not occur later."

  Status:
    RESOLVED - temporal + collection visibility gap.


[C3] 4x03 scheduled-task capability vs 4x05 scheduled-task evidence

  4x03:
    PersistViaTask capability existed in the malware but was marked
    NOT EXERCISED during malware triage.

  4x05 Memory:
    TaskCache contains:
      \HealthSync Update Service

  4x05 Disk:
    Full Scheduled Task XML recovered.

  Explanation:
    4x03 correctly described what was observed at the time of the
    malware analysis. Later attacker activity activated persistence.

  Resolution:
    T1053.005 is now CONFIRMED at MedDefense.

  Status:
    UPGRADED, not an analytical error.


[C4] 4x03 exfiltration capability vs 4x05 actual exfiltration

  4x03:
    Exfiltration functionality existed in the malware but successful
    MedDefense data theft was not yet confirmed.

  4x05 Disk:
    Patient and insurance data were collected, archived and staged.

  4x05 Firewall:
    Outbound byte counts match staged artifacts exactly.

  Resolution:
    Capability has become observed execution.

    T1005, T1074.001, T1560.001 and T1041 are now supported by
    incident evidence.

  Status:
    UPGRADED.


[C5] T1550.002 Pass-the-Hash interpretation

  4x04:
    NTLM use by svc_healthsync following LSASS dumping was mapped
    to T1550.002 Pass-the-Hash.

  Supporting evidence:
    - LSASS dumped before lateral movement.
    - svc_healthsync appears in recovered credential material.
    - svc_healthsync performs unauthorized NTLM authentication.
    - Remote administration follows.

  Limitation:
    NTLM authentication alone does not independently prove that a
    stolen NTLM hash, rather than another credential representation,
    was supplied.

  Resolution:
    Preserve the 4x04 mapping as strongly supported / observed in
    the project evidence, but explicitly document the forensic
    limitation.

  Confidence:
    PROBABLE-to-HIGH for exact Pass-the-Hash mechanism;
    CONFIRMED for credential theft and service-account abuse.
EOF

echo

# ------------------------------------------------------------------
# Technique correlation
# ------------------------------------------------------------------

line
echo "ATT&CK TECHNIQUE CORRELATION"
line
echo

printf "%-11s %-31s %-12s %-20s %s\n" \
    "Technique" "Description" "4x02/4x04" "4x05 Evidence" "Update"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1566.001" "Spearphishing Link" "OBSERVED" "4x00/4x01" "CONFIRMED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1071.001" "Web Protocols" "OBSERVED" "4x01/MEM/FW" "CONFIDENCE +"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1547.001" "Registry Run Keys" "OBSERVED" "4x03/MEM/DISK" "CONFIDENCE +"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1003.001" "LSASS Memory" "4x04 OBS" "4x04/MEM/DISK" "CONFIRMED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1021.002" "SMB/Admin Shares" "4x04 OBS" "4x04/DISK/FW" "CONFIRMED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1047" "WMI" "4x04 OBS" "4x04/DISK/FW" "CONFIRMED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1021.006" "PowerShell Remoting" "4x04 OBS" "4x04/DISK/FW" "CONFIRMED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1078.002" "Domain Account" "4x04 OBS" "4x04/MEM/DISK" "CONFIRMED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1550.002" "Pass-the-Hash" "4x04 OBS" "LSASS+NTLM context" "QUALIFIED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1053.005" "Scheduled Task" "NOT OBS" "MEM + DISK" "NEW CONFIRMED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1562.001" "Impair Defenses" "NOT OBS" "MEM + DISK" "NEW CONFIRMED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1074.001" "Local Data Staging" "NOT OBS" "DISK + FW" "NEW CONFIRMED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1560.001" "Archive Collected Data" "NOT OBS" "DISK + FW" "NEW CONFIRMED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1070.001" "Clear Windows Logs" "NOT OBS" "MEM + DISK" "NEW CONFIRMED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1070.004" "File Deletion" "NOT OBS" "DISK" "PROBABLE/OBS"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1005" "Data from Local System" "CAPABILITY" "MEM/DISK/FW" "UPGRADED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1041" "Exfiltration Over C2" "CAPABILITY" "DISK + FW" "UPGRADED"

printf "%-11s %-31s %-12s %-20s %s\n" \
    "T1571" "Non-Standard Port" "NOT OBS" "MEM + FW" "NEW / PROBABLE"

echo

# ------------------------------------------------------------------
# Technique upgrades
# ------------------------------------------------------------------

echo "TECHNIQUE UPGRADES / CORRECTIONS:"
echo

cat <<'EOF'
  UPGRADED / independently confirmed:
    T1003.001  LSASS Memory
    T1021.002  SMB / Windows Admin Shares
    T1021.006  PowerShell Remoting
    T1047      WMI
    T1078.002  Domain Account
    T1005      Data from Local System
    T1041      Exfiltration Over C2 Channel

  NEW from 4x05 IR:
    T1053.005  Scheduled Task/Job
    T1562.001  Impair Defenses
    T1074.001  Local Data Staging
    T1560.001  Archive Collected Data
    T1070.001  Clear Windows Event Logs
    T1070.004  File Deletion
    T1571      Non-Standard Port

  QUALIFIED:
    T1550.002  Pass-the-Hash

    The overall credential-theft / NTLM-abuse chain is strongly
    supported, but exact hash reuse is not independently demonstrated
    by the NTLM event alone.
EOF

echo

# ------------------------------------------------------------------
# Evidence convergence
# ------------------------------------------------------------------

line
echo "STRONGEST CROSS-EVIDENCE CONVERGENCES"
line
echo

cat <<'EOF'
[CV-1] Primary HEALTHBANE C2

  4x01:
    Network fingerprint / 5-minute beaconing.

  4x03:
    Malware contains HEALTHBANE C2 behavior.

  Memory:
    Live malicious process / C2 evidence.

  Firewall:
    3,958 C2 sessions across the IR window.

  Confidence:
    CONFIRMED


[CV-2] Credential theft

  4x04:
    Sysmon LSASS access by debug_tool.exe.

  Memory:
    Residual LSASS handle evidence.

  Disk:
    debug_tool.exe execution + out.dat dump material.
    svc_healthsync strings recovered.

  Confidence:
    CONFIRMED


[CV-3] Lateral movement

  4x04:
    PsExec + WMI + PSRemoting + unauthorized svc_healthsync.

  Disk:
    Prefetch / filesystem execution artifacts.

  Firewall:
    SMB/RPC/WinRM cross-VLAN sessions.

  Confidence:
    CONFIRMED


[CV-4] Scheduled-task persistence

  Memory:
    TaskCache registry entry.

  Disk:
    Full scheduled-task XML + schtasks/prefetch evidence.

  Confidence:
    CONFIRMED


[CV-5] Patient-data exfiltration

  Disk:
    staging_export_001.zip = 14,219,484 bytes.
    Contains 47,138 patient records.

  Firewall:
    14,219,484 bytes outbound to known C2.

  Confidence:
    CONFIRMED


[CV-6] Insurance-data exfiltration

  Disk:
    staging_export_002.zip = 11,802,944 bytes.
    Contains 51,002 insurance/member records.

  Firewall:
    11,802,944 bytes outbound to known C2.

  Confidence:
    CONFIRMED


[CV-7] Anti-forensics

  Memory:
    clear_logs:true residual configuration.

  Disk:
    Security.evtx deletion/recreation + 12-minute log gap.

  Confidence:
    CONFIRMED


[CV-8] Secondary attacker infrastructure

  Memory:
    Live connection to 203.0.113.47:8443.

  Firewall:
    14 sessions across nine days.

  Confidence:
    CONFIRMED malicious association.
    PROBABLE secondary/fallback C2 role.
EOF

echo

# ------------------------------------------------------------------
# Gaps
# ------------------------------------------------------------------

line
echo "REMAINING EVIDENCE GAPS"
line
echo

cat <<'EOF'
[G1] Other compromised workstations

  Known:
    WS-RECV-03 is the confirmed Stage-4 pivot.

  Unknown:
    Whether debug_tool.exe / PsExec64.exe were deployed to other
    workstations.

  Cause:
    COLLECTION LIMITATION.

    IR memory and disk acquisition covered WS-RECV-03 only.


[G2] Exact secondary-C2 delivery mechanism

  Known:
    203.0.113.47:8443 is maliciously associated.

  Unknown:
    Whether the IP was hardcoded dynamically, delivered as a C2
    directive, or introduced by another component.

  Cause:
    COLLECTION / CONTENT-VISIBILITY LIMITATION.

    Firewall metadata cannot show encrypted command contents.


[G3] Exact Pass-the-Hash mechanism

  Known:
    LSASS dump occurred.
    svc_healthsync material was present.
    Unauthorized NTLM authentication followed.

  Unknown:
    Exact credential representation supplied during authentication.

  Cause:
    FORENSIC VISIBILITY LIMITATION.


[G4] Complete scope beyond WS-RECV-03

  Known:
    HEALTH-DB, INS-DB and DC-01 were reached.

  Unknown:
    Whether persistence or attacker tooling remains on those servers.

  Cause:
    COLLECTION LIMITATION.

    Endpoint forensic acquisition is currently limited to WS-RECV-03.


[G5] Full contents of every encrypted C2 exchange

  Known:
    Timing, destination and byte counts.

  Unknown:
    Exact commands/content for every encrypted session.

  Cause:
    ENCRYPTION / COLLECTION LIMITATION.
EOF

echo

# ------------------------------------------------------------------
# Final synthesis
# ------------------------------------------------------------------

line
echo "CORRELATION ASSESSMENT"
line
echo

cat <<'EOF'
The evidence landscape no longer supports five isolated investigation
stories. It supports one continuous HEALTHBANE intrusion.

The strongest reconstruction is:

  Phishing / credential harvesting
            |
            v
  HEALTHBANE RAT deployment
            |
            v
  Persistent C2
            |
            v
  Defender impairment
            |
            v
  LSASS credential dumping
            |
            v
  svc_healthsync compromise
            |
            v
  PsExec / WMI / PowerShell Remoting
            |
            +------> SRV-HEALTH-DB
            |
            +------> SRV-INS-DB
            |
            +------> SRV-DC-01
            |
            v
  Scheduled-task persistence
            |
            v
  Data collection
            |
            v
  Local staging + compression
            |
            v
  Exfiltration over known C2
            |
            v
  File deletion / event-log clearing

OVERALL RECONSTRUCTION CONFIDENCE:
  HIGH

Reason:
  The critical phases of the intrusion are supported by convergent
  evidence from independent domains including network, SIEM, memory,
  disk and firewall telemetry.

Most significant change from previous investigations:
  Data theft is no longer a hypothesis.

  Disk + firewall correlation demonstrates successful exfiltration
  of sensitive MedDefense data.
EOF

echo
line
echo "   Cross-evidence correlation complete."
line