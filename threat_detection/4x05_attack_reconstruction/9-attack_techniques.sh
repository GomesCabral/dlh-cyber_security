#!/bin/bash
#
# 4x05 - Attack Reconstruction
# Task 9 - Final ATT&CK Technique Identification
#
# Re-assesses the post-4x04 ATT&CK baseline against the complete
# 4x05 evidence set.
#

set -euo pipefail

BASELINE="reference/attck_navigator_80pct.json"

PHISH="previous_findings/4x00_phishing_summary.txt"
NETWORK="previous_findings/4x01_network_timeline.txt"
MAPPING="previous_findings/4x02_attack_mapping.json"
MALWARE="previous_findings/4x03_malware_summary.txt"
HUNT="previous_findings/4x04_hunting_report.txt"

MEMORY="ir_evidence/memory_artifacts.txt"
DISK="ir_evidence/disk_forensics_report.txt"
FIREWALL="ir_evidence/firewall_sessions_ws_recv_03.json"

FILES=(
    "$BASELINE"
    "$PHISH"
    "$NETWORK"
    "$MAPPING"
    "$MALWARE"
    "$HUNT"
    "$MEMORY"
    "$DISK"
    "$FIREWALL"
)

for file in "${FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Missing required source: $file" >&2
        exit 1
    fi
done

for cmd in jq awk; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command missing: $cmd" >&2
        exit 1
    fi
done

line() {
    printf '%*s\n' 78 '' | tr ' ' '='
}

# ------------------------------------------------------------------
# Baseline values - read dynamically from Navigator
# ------------------------------------------------------------------

THREAT_TOTAL="$(
    jq -r '.technique_count_summary.total_in_threat_model' "$BASELINE"
)"

BASE_OBSERVED="$(
    jq -r '.technique_count_summary.observed' "$BASELINE"
)"

BASE_INFERRED="$(
    jq -r '.technique_count_summary.inferred' "$BASELINE"
)"

BASE_NOT_COVERED="$(
    jq -r '.technique_count_summary.not_covered' "$BASELINE"
)"

BASE_PERCENT="$(
    jq -r '.technique_count_summary.percent_observed' "$BASELINE"
)"

ACTUAL_TECHNIQUES="$(
    jq '[.techniques[].techniqueID] | unique | length' "$BASELINE"
)"

if [[ "$THREAT_TOTAL" -ne "$ACTUAL_TECHNIQUES" ]]; then
    echo "ERROR: Baseline threat-model count does not match technique array." >&2
    exit 1
fi

# ------------------------------------------------------------------
# Verify the open 4x05 hypotheses actually exist in baseline
# ------------------------------------------------------------------

for tid in T1053.005 T1074.001 T1560.001 T1070.001 T1005; do
    if ! jq -e --arg tid "$tid" \
        '.techniques[] | select(.techniqueID == $tid)' \
        "$BASELINE" >/dev/null; then

        echo "ERROR: Expected baseline technique missing: $tid" >&2
        exit 1
    fi
done

# ------------------------------------------------------------------
# Final assessment
#
# 27 CONFIRMED:
#   23 baseline OBSERVED
#   + T1041 upgraded from INFERRED
#   + T1005 upgraded from INFERRED
#   + T1053.005
#   + T1074.001
#   + T1560.001
#   + T1070.001
#   - T1550.002 downgraded to PROBABLE
#
# Remaining:
#   T1048.003 POSSIBLE
#   T1550.002 PROBABLE
# ------------------------------------------------------------------

FINAL_CONFIRMED=27
FINAL_PROBABLE=1
FINAL_POSSIBLE=1

FINAL_PERCENT="$(
    awk -v confirmed="$FINAL_CONFIRMED" -v total="$THREAT_TOTAL" \
        'BEGIN { printf "%.1f", (confirmed / total) * 100 }'
)"

FINAL_MAPPED_PERCENT="$(
    awk -v total="$THREAT_TOTAL" \
        'BEGIN { printf "%.1f", (total / total) * 100 }'
)"

# ------------------------------------------------------------------
# Header
# ------------------------------------------------------------------

line
echo "   HEALTHBANE ATT&CK TECHNIQUE INVENTORY (FINAL)"
echo "   Total techniques in threat model: $THREAT_TOTAL"
line
echo

echo "Baseline validation:"
echo "  Navigator techniques:     $ACTUAL_TECHNIQUES"
echo "  Post-4x04 confirmed:      $BASE_OBSERVED"
echo "  Post-4x04 inferred:       $BASE_INFERRED"
echo "  Post-4x04 not covered:    $BASE_NOT_COVERED"
echo "  Post-4x04 coverage:       ${BASE_PERCENT}%"
echo

line
echo "FINAL TECHNIQUE INVENTORY"
line
echo

cat <<'EOF'
#   Technique   Name / Tactic                         Conf       First     Status
--  ----------  ------------------------------------  ---------  --------  ---------

01  T1566.001   Spearphishing Attachment              CONFIRMED  4x00      UNCHANGED
                Tactic: Initial Access
                Evidence: 4x00, 4x01, 4x03
                HEALTHBANE_S2_invoice.docm /
                April-Invoice-MD2026.docm delivered to MedDefense.

02  T1566.002   Spearphishing Link                    CONFIRMED  4x00      UNCHANGED
                Tactic: Initial Access
                Evidence: 4x00, 4x01
                Diane followed meddefense-portal.com credential lure.

03  T1204.002   User Execution: Malicious File        CONFIRMED  4x03      UNCHANGED
                Tactic: Execution
                Evidence: 4x01, 4x03
                Malicious DOCM required user execution / macro path.

04  T1059.001   PowerShell                            CONFIRMED  4x03      UNCHANGED
                Tactic: Execution
                Evidence: 4x03, 4x04, IR-MEM, IR-DISK
                PowerShell used by malware, PSRemoting and scheduled task.

05  T1059.005   Visual Basic                          CONFIRMED  4x03      UNCHANGED
                Tactic: Execution
                Evidence: 4x03
                AutoOpen / Document_Open VBA handlers confirmed.

06  T1547.001   Registry Run Keys / Startup Folder    CONFIRMED  4x03      UNCHANGED
                Tactic: Persistence
                Evidence: 4x03, IR-MEM, IR-DISK
                HKCU\...\Run\HealthSync persistence confirmed.

07  T1071.001   Web Protocols                         CONFIRMED  4x01      UNCHANGED
                Tactic: Command and Control
                Evidence: 4x01, 4x03, IR-MEM, IR-FW
                HTTPS C2 to HEALTHBANE infrastructure.

08  T1071.004   DNS                                   CONFIRMED  4x01      UNCHANGED
                Tactic: Command and Control
                Evidence: 4x01, 4x03
                DNS TXT/test channel and DNS-capable exfiltrator observed.
                Note: DNS communication is confirmed; high-volume DNS
                exfiltration is NOT independently confirmed.

09  T1573.001   Encrypted Channel                     CONFIRMED  4x01      UNCHANGED
                Tactic: Command and Control
                Evidence: 4x01, 4x03
                RAT implements RC4-like payload wrapping before TLS.

10  T1027       Obfuscated/Compressed Files           CONFIRMED  4x03      UNCHANGED
                Tactic: Defense Evasion
                Evidence: 4x03
                Base64 + XOR obfuscation confirmed.

11  T1027.010   Command Obfuscation                   CONFIRMED  4x03      UNCHANGED
                Tactic: Defense Evasion
                Evidence: 4x03, IR-MEM, IR-DISK
                PowerShell -EncodedCommand execution confirmed.

12  T1140       Deobfuscate/Decode Files              CONFIRMED  4x03      UNCHANGED
                Tactic: Defense Evasion
                Evidence: 4x03
                Embedded payload decoded at runtime.

13  T1105       Ingress Tool Transfer                 CONFIRMED  4x01      UNCHANGED
                Tactic: Command and Control
                Evidence: 4x01, 4x03
                svchost_update.exe downloaded from HEALTHBANE C2.

14  T1041       Exfiltration Over C2 Channel          CONFIRMED  4x03      UPGRADED
                Tactic: Exfiltration
                Evidence: 4x03 capability + IR-DISK + IR-FW
                Baseline: INFERRED
                Final: staged artifact sizes correlate with outbound
                suspicious/C2 transfer evidence.

15  T1048.003   Exfiltration Over Unencrypted/
                Alternative Protocol: DNS             POSSIBLE   4x01      UNCHANGED*
                Tactic: Exfiltration
                Evidence: 4x01 test pings + 4x03 capability
                Baseline: INFERRED
                Final: POSSIBLE
                No supplied evidence proves high-volume DNS exfiltration
                of the recovered MedDefense staging files.

16  T1005       Data from Local System                CONFIRMED  4x03      UPGRADED
                Tactic: Collection
                Evidence: IR-DISK + Stage-4 reconstruction
                Baseline: INFERRED
                Final: recovered patient, insurance and AD query output
                proves collection occurred.

17  T1583.001   Acquire Infrastructure: Domains       CONFIRMED  4x00      UNCHANGED
                Tactic: Resource Development
                Evidence: 4x00 WHOIS / domain analysis
                Attacker-controlled lookalike infrastructure confirmed.

18  T1003.001   LSASS Memory                          CONFIRMED  4x04      UNCHANGED
                Tactic: Credential Access
                Evidence: 4x04, IR-MEM, IR-DISK
                debug_tool.exe accessed LSASS; out.dat recovered.

19  T1021.002   SMB / Windows Admin Shares            CONFIRMED  4x04      UNCHANGED
                Tactic: Lateral Movement
                Evidence: 4x04, IR-DISK, IR-FW
                PsExec pivots from WS-RECV-03 confirmed.

20  T1021.006   Windows Remote Management             CONFIRMED  4x04      UNCHANGED
                Tactic: Lateral Movement
                Evidence: 4x04, IR-DISK, IR-FW
                PowerShell Remoting / Enter-PSSession confirmed.

21  T1047       Windows Management Instrumentation    CONFIRMED  4x04      UNCHANGED
                Tactic: Execution / Lateral Movement
                Evidence: 4x04, IR-DISK, IR-FW
                WMI used against Stage-4 targets.

22  T1078       Valid Accounts                        CONFIRMED  4x00      UNCHANGED
                Tactic: Defense Evasion
                Evidence: 4x00, 4x04, IR evidence
                Credential harvesting and later credential abuse observed.

23  T1078.002   Domain Accounts                       CONFIRMED  4x04      UNCHANGED
                Tactic: Defense Evasion
                Evidence: 4x04, IR-FW, IR-DISK
                svc_healthsync used outside its authorization model.

24  T1550.002   Pass the Hash                         PROBABLE   4x04      CORRECTED
                Tactic: Lateral Movement
                Evidence: 4x04 + credential-dump correlation
                Baseline: OBSERVED
                Final: PROBABLE
                NTLM use of svc_healthsync after LSASS dumping is highly
                consistent with Pass-the-Hash, but NTLM alone does not
                prove the exact credential-reuse mechanism.

25  T1112       Modify Registry                       CONFIRMED  4x03      UNCHANGED
                Tactic: Defense Evasion
                Evidence: 4x03, 4x04, IR registry evidence
                Registry modifications associated with persistence and
                service activity confirmed.

26  T1053.005   Scheduled Task/Job: Scheduled Task    CONFIRMED  4x05-IR   UPGRADED
                Tactic: Persistence
                Evidence: IR-MEM + IR-DISK
                Baseline: NOT COVERED
                HealthSync Update Service task confirmed independently
                in memory TaskCache and on-disk task XML.

27  T1074.001   Local Data Staging                    CONFIRMED  4x05-IR   UPGRADED
                Tactic: Collection
                Evidence: IR-DISK + network correlation
                Baseline: NOT COVERED
                Data staged under C:\Users\Public\Tmp\.

28  T1560.001   Archive Collected Data                CONFIRMED  4x05-IR   UPGRADED
                Tactic: Collection
                Evidence: IR-DISK + 4x03 malware capability
                Baseline: NOT COVERED
                staging_export_001.zip and staging_export_002.zip
                recovered from deleted disk artifacts.

29  T1070.001   Clear Windows Event Logs              CONFIRMED  4x05-IR   UPGRADED
                Tactic: Defense Evasion
                Evidence: IR-DISK + IR-MEM configuration
                Baseline: NOT COVERED
                Security.evtx deleted/recreated and clear_logs:true
                configuration recovered.
EOF

echo

# ------------------------------------------------------------------
# Coverage
# ------------------------------------------------------------------

line
echo "COVERAGE EVOLUTION"
line
echo

cat <<EOF
Post-4x02 - Intelligence:
  11 / 29 directly OBSERVED = 38%
  16 / 29 OBSERVED + INFERRED = 55%

Post-4x03 - Malware analysis:
  approximately 55% direct coverage

Post-4x04 - Threat hunting:
  23 / 29 = ${BASE_PERCENT}% confirmed/observed

Post-4x05 - Reconstruction:
  $FINAL_CONFIRMED / $THREAT_TOTAL = ${FINAL_PERCENT}% CONFIRMED
  $FINAL_PROBABLE / $THREAT_TOTAL = PROBABLE
  $FINAL_POSSIBLE / $THREAT_TOTAL = POSSIBLE

Final mapped coverage:
  $THREAT_TOTAL / $THREAT_TOTAL = ${FINAL_MAPPED_PERCENT}%

Important:
  "Mapped" does NOT mean "confirmed".
EOF

echo

# ------------------------------------------------------------------
# Changes
# ------------------------------------------------------------------

line
echo "UPGRADED TECHNIQUES"
line
echo

cat <<'EOF'
T1041
  Exfiltration Over C2 Channel
  INFERRED -> CONFIRMED

  Before:
    Malware had an upload capability.

  New evidence:
    IR disk artifacts + firewall outbound transfer correlation.


T1005
  Data from Local System
  INFERRED -> CONFIRMED

  Before:
    Database access was known, but specific data reads were not.

  New evidence:
    Recovered patient, insurance and AD datasets.


T1053.005
  Scheduled Task
  NOT COVERED -> CONFIRMED

  New evidence:
    Memory TaskCache + disk task XML.


T1074.001
  Local Data Staging
  NOT COVERED -> CONFIRMED

  New evidence:
    Recovered files under C:\Users\Public\Tmp\.


T1560.001
  Archive Collected Data
  NOT COVERED -> CONFIRMED

  New evidence:
    staging_export_001.zip
    staging_export_002.zip


T1070.001
  Clear Windows Event Logs
  NOT COVERED -> CONFIRMED

  New evidence:
    Security.evtx deletion/recreation
    + clear_logs:true configuration.
EOF

echo

line
echo "CORRECTED / DOWNGRADED TECHNIQUES"
line
echo

cat <<'EOF'
T1550.002 - Pass the Hash

  Post-4x04:
    OBSERVED

  Final assessment:
    PROBABLE

  Reason:
    The sequence is strongly suspicious:

      LSASS dump
          ->
      svc_healthsync credential material
          ->
      NTLM authentication from WS-RECV-03
          ->
      lateral movement

    However, NTLM authentication alone does not demonstrate that
    the attacker supplied an NT hash rather than another reusable
    credential representation.

  Therefore:
    Credential abuse is CONFIRMED.
    Pass-the-Hash specifically is PROBABLE.


T1048.003 - DNS Exfiltration

  Post-4x04:
    INFERRED

  Final assessment:
    POSSIBLE

  Reason:
    DNS test traffic and malware capability exist, but the supplied
    MedDefense evidence does not demonstrate high-volume DNS transfer
    of the recovered sensitive-data archives.

  The confirmed exfiltration path is T1041 over the C2 channel.
EOF

echo

# ------------------------------------------------------------------
# New IR evidence
# ------------------------------------------------------------------

line
echo "TECHNIQUES FIRST CONFIRMED BY 4x05 IR"
line
echo

cat <<'EOF'
T1053.005  Scheduled Task
T1074.001  Local Data Staging
T1560.001  Archive Collected Data
T1070.001  Clear Windows Event Logs

Important:
  These are not new IDs outside the 29-technique threat model.

  They already existed in attck_navigator_80pct.json as open
  hypotheses with score 0.

  4x05 supplies the evidence required to CONFIRM them.
EOF

echo

# ------------------------------------------------------------------
# Additional behavior outside original 29
# ------------------------------------------------------------------

line
echo "ADDITIONAL RECONSTRUCTION TECHNIQUES"
line
echo

cat <<'EOF'
The IR evidence also supports behaviors useful for the final
reconstruction, but these should NOT silently change the denominator
of the established 29-technique HEALTHBANE threat model.

T1562.001
  Impair Defenses
  Evidence:
    Defender exclusion C:\Windows\Temp.
  Confidence:
    CONFIRMED - memory + disk.

T1070.004
  File Deletion
  Evidence:
    deleted staging ZIP/CSV/config/dump artifacts.
  Confidence:
    PROBABLE from disk evidence alone under the project's
    two-independent-source CONFIRMED standard.

T1571
  Non-Standard Port
  Evidence:
    203.0.113.47:8443 in memory + firewall.
  Confidence:
    CONFIRMED for communication on non-standard port;
    secondary-C2 role remains PROBABLE.

T1087.002
  Domain Account Discovery
  Evidence:
    Get-ADUser / recovered AD enumeration output.
  Confidence:
    CONFIRMED when correlated with Stage-4 evidence.

These can be added to an EXPANDED final Navigator layer if the
project requires the threat model itself to grow beyond the original
29 techniques.

They are intentionally excluded from the 29-technique coverage
percentage so that the denominator remains comparable with 4x02,
4x03 and 4x04.
EOF

echo

# ------------------------------------------------------------------
# Final gaps
# ------------------------------------------------------------------

line
echo "REMAINING UNCERTAINTY"
line
echo

cat <<'EOF'
There is no longer an evidence-visibility gap for the four open
4x05 hypotheses from the post-4x04 Navigator:

  T1053.005  -> CONFIRMED
  T1074.001  -> CONFIRMED
  T1560.001  -> CONFIRMED
  T1070.001  -> CONFIRMED

Two technique-level qualifications remain:

  T1048.003 DNS Exfiltration
    POSSIBLE
    Capability/test traffic exists, but bulk MedDefense DNS
    exfiltration is not demonstrated.

  T1550.002 Pass the Hash
    PROBABLE
    Strong behavioral correlation exists, but exact hash-based
    authentication mechanics are not directly proven.

Therefore:

  Confirmed coverage: 27/29 = 93.1%
  Analytically mapped: 29/29 = 100%

Do NOT report 100% confirmed coverage.
EOF

echo

line
echo "FINAL ASSESSMENT"
line
echo

cat <<EOF
Threat-model size:          $THREAT_TOTAL
CONFIRMED techniques:       $FINAL_CONFIRMED
PROBABLE techniques:        $FINAL_PROBABLE
POSSIBLE techniques:        $FINAL_POSSIBLE

Confirmed coverage:         ${FINAL_PERCENT}%
Mapped coverage:            ${FINAL_MAPPED_PERCENT}%

Overall result:
  The reconstruction closes every previous NOT-COVERED hypothesis,
  confirms actual collection, staging and C2 exfiltration, and
  corrects over-confidence around Pass-the-Hash.

  Final ATT&CK coverage should therefore be reported as:

      27 CONFIRMED / 1 PROBABLE / 1 POSSIBLE
      = 93.1% confirmed coverage

  rather than forcing the expected example's ~96% figure.
EOF

echo
line
echo "   Final ATT&CK technique assessment complete."
line