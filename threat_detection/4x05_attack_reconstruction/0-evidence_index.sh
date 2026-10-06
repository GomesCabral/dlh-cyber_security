#!/bin/bash
#
# 4x05 - Attack Reconstruction
# Task 0 - Evidence Inventory
#
# Purpose:
#   Catalog all reconstruction evidence, document reliability and
#   temporal/domain coverage, and identify evidence gaps that constrain
#   the HEALTHBANE reconstruction.
#

set -euo pipefail

IR_DIR="ir_evidence"
PREV_DIR="previous_findings"
REF_DIR="reference"

REQUIRED_FILES=(
    "$IR_DIR/disk_forensics_report.txt"
    "$IR_DIR/firewall_sessions_ws_recv_03.json"
    "$IR_DIR/ir_team_notes.txt"
    "$IR_DIR/memory_artifacts.txt"
    "$PREV_DIR/4x00_phishing_summary.txt"
    "$PREV_DIR/4x01_network_timeline.txt"
    "$PREV_DIR/4x02_attack_mapping.json"
    "$PREV_DIR/4x03_malware_summary.txt"
    "$PREV_DIR/4x04_hunting_report.txt"
    "$REF_DIR/attck_navigator_80pct.json"
    "$REF_DIR/healthbane_ioc_master.json"
    "$REF_DIR/meddefense_asset_inventory.txt"
    "$REF_DIR/network_topology.txt"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Required evidence source not found: $file" >&2
        exit 1
    fi
done

for cmd in jq grep sort uniq wc date; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $cmd" >&2
        exit 1
    fi
done

HOST_NAME="$(hostname)"
RUN_DATE="$(date '+%Y-%m-%d')"

FW_START="$(
    jq -r '.metadata.time_range_utc.start // "UNKNOWN"' \
        "$IR_DIR/firewall_sessions_ws_recv_03.json"
)"

FW_END="$(
    jq -r '.metadata.time_range_utc.end // "UNKNOWN"' \
        "$IR_DIR/firewall_sessions_ws_recv_03.json"
)"

FW_SESSIONS="$(
    jq -r '.metadata.session_count_in_export // "UNKNOWN"' \
        "$IR_DIR/firewall_sessions_ws_recv_03.json"
)"

IOC_COUNT="$(
    jq '[.iocs[]?] | length' \
        "$REF_DIR/healthbane_ioc_master.json"
)"

ATTACK_OBSERVED="$(
    jq '[.techniques[]? | select(.score == 3)] | length' \
        "$REF_DIR/attck_navigator_80pct.json"
)"

ATTACK_INFERRED="$(
    jq '[.techniques[]? | select(.score == 2)] | length' \
        "$REF_DIR/attck_navigator_80pct.json"
)"

ATTACK_UNCOVERED="$(
    jq '[.techniques[]? | select((.score // 0) == 0)] | length' \
        "$REF_DIR/attck_navigator_80pct.json"
)"

echo "================================================================"
echo "   EVIDENCE INVENTORY - HEALTHBANE Reconstruction"
echo "   Analyst: $HOST_NAME    Date: $RUN_DATE"
echo "================================================================"
echo

echo "SOURCE CATALOG:"
echo

cat <<'EOF'
  [01] 4x00_phishing_summary.txt
       Phase: 4x00 (Phishing Dissection)
       Type: Email analysis findings
       Coverage: 2026-04-14 through 2026-04-21
       Reliability: MEDIUM
                    Derived investigation summary; original email,
                    header and sandbox evidence is not in this package.
       Key content:
         - HEALTHBANE phishing campaign
         - 8 emails analyzed; 3 confirmed malicious
         - Credential harvesting
         - Diane Marsh / WS-RECV-03 initial victim context
         - Campaign domains and email IOCs

  [02] 4x01_network_timeline.txt
       Phase: 4x01 (Network Forensics)
       Type: Network / PCAP-derived findings
       Coverage: Investigation 2026-04-15 through 2026-04-22
                 Raw PCAP window 2026-04-14T00:00Z to
                 2026-04-16T00:00Z
       Reliability: MEDIUM
                    Derived timeline; original PCAPs are not included.
       Key content:
         - Phishing click network sequence
         - C2 beaconing
         - HEALTHBANE network IOCs
         - DNS exfiltration capability
         - 48-hour packet-capture visibility

  [03] 4x02_attack_mapping.json
       Phase: 4x02 (Threat Intelligence)
       Type: Intelligence / ATT&CK mapping
       Coverage: Campaign knowledge accumulated through 4x02
       Reliability: MEDIUM
                    Analytical mapping combining prior evidence and
                    external campaign intelligence.
       Key content:
         - HEALTHBANE ATT&CK techniques
         - OBSERVED / INFERRED / NOT COVERED classifications
         - Pre-malware and pre-hunt ATT&CK baseline

  [04] 4x03_malware_summary.txt
       Phase: 4x03 (Malware Triage)
       Type: Malware analysis findings
       Coverage: 2026-04-22 through 2026-05-02
       Reliability: MEDIUM
                    Consolidated findings; original sandbox, IDA and
                    working artifacts are outside this package.
       Key content:
         - HEALTHBANE dropper
         - svchost_update.exe RAT
         - sync_healthdata.ps1 exfiltrator
         - C2 and persistence capabilities
         - Behavioral IOCs

  [05] 4x04_hunting_report.txt
       Phase: 4x04 (Threat Hunting)
       Type: SIEM / endpoint telemetry findings
       Coverage: 2026-05-04 through 2026-05-18
       Reliability: MEDIUM
                    Derived hunt report based on Wazuh and Sysmon;
                    raw SIEM datasets are not included here.
       Key content:
         - LSASS credential-access activity
         - PsExec lateral movement
         - WMI activity
         - PowerShell Remoting
         - svc_healthsync misuse
         - Stage 4 lateral movement findings

  [06] memory_artifacts.txt
       Phase: 4x05-IR (Incident Response)
       Type: Volatile memory forensics
       Coverage: Point-in-time capture:
                 2026-05-15 14:18:42 CDT / 19:18:42 UTC
       Reliability: HIGH
                    Primary host evidence acquired under IR chain
                    of custody and peer reviewed.
       Key content:
         - Running processes
         - Active network connections
         - Registry artifacts
         - Malware traces
         - Credential-access traces
         - Persistence artifacts
         - Unknown / secondary C2 evidence

  [07] disk_forensics_report.txt
       Phase: 4x05-IR (Incident Response)
       Type: Disk forensics
       Coverage: NTFS/USN history through acquisition on
                 2026-05-15 19:45 CDT
       Reliability: HIGH
                    Primary forensic image findings with verified
                    E01 acquisition and chain of custody.
       Key content:
         - Scheduled-task persistence
         - Run-key persistence
         - Deleted staging archives
         - Prefetch execution evidence
         - LSASS dumper artifacts
         - Anti-forensics
         - Collection / staging evidence

  [08] firewall_sessions_ws_recv_03.json
       Phase: 4x05-IR (Incident Response)
       Type: Firewall / network session telemetry
EOF

printf '       Coverage: %s through %s\n' "$FW_START" "$FW_END"

cat <<EOF
       Reliability: HIGH
                    Primary firewall session evidence exported from
                    the network security device.
       Key content:
         - $FW_SESSIONS selected sessions in supplied IR export
         - Known HEALTHBANE C2
         - Cross-VLAN server connections
         - Exfiltration-related sessions
         - New 203.0.113.47:8443 secondary-C2 hypothesis

  [09] ir_team_notes.txt
       Phase: 4x05-IR (Incident Response)
       Type: Preliminary analyst observations
       Coverage: 2026-05-15 through 2026-05-18
       Reliability: LOW
                    Working notes contain HIGH, MED, LOW, DISPUTED
                    and TODO observations and require validation.
       Key content:
         - Isolation actions
         - Initial memory/disk observations
         - Secondary C2 hypothesis
         - Exfiltration estimates
         - Open investigative questions

  [10] healthbane_ioc_master.json
       Phase: Reference (4x00-4x04 consolidated)
       Type: IOC intelligence database
       Coverage: HEALTHBANE evidence accumulated through 2026-05-18
       Reliability: MEDIUM
                    Consolidated reference derived from previous
                    investigations.
       Key content:
         - $IOC_COUNT IOC records
         - Domains, IPs, hashes and behavioral indicators
         - Known IOC confidence and source attribution

  [11] attck_navigator_80pct.json
       Phase: Reference (post-4x04)
       Type: ATT&CK coverage baseline
       Coverage: Detection/hunt knowledge through 4x04
       Reliability: MEDIUM
                    Analytical ATT&CK layer derived from previous work.
       Key content:
         - Observed techniques: $ATTACK_OBSERVED
         - Inferred techniques: $ATTACK_INFERRED
         - Uncovered techniques: $ATTACK_UNCOVERED
         - Post-hunt observed coverage baseline: 80%

  [12] meddefense_asset_inventory.txt
       Phase: Reference
       Type: Asset / data sensitivity reference
       Coverage: Effective 2026-04-01
       Reliability: HIGH
                    Authoritative organizational asset inventory.
       Key content:
         - Host roles
         - PHI / PII / financial-data classification
         - Criticality
         - Compromise impact

  [13] network_topology.txt
       Phase: Reference
       Type: Network topology / authorization reference
       Coverage: Effective 2026-05-01
       Reliability: HIGH
                    Authoritative network and host relationship
                    reference.
       Key content:
         - VLANs and network segments
         - Host/IP mapping
         - Server roles
         - Authorized relationships
EOF

echo
echo "TEMPORAL COVERAGE MATRIX:"
echo
cat <<'EOF'
  Period             EMAIL  PCAP  MALWARE  SIEM  FIREWALL  MEMORY  DISK
  ----------------------------------------------------------------------
  Apr 14-15           [X]    [X]     [-]     [-]     [-]      [-]    [~]
  Apr 16-21           [X]    [-]     [-]     [-]     [-]      [-]    [~]
  Apr 22-May 02       [-]    [-]     [X]     [-]     [~]      [-]    [X]
  May 03              [-]    [-]     [-]     [-]     [X]      [-]    [X]
  May 04-May 14       [-]    [-]     [-]     [X]     [X]      [-]    [X]
  May 15              [-]    [-]     [-]     [X]     [X]      [X]    [X]
  May 16-18           [-]    [-]     [-]     [X]     [-]      [-]    [-]

  Legend:
    [X] direct/defined coverage
    [~] artifact history may provide retrospective evidence
    [-] no direct coverage from that evidence type
EOF

echo
echo "EVIDENCE GAPS:"
echo
cat <<'EOF'
  [G1] NETWORK COLLECTION GAP
       Full-packet PCAP evidence ends on 2026-04-16.
       Later network behavior must therefore be reconstructed from
       firewall/SIEM/host artifacts rather than continuous PCAP.

  [G2] ENDPOINT TELEMETRY GAP
       The 4x04 SIEM hunt covers 2026-05-04 onward.
       Earlier endpoint behavior cannot be reconstructed from the
       supplied Wazuh/Sysmon hunt summary alone.

  [G3] HOST-SCOPE GAP
       Live memory and full disk forensic evidence are available only
       for WS-RECV-03. Reached servers do not have equivalent memory
       or disk images in this reconstruction package.

  [G4] FIREWALL-SCOPE GAP
       The supplied firewall file is an abridged export centered on
       WS-RECV-03. It is not the complete enterprise firewall dataset.

  [G5] EXFILTRATION CERTAINTY GAP
       Disk artifacts can establish collection and staging, but disk
       evidence alone cannot prove that staged data crossed the
       network boundary. Network evidence must be correlated.

  [G6] SECONDARY-C2 ATTRIBUTION GAP
       203.0.113.47:8443 is new relative to the pre-4x05 IOC baseline.
       It must be correlated with memory, firewall timing and process
       evidence before campaign attribution is considered confirmed.

  [G7] PREVIOUS-FINDINGS PROVENANCE GAP
       The 4x00-4x04 files are consolidated summaries. They preserve
       findings but not all underlying raw evidence in this package.

  [G8] IR-NOTES RELIABILITY GAP
       ir_team_notes.txt contains preliminary, disputed and unverified
       observations. No claim from this file should become a final
       reconstruction finding without independent validation.
EOF

echo
echo "DOMAIN COVERAGE:"
echo
cat <<'EOF'
  Initial Access:
    Sources: 4x00 + 4x01
    Status: MULTI-SOURCE

  Execution / Malware:
    Sources: 4x01 + 4x03 + memory + disk
    Status: MULTI-SOURCE

  Command and Control:
    Sources: 4x01 + 4x03 + firewall + memory
    Status: MULTI-SOURCE

  Credential Access:
    Sources: 4x04 + memory + disk
    Status: MULTI-SOURCE

  Lateral Movement:
    Sources: 4x04 + firewall + disk
    Status: MULTI-SOURCE

  Persistence:
    Sources: memory + disk
    Status: MULTI-SOURCE

  Collection / Staging:
    Sources: disk + memory context
    Status: MULTI-SOURCE, but transmission requires network correlation

  Exfiltration:
    Sources: 4x01 capability + firewall + disk staging
    Status: REQUIRES CORRELATION before final confidence assignment

  Impact:
    Sources: asset inventory + reconstructed access/staging evidence
    Status: REQUIRES FINAL RECONSTRUCTION
EOF

echo
echo "CRITICAL QUESTIONS FOR RECONSTRUCTION:"
echo
cat <<'EOF'
  [Q1] What is the complete chronological chain from Diane Marsh's
       phishing interaction to compromise of WS-RECV-03?

  [Q2] Which events connect credential theft on WS-RECV-03 to
       svc_healthsync abuse and lateral movement?

  [Q3] Which database and infrastructure servers were actually reached,
       and what actions occurred on each target?

  [Q4] Does firewall evidence confirm or contradict the timing reported
       by the 4x01 network timeline and the 4x04 SIEM hunt?

  [Q5] Is 203.0.113.47:8443 a HEALTHBANE secondary C2 channel or
       unrelated network traffic?

  [Q6] What persistence mechanisms existed on WS-RECV-03, when were
       they established, and why were they not detected earlier?

  [Q7] What data was collected and staged from SRV-HEALTH-DB or other
       sensitive systems?

  [Q8] Is there sufficient evidence to prove that patient data was
       exfiltrated, rather than only collected and staged?

  [Q9] Are timeline disagreements caused by UTC/CDT conversion,
       collection timing, clock skew or genuine evidence conflict?

  [Q10] Which findings can be classified CONFIRMED through two
        independent evidence sources, and which remain PROBABLE or
        POSSIBLE?

  [Q11] Which new IOCs discovered by IR are absent from the existing
        HEALTHBANE IOC master database?

  [Q12] Which ATT&CK techniques become newly OBSERVED after integrating
        memory, disk and firewall evidence?

  [Q13] Which attack phases still have insufficient visibility after
        all available evidence has been correlated?
EOF

echo
echo "RECONSTRUCTION CONFIDENCE STANDARD:"
echo
cat <<'EOF'
  CONFIRMED:
    Direct evidence from at least two independent sources.

  PROBABLE:
    Strong evidence from one source with supporting context.

  POSSIBLE:
    Technique logic supports the hypothesis, but direct evidence is
    limited or ambiguous.

  RULE:
    Absence of evidence will not automatically be treated as evidence
    of absence. Collection limitations must be documented separately.
EOF

echo
echo "================================================================"
echo "   Evidence inventory complete."
echo "================================================================"