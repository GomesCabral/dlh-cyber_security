#!/bin/bash
#
# 4x05 - Attack Reconstruction
# Task 8 - Unified Timeline Assembly
#
# Builds one evidence-cited chronological timeline for the complete
# HEALTHBANE intrusion against MedDefense.
#

set -euo pipefail

T5="./5-stages_1_2.sh"
T6="./6-stage_3.sh"
T7="./7-stage_4.sh"

PHISH="previous_findings/4x00_phishing_summary.txt"
NETWORK="previous_findings/4x01_network_timeline.txt"
MALWARE="previous_findings/4x03_malware_summary.txt"
HUNT="previous_findings/4x04_hunting_report.txt"

MEMORY="ir_evidence/memory_artifacts.txt"
DISK="ir_evidence/disk_forensics_report.txt"
FIREWALL="ir_evidence/firewall_sessions_ws_recv_03.json"
IR_NOTES="ir_evidence/ir_team_notes.txt"

FILES=(
    "$PHISH"
    "$NETWORK"
    "$MALWARE"
    "$HUNT"
    "$MEMORY"
    "$DISK"
    "$FIREWALL"
    "$IR_NOTES"
)

for file in "${FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Missing required evidence source: $file" >&2
        exit 1
    fi
done

for cmd in jq date awk; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $cmd" >&2
        exit 1
    fi
done

line() {
    printf '%*s\n' 78 '' | tr ' ' '='
}

# ------------------------------------------------------------------
# Read T5-T7 outputs when available.
# They are used as reconstruction inputs, while primary evidence
# remains authoritative for timestamps.
# ------------------------------------------------------------------

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

for stage in 5 6 7; do
    script_var="T${stage}"
    script="${!script_var}"

    if [[ -x "$script" ]]; then
        "$script" > "$TMP_DIR/t${stage}.txt" 2>/dev/null || true
    else
        : > "$TMP_DIR/t${stage}.txt"
    fi
done

# ------------------------------------------------------------------
# Temporal anchors
# UTC used for calculations.
# CDT = UTC-5 during this incident.
# ------------------------------------------------------------------

FIRST_ACCESS="2026-04-14T13:14:22Z"
CRED_EXPOSURE="2026-04-14T13:18:42Z"
SECOND_WAVE="2026-04-15T08:43:18Z"
FIRST_C2="2026-04-15T08:51:38Z"

RUN_KEY="2026-04-22T06:14:47Z"

DEFENDER="2026-05-04T23:11:08Z"
LSASS1="2026-05-05T08:22:14Z"
LATERAL1="2026-05-06T07:11:42Z"
TASK_CREATE="2026-05-07T06:47:33Z"
STAGING1="2026-05-08T07:36:34Z"
LATERAL2="2026-05-09T07:46:11Z"
LOG_CLEAR="2026-05-09T08:01:42Z"
STAGING2="2026-05-11T08:15:09Z"
LSASS2="2026-05-12T07:45:01Z"
LATERAL3="2026-05-13T07:08:56Z"
AD_STAGE="2026-05-13T07:31:18Z"

LAST_TASK="2026-05-15T07:00:14Z"
CONTAINMENT="2026-05-15T18:42:00Z"
MEM_CAPTURE="2026-05-15T19:18:42Z"
DISK_IMAGE="2026-05-16T00:45:00Z"

# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------

epoch() {
    date -d "$1" +%s
}

human_duration() {
    local start="$1"
    local end="$2"
    local seconds days hours mins

    seconds=$(( $(epoch "$end") - $(epoch "$start") ))
    days=$(( seconds / 86400 ))
    hours=$(( (seconds % 86400) / 3600 ))
    mins=$(( (seconds % 3600) / 60 ))

    printf "%dd %02dh %02dm" "$days" "$hours" "$mins"
}

hours_duration() {
    local start="$1"
    local end="$2"
    local seconds

    seconds=$(( $(epoch "$end") - $(epoch "$start") ))

    awk -v s="$seconds" 'BEGIN { printf "%.2f", s / 3600 }'
}

days_duration() {
    local start="$1"
    local end="$2"
    local seconds

    seconds=$(( $(epoch "$end") - $(epoch "$start") ))

    awk -v s="$seconds" 'BEGIN { printf "%.2f", s / 86400 }'
}

# ------------------------------------------------------------------
# Metrics
# ------------------------------------------------------------------

DWELL="$(human_duration "$FIRST_ACCESS" "$CONTAINMENT")"
BREAKOUT_HOURS="$(hours_duration "$FIRST_ACCESS" "$LATERAL1")"
PERSIST_HOURS="$(hours_duration "$FIRST_ACCESS" "$TASK_CREATE")"
STAGING_DAYS="$(days_duration "$FIRST_ACCESS" "$STAGING1")"

# There is no reliable formal 4x04 detection timestamp because
# the source files conflict. Do not fabricate this metric.
DETECTION_TO_CONTAINMENT="UNRESOLVED - source chronology conflict"

# Attack phase anchors for average tempo.
PHASES=(
    "$FIRST_ACCESS"
    "$FIRST_C2"
    "$RUN_KEY"
    "$DEFENDER"
    "$LSASS1"
    "$LATERAL1"
    "$TASK_CREATE"
    "$STAGING1"
    "$LATERAL2"
    "$STAGING2"
    "$LSASS2"
    "$LATERAL3"
    "$CONTAINMENT"
)

TOTAL_GAP=0
GAP_COUNT=0

for ((i=1; i<${#PHASES[@]}; i++)); do
    prev="$(epoch "${PHASES[$((i-1))]}")"
    curr="$(epoch "${PHASES[$i]}")"

    TOTAL_GAP=$((TOTAL_GAP + curr - prev))
    GAP_COUNT=$((GAP_COUNT + 1))
done

AVG_PHASE_HOURS="$(
    awk -v s="$TOTAL_GAP" -v n="$GAP_COUNT" \
        'BEGIN { printf "%.1f", (s / n) / 3600 }'
)"

# ------------------------------------------------------------------
# Header
# ------------------------------------------------------------------

line
echo "   UNIFIED ATTACK TIMELINE - HEALTHBANE vs MedDefense"
echo "   Period: 2026-04-14 13:14:22 UTC -> 2026-05-15 13:42 CDT"
line
echo

echo "Primary victim/pivot:"
echo "  WS-RECV-03 (10.10.3.21)"
echo

echo "Timezone convention:"
echo "  April network evidence: UTC unless source says otherwise."
echo "  May host/IR events: CDT (UTC-5)."
echo "  UTC equivalents are shown where useful."
echo

echo "Clock-skew rule:"
echo "  Firewall timestamps are approximately +4 seconds relative to"
echo "  PCAP/Wazuh because the firewall timestamps policy/SYN handling."
echo "  Firewall time is authoritative for connection initiation when"
echo "  the same connection exists in both sources."
echo

# ------------------------------------------------------------------
# Timeline
# ------------------------------------------------------------------

line
echo "CHRONOLOGICAL SEQUENCE"
line
echo

cat <<'EOF'
#01  2026-04-14 13:14:22 UTC
     EVENT: Initial HEALTHBANE phishing email delivered
     SOURCE: 45.142.214.108
     TARGET: MedDefense mail infrastructure / Diane Marsh
     USER: MEDDEFENSE\dmarsh
     ATT&CK: T1566.001
     EVIDENCE: 4x00 + 4x01
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#02  2026-04-14 13:18:05 UTC
     EVENT: Diane clicks meddefense-portal.com phishing link
     SOURCE: WS-RECV-03 (10.10.3.21)
     TARGET: meddefense-portal.com / 91.219.236.117
     USER: MEDDEFENSE\dmarsh
     ATT&CK: T1566.001
     EVIDENCE: 4x00 + 4x01 DNS/TLS evidence
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#03  2026-04-14 13:18:42 UTC
     EVENT: Credentials submitted to /collect.php
     SOURCE: WS-RECV-03
     TARGET: 91.219.236.117:443
     USER: MEDDEFENSE\dmarsh
     ATT&CK: T1078
     EVIDENCE: 4x00 + 4x01
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#04  2026-04-15 08:43:18 UTC
     EVENT: Second-wave malicious DOCM delivered
     SOURCE: 45.142.214.108
     TARGET: MedDefense / Diane Marsh
     USER: MEDDEFENSE\dmarsh
     ARTIFACT: April-Invoice-MD2026.docm
     ATT&CK: T1566.001
     EVIDENCE: 4x01 + 4x03
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#05  2026-04-15 08:51:09 UTC
     EVENT: Dropper resolves update.healthbane-c2.net
     SOURCE: WS-RECV-03
     TARGET: 185.220.101.45
     USER: dmarsh execution context
     ATT&CK: T1568
     EVIDENCE: 4x01 + 4x03
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#06  2026-04-15 08:51:11 UTC
     EVENT: svchost_update.exe downloaded
     SOURCE: WS-RECV-03
     TARGET: 185.220.101.45:443
     USER: dmarsh execution context
     ATT&CK: T1105
     EVIDENCE: 4x01 + 4x03
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#07  2026-04-15 08:51:38 UTC
     EVENT: First confirmed HEALTHBANE C2 beacon
     SOURCE: WS-RECV-03
     TARGET: sync.healthbane-c2.net / 185.220.101.45:443
     USER: compromised workstation context
     ATT&CK: T1071.001, T1573.001
     EVIDENCE: 4x01 + 4x03; later IR firewall confirms persistence
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#08  2026-04-22 06:14:47 UTC
     EVENT: HealthSync Run-key persistence present
     SOURCE: WS-RECV-03
     TARGET: HKCU\...\Run\HealthSync
     USER: records03 profile
     ATT&CK: T1547.001
     EVIDENCE: 4x03 + IR-MEM + IR-DISK
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#09  2026-05-04 18:11:08 CDT
     EVENT: Defender exclusion added for C:\Windows\Temp
     SOURCE: WS-RECV-03
     TARGET: Windows Defender configuration
     USER: records03 elevated context
     ATT&CK: T1562.001
     EVIDENCE: IR-MEM + IR-DISK
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#10  2026-05-05 03:22:14 CDT
     EVENT: debug_tool.exe executes and accesses LSASS
     SOURCE: WS-RECV-03
     TARGET: lsass.exe
     USER: MEDDEFENSE\records03
     ATT&CK: T1003.001
     EVIDENCE: 4x04 + IR-MEM + IR-DISK
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#11  2026-05-05 03:22:18-03:22:34 CDT
     EVENT: LSASS material written to C:\Windows\Temp\out.dat
     SOURCE: WS-RECV-03 / lsass.exe
     TARGET: out.dat
     USER: records03
     CREDENTIAL FOUND: svc_healthsync
     ATT&CK: T1003.001
     EVIDENCE: 4x04 + IR-MEM + IR-DISK
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#12  2026-05-06 02:11:42 CDT
     EVENT: First lateral movement - PsExec
     SOURCE: WS-RECV-03
     TARGET: SRV-HEALTH-DB
     USER: records03
     CREDENTIAL: MEDDEFENSE\svc_healthsync
     ATT&CK: T1021.002, T1078.002
     EVIDENCE: 4x04 + IR-DISK + IR-FW
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#13  2026-05-06 02:13:11-02:13:48 CDT
     EVENT: WMI follow-on execution
     SOURCE: WS-RECV-03
     TARGET: SRV-HEALTH-DB
     CREDENTIAL: svc_healthsync
     ATT&CK: T1047
     EVIDENCE: 4x04 + IR-DISK + IR-FW
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#14  2026-05-06 ~02:36 CDT
     EVENT: PowerShell Remoting / stage1.ps1 transfer
     SOURCE: WS-RECV-03
     TARGET: SRV-HEALTH-DB
     CREDENTIAL: svc_healthsync
     ATT&CK: T1021.006
     EVIDENCE: 4x04 + IR-DISK
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#15  2026-05-07 01:47:33 CDT
     EVENT: "HealthSync Update Service" scheduled task created
     SOURCE: WS-RECV-03
     TARGET: Local Task Scheduler
     USER: MEDDEFENSE\records03
     ATT&CK: T1053.005
     EVIDENCE: IR-MEM + IR-DISK
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#16  2026-05-07 ~01:48 CDT
     EVENT: Secondary attacker-associated channel begins
     SOURCE: WS-RECV-03
     TARGET: 203.0.113.47:8443
     USER: svchost_update.exe context
     ATT&CK: T1571
     EVIDENCE: IR-MEM + IR-FW
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED for communication
     ROLE: PROBABLE secondary/fallback C2

#17  2026-05-08 02:36:08-02:36:34 CDT
     EVENT: Patient data collected and archived locally
     SOURCE: SRV-HEALTH-DB
     TARGET: WS-RECV-03\C:\Users\Public\Tmp\
     USER/CREDENTIAL: svc_healthsync / records03 execution context
     ARTIFACT: staging_export_001.zip
     RECORDS: 47,138 patient records
     ATT&CK: T1005, T1074.001, T1560.001
     EVIDENCE: IR-DISK + related network evidence
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#18  2026-05-08 ~02:36-02:38 CDT
     EVENT: First confirmed sensitive-data exfiltration burst
     SOURCE: WS-RECV-03
     TARGET: HEALTHBANE C2 infrastructure
     DATA: patient dataset
     ATT&CK: T1041
     EVIDENCE: IR-DISK + IR-FW
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#19  2026-05-08 02:38:14 CDT
     EVENT: Patient staging artifacts deleted
     SOURCE/TARGET: WS-RECV-03
     USER: records03 context
     ATT&CK: T1070.004
     EVIDENCE: IR-DISK
     STATUS: SINGLE-SOURCE
     CONFIDENCE: PROBABLE under project rubric

#20  2026-05-09 02:46:11 CDT
     EVENT: Second major lateral pivot
     SOURCE: WS-RECV-03
     TARGET: SRV-INS-DB
     CREDENTIAL: svc_healthsync
     TOOL: PsExec -> WMI -> PSRemoting
     ATT&CK: T1021.002, T1047, T1021.006, T1078.002
     EVIDENCE: 4x04 + IR-DISK + IR-FW
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#21  2026-05-09 03:01:42 CDT
     EVENT: Windows Security event log deleted/recreated
     SOURCE/TARGET: WS-RECV-03
     USER: attacker in records03 context
     ATT&CK: T1070.001
     EVIDENCE: IR-DISK + memory clear_logs configuration
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#22  2026-05-11 03:14:42-03:15:09 CDT
     EVENT: Insurance/member data collected and archived
     SOURCE: SRV-INS-DB
     TARGET: WS-RECV-03\C:\Users\Public\Tmp\
     ARTIFACT: staging_export_002.zip
     RECORDS: 51,002 insurance/member records
     ATT&CK: T1005, T1074.001, T1560.001
     EVIDENCE: IR-DISK + network correlation
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#23  2026-05-11 ~03:15-03:17 CDT
     EVENT: Second confirmed sensitive-data exfiltration burst
     SOURCE: WS-RECV-03
     TARGET: HEALTHBANE C2 infrastructure
     DATA: insurance/member dataset
     ATT&CK: T1041
     EVIDENCE: IR-DISK + IR-FW
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#24  2026-05-11 03:17:01 CDT
     EVENT: Insurance staging artifacts deleted
     SOURCE/TARGET: WS-RECV-03
     ATT&CK: T1070.004
     EVIDENCE: IR-DISK
     STATUS: SINGLE-SOURCE
     CONFIDENCE: PROBABLE under project rubric

#25  2026-05-12 02:45:01 CDT
     EVENT: Second LSASS credential dump
     SOURCE: WS-RECV-03
     TARGET: lsass.exe / out.dat
     USER: records03
     ATT&CK: T1003.001
     EVIDENCE: 4x04 + IR-DISK + IR-MEM residual evidence
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#26  2026-05-13 02:08:56 CDT
     EVENT: Third major lateral pivot
     SOURCE: WS-RECV-03
     TARGET: SRV-DC-01
     CREDENTIAL: svc_healthsync
     TOOL: PsExec -> WMI -> PSRemoting
     ATT&CK: T1021.002, T1047, T1021.006, T1078.002
     EVIDENCE: 4x04 + IR-DISK + IR-FW
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#27  2026-05-13 02:31:18 CDT
     EVENT: Active Directory enumeration results staged
     SOURCE: SRV-DC-01
     TARGET: WS-RECV-03\C:\Users\Public\Tmp\query_results.csv
     USER/CREDENTIAL: svc_healthsync
     ATT&CK: T1087.002, T1074.001
     EVIDENCE: 4x04 + IR-DISK
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#28  2026-05-13 ~02:31-02:34 CDT
     EVENT: AD enumeration data transmitted externally
     SOURCE: WS-RECV-03
     TARGET: HEALTHBANE C2
     DATA: 1,184 AD account records
     ATT&CK: T1041
     EVIDENCE: IR-DISK + IR-FW
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#29  2026-05-15 02:00:14 CDT
     EVENT: Last observed scheduled exfiltrator execution before isolation
     SOURCE: WS-RECV-03
     TARGET: local staging/C2 workflow
     USER: records03
     ATT&CK: T1053.005
     EVIDENCE: IR-MEM + IR-DISK Prefetch
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#30  2026-05-15 13:42 CDT / 18:42 UTC
     EVENT: WS-RECV-03 isolated from network
     SOURCE: MedDefense IR
     TARGET: WS-RECV-03
     ATT&CK: N/A - containment
     EVIDENCE: IR Team Notes + post-isolation network state
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#31  2026-05-15 14:18:42 CDT
     EVENT: Live memory captured after network isolation
     SOURCE: WS-RECV-03
     TOOL: WinPmem 4.0.1
     ATT&CK: N/A - DFIR action
     EVIDENCE: IR-MEM + IR Team Notes
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED

#32  2026-05-15 19:45 CDT / 2026-05-16 00:45 UTC
     EVENT: Forensic disk image completed
     SOURCE: WS-RECV-03
     TOOL: FTK Imager 4.7.1.4
     ATT&CK: N/A - DFIR action
     EVIDENCE: IR-DISK + IR Team Notes
     STATUS: CONVERGED
     CONFIDENCE: CONFIRMED
EOF

echo
echo "Total timeline events: 32"
echo

# ------------------------------------------------------------------
# Metrics
# ------------------------------------------------------------------

line
echo "TEMPORAL METRICS"
line
echo

echo "Total dwell time:"
echo "  $DWELL"
echo "  From first phishing delivery to network containment."
echo

echo "Breakout time:"
echo "  $BREAKOUT_HOURS hours"
echo "  Initial phishing delivery -> first confirmed lateral movement."
echo

echo "Time to scheduled-task persistence:"
echo "  $PERSIST_HOURS hours"
echo "  Initial phishing delivery -> HealthSync Update Service creation."
echo

echo "Time to first sensitive-data staging:"
echo "  $STAGING_DAYS days"
echo "  Initial phishing delivery -> first patient archive."
echo

echo "Detection to containment:"
echo "  $DETECTION_TO_CONTAINMENT"
echo

cat <<'EOF'
  Reason:
    The supplied sources contain an unresolved chronology conflict.

    4x04_hunting_report.txt states:
      Hunt initiated: 2026-05-18 09:00 CDT
      IR escalation:  2026-05-18 17:30 CDT

    But ir_team_notes.txt states:
      WS-RECV-03 was isolated on 2026-05-15 13:42 CDT
      because of 4x04 hunt findings.

    Since containment cannot occur three days before the hunt that
    supposedly triggered it, a reliable "detection-to-containment"
    duration cannot be calculated from the supplied evidence.

    The containment timestamp itself IS independently supported.
EOF

echo

echo "Average time between major reconstructed phase anchors:"
echo "  approximately $AVG_PHASE_HOURS hours"
echo

echo "Operational tempo:"
echo "  Initial foothold developed slowly across April."
echo "  Stage 4 accelerated into repeated 01:00-04:00 CDT activity."
echo "  Major May operational dates:"
echo "    May 05 - credential access"
echo "    May 06 - HEALTH-DB lateral movement"
echo "    May 07 - scheduled persistence / secondary channel"
echo "    May 08 - patient-data staging/exfiltration"
echo "    May 09 - INS-DB lateral movement / log clearing"
echo "    May 11 - insurance-data staging/exfiltration"
echo "    May 12 - second credential dump"
echo "    May 13 - DC lateral movement / AD collection"
echo "    May 15 - final task execution / containment"
echo

# ------------------------------------------------------------------
# Gaps
# ------------------------------------------------------------------

line
echo "TIMELINE GAPS"
line
echo

cat <<'EOF'
GAP 1:
  2026-04-14 13:18:42 UTC -> 2026-04-15 08:43:18 UTC

  Known:
    Diane's credentials had been submitted.

  Unknown:
    Whether dmarsh was used during the approximately 17-minute
    pre-rotation opportunity identified in the IR notes.

  Assessment:
    EVIDENCE GAP.
    Do not interpret absence of a confirmed logon as proof that
    the credentials were never tested.


GAP 2:
  2026-04-16 -> 2026-04-22

  Known:
    C2 was active when the 48-hour PCAP collection ended.

  Limitation:
    4x01 PCAP coverage ended at 2026-04-16 00:00 UTC.

  Next strong host artifact:
    Run-key / RAT execution evidence on 2026-04-22.

  Assessment:
    COLLECTION GAP, not evidence of attacker dormancy.


GAP 3:
  2026-04-22 -> 2026-05-04

  Known:
    Persistent RAT foothold existed.

  Later firewall evidence:
    demonstrates continued C2 during its available May window.

  Unknown:
    Complete operator command sequence during this interval.

  Assessment:
    PARTIAL VISIBILITY.


GAP 4:
  2026-05-10

  Scheduled task executed at approximately 02:00.

  No major new pivot or independently established sensitive-data
  staging event is present in the supplied reconstruction evidence.

  Assessment:
    Activity may have been routine C2/task execution.
    Do not invent an attacker objective.


GAP 5:
  2026-05-14

  Scheduled task executed at approximately 02:00.

  No independently confirmed new lateral-movement or data-staging
  event is established.

  Assessment:
    Attacker intent during this period is UNKNOWN.


GAP 6:
  2026-05-15 02:00 -> 13:42 CDT

  Scheduled task executed at 02:00.
  Host remained compromised until isolation at 13:42.

  Exact operator activity between those anchors is incomplete.

  Assessment:
    PARTIAL VISIBILITY.
EOF

echo

# ------------------------------------------------------------------
# Sequencing uncertainties
# ------------------------------------------------------------------

line
echo "SEQUENCING UNCERTAINTIES / CONTRADICTIONS"
line
echo

cat <<'EOF'
[1] 4x04 HUNT DATE vs CONTAINMENT DATE -- UNRESOLVED

    Source A:
      4x04_hunting_report.txt says hunt initiated 2026-05-18
      and escalation issued 2026-05-18.

    Source B:
      ir_team_notes.txt says the host was isolated 2026-05-15
      because of 4x04 hunt findings.

    These statements cannot both be chronologically correct.

    Resolution:
      Do NOT silently rewrite either source.

      Adopt:
        2026-05-15 13:42 CDT as authoritative containment time,
        because it is a direct operational IR event.

      Do NOT calculate an exact detection-to-containment metric
      until the hunt metadata is corrected or clarified.

    Impact:
      Significant for process/performance metrics.
      Minimal for reconstruction of attacker activity before
      containment.


[2] PsExec timestamps -- SOURCE GRANULARITY

    4x04 summary uses rounded/correlated session times such as
    approximately 02:12 CDT.

    Disk Prefetch provides executable-run timestamps such as:
      2026-05-06 02:11:42 CDT.

    Resolution:
      Use the more precise artifact timestamp for executable
      execution and retain 4x04 as corroborating evidence.

    Impact:
      Minimal.


[3] Firewall vs host/PCAP timestamps -- RESOLVED

    Difference:
      approximately four seconds.

    Cause documented in firewall metadata:
      firewall timestamps policy/SYN processing;
      PCAP/host sources timestamp collection/receipt.

    Resolution:
      firewall timestamp is authoritative for connection initiation
      when the same session exists in both sources.

    Impact:
      Minimal.


[4] 203.0.113.47 ROLE -- PARTIALLY RESOLVED

    Communication itself:
      CONFIRMED by memory + firewall.

    Exact role as fallback/secondary C2:
      PROBABLE.

    Reason:
      encrypted communication prevents direct reconstruction of
      command content.

    Impact:
      Does not change the confirmed compromise timeline.


[5] Second LSASS dump motivation -- UNKNOWN

    Event:
      CONFIRMED.

    Hypothesis:
      attacker re-acquired credentials after suspected rotation.

    Evidence does not prove that motivation.

    Resolution:
      Keep motivation POSSIBLE rather than factual.
EOF

echo

# ------------------------------------------------------------------
# Unified chain
# ------------------------------------------------------------------

line
echo "UNIFIED ATTACK CHAIN"
line
echo

cat <<'EOF'
14 Apr
Phishing / credential harvesting
        |
        v
15 Apr
Malicious DOCM
        |
        v
svchost_update.exe
        |
        v
Primary C2 established
        |
        v
22 Apr
Run-key persistence
        |
        v
04 May
Defender exclusion
        |
        v
05 May
LSASS dump
        |
        v
svc_healthsync credential material
        |
        v
06 May
SRV-HEALTH-DB
PsExec -> WMI -> PSRemoting
        |
        v
07 May
Scheduled task + secondary channel
        |
        v
08 May
47,138 patient records
collection -> staging -> exfiltration
        |
        v
09 May
SRV-INS-DB + Security log clear
        |
        v
11 May
51,002 insurance/member records
collection -> staging -> exfiltration
        |
        v
12 May
Second LSASS dump
        |
        v
13 May
SRV-DC-01
AD enumeration -> staging -> transmission
        |
        v
15 May
Scheduled malware still executing
        |
        v
13:42 CDT
WS-RECV-03 ISOLATED
        |
        +--> 14:18 memory acquisition
        |
        `--> 19:45 disk imaging
EOF

echo

# ------------------------------------------------------------------
# Final assessment
# ------------------------------------------------------------------

line
echo "TIMELINE ASSESSMENT"
line
echo

cat <<'EOF'
The unified evidence supports a continuous HEALTHBANE intrusion from
the initial phishing event through containment.

Strongest convergences:

  - phishing:
      4x00 + 4x01

  - malware/C2:
      4x01 + 4x03 + memory + later firewall evidence

  - LSASS credential access:
      4x04 + memory + disk

  - lateral movement:
      4x04 + disk + firewall

  - scheduled-task persistence:
      memory + disk

  - sensitive-data staging:
      disk + network correlation

  - exfiltration:
      disk artifact sizes + firewall transfer evidence

  - containment:
      IR records + resulting network isolation state

Overall reconstruction confidence:
  HIGH

Critical limitation:
  The formal 4x04 hunt timestamp conflicts with the IR containment
  chronology. That discrepancy remains explicitly unresolved and must
  not be hidden in the final report.
EOF

echo
line
echo "   Unified timeline complete."
line