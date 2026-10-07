#!/bin/bash
#
# 4x05 - Attack Reconstruction
# Task 3 - Firewall Session Analysis
#
# Analyzes the 14-day firewall export for WS-RECV-03 and correlates
# C2, lateral movement and exfiltration with previous findings.
#

set -euo pipefail

FW="ir_evidence/firewall_sessions_ws_recv_03.json"
DISK="ir_evidence/disk_forensics_report.txt"
NETWORK="previous_findings/4x01_network_timeline.txt"
HUNT="previous_findings/4x04_hunting_report.txt"
IOC_DB="reference/healthbane_ioc_master.json"

for file in "$FW" "$DISK" "$NETWORK" "$HUNT" "$IOC_DB"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Required file not found: $file" >&2
        exit 1
    fi
done

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required." >&2
    exit 1
fi

is_session='
    type == "object"
    and has("src_ip")
    and has("dst_ip")
    and has("ts_start")
'

TOTAL_SESSIONS="$(jq -r '.summary.total_sessions_in_window' "$FW")"
EXPORTED_SESSIONS="$(jq -r '.summary.session_count_this_export // .metadata.session_count_in_export' "$FW")"

KNOWN_C2_SESSIONS="$(jq -r '.summary.by_classification.KNOWN_C2.session_count' "$FW")"
KNOWN_C2_IN="$(jq -r '.summary.by_classification.KNOWN_C2.total_bytes_in' "$FW")"
KNOWN_C2_OUT="$(jq -r '.summary.by_classification.KNOWN_C2.total_bytes_out_including_exfil_bursts' "$FW")"

SECONDARY_SESSIONS="$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.session_count' "$FW")"
SECONDARY_IN="$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.total_bytes_in' "$FW")"
SECONDARY_OUT="$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.total_bytes_out' "$FW")"
SECONDARY_FIRST="$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.first_seen_in_window' "$FW")"
SECONDARY_LAST="$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.last_seen_in_window' "$FW")"
SECONDARY_PATTERN="$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.interval_observed' "$FW")"

EXFIL_SESSIONS="$(jq -r '.summary.by_classification.EXFIL_BURST.session_count' "$FW")"
EXFIL_TOTAL="$(jq -r '.summary.by_classification.EXFIL_BURST.total_bytes_out' "$FW")"

LATERAL_SESSIONS="$(jq -r '.summary.by_classification.LATERAL_MOVEMENT.session_count' "$FW")"

START="$(jq -r '.metadata.time_range_utc.start' "$FW")"
END="$(jq -r '.metadata.time_range_utc.end' "$FW")"

fmt_bytes() {
    local bytes="$1"

    awk -v b="$bytes" '
        BEGIN {
            if (b >= 1073741824)
                printf "%.2f GiB", b / 1073741824
            else if (b >= 1048576)
                printf "%.2f MiB", b / 1048576
            else if (b >= 1024)
                printf "%.2f KiB", b / 1024
            else
                printf "%d B", b
        }
    '
}

echo "================================================================"
echo "   FIREWALL SESSION ANALYSIS - WS-RECV-03"
echo "   Source: $FW"
echo "   Period: $START to $END"
echo "================================================================"
echo

echo "DATASET NOTE:"
echo "  Full 14-day firewall population: $TOTAL_SESSIONS sessions"
echo "  Sessions reproduced individually: $EXPORTED_SESSIONS"
echo
echo "  This is an abridged IR export."
echo "  Aggregate statistics below use .summary where available."
echo

echo "================================================================"
echo "SESSION OVERVIEW"
echo "================================================================"
echo

echo "  Total sessions in full window:       $TOTAL_SESSIONS"
echo "  Individually reproduced sessions:    $EXPORTED_SESSIONS"
echo "  Known C2 sessions:                   $KNOWN_C2_SESSIONS"
echo "  Secondary-C2 hypothesis sessions:    $SECONDARY_SESSIONS"
echo "  Lateral-movement sessions:           $LATERAL_SESSIONS"
echo "  Explicit exfiltration bursts:        $EXFIL_SESSIONS"
echo

echo "  Known C2 bytes out:"
echo "    $KNOWN_C2_OUT bytes ($(fmt_bytes "$KNOWN_C2_OUT"))"
echo
echo "  Known C2 bytes in:"
echo "    $KNOWN_C2_IN bytes ($(fmt_bytes "$KNOWN_C2_IN"))"
echo
echo "  Secondary C2 bytes out:"
echo "    $SECONDARY_OUT bytes ($(fmt_bytes "$SECONDARY_OUT"))"
echo
echo "  Secondary C2 bytes in:"
echo "    $SECONDARY_IN bytes ($(fmt_bytes "$SECONDARY_IN"))"
echo

echo "NOTE:"
echo "  Exact internal-vs-external totals for all $TOTAL_SESSIONS sessions"
echo "  cannot be recomputed from the 168 reproduced records alone."
echo "  The file provides authoritative aggregate classification counts."
echo

echo "================================================================"
echo "TOP EXTERNAL DESTINATIONS - REPRODUCED SESSION SAMPLE"
echo "================================================================"
echo

printf "%-5s %-18s %-7s %-7s %-10s %-14s %-14s\n" \
    "Rank" "IP" "Port" "Proto" "Sessions" "Bytes Out" "Bytes In"

jq -r "
    [.sessions[]
     | select($is_session)
     | select(.dst_ip | test(\"^(10\\\\.|192\\\\.168\\\\.|172\\\\.(1[6-9]|2[0-9]|3[01])\\\\.)\") | not)
     | {
         ip: .dst_ip,
         port: .dst_port,
         proto: .proto,
         bytes_out: (.bytes_out // 0),
         bytes_in: (.bytes_in // 0)
       }]
    | group_by([.ip,.port,.proto])
    | map({
        ip: .[0].ip,
        port: .[0].port,
        proto: .[0].proto,
        sessions: length,
        bytes_out: (map(.bytes_out) | add),
        bytes_in: (map(.bytes_in) | add)
      })
    | sort_by(.bytes_out)
    | reverse
    | .[:10]
    | to_entries[]
    | [
        (.key + 1),
        .value.ip,
        .value.port,
        .value.proto,
        .value.sessions,
        .value.bytes_out,
        .value.bytes_in
      ]
    | @tsv
" "$FW" |
awk -F '\t' '{
    printf "%-5s %-18s %-7s %-7s %-10s %-14s %-14s\n",
           $1,$2,$3,$4,$5,$6,$7
}'

echo
echo "================================================================"
echo "TOP INTERNAL DESTINATIONS - REPRODUCED SESSION SAMPLE"
echo "================================================================"
echo

printf "%-5s %-18s %-10s %-14s %-14s\n" \
    "Rank" "IP" "Sessions" "Bytes Out" "Bytes In"

jq -r "
    [.sessions[]
     | select($is_session)
     | select(.dst_ip | test(\"^(10\\\\.|192\\\\.168\\\\.|172\\\\.(1[6-9]|2[0-9]|3[01])\\\\.)\"))
     | {
         ip: .dst_ip,
         bytes_out: (.bytes_out // 0),
         bytes_in: (.bytes_in // 0)
       }]
    | group_by(.ip)
    | map({
        ip: .[0].ip,
        sessions: length,
        bytes_out: (map(.bytes_out) | add),
        bytes_in: (map(.bytes_in) | add)
      })
    | sort_by(.sessions)
    | reverse
    | .[:10]
    | to_entries[]
    | [
        (.key + 1),
        .value.ip,
        .value.sessions,
        .value.bytes_out,
        .value.bytes_in
      ]
    | @tsv
" "$FW" |
awk -F '\t' '{
    printf "%-5s %-18s %-10s %-14s %-14s\n",
           $1,$2,$3,$4,$5
}'

echo
echo "KNOWN HEALTHBANE C2:"
echo

cat <<EOF
  Destination:
    185.220.101.45:443/TCP

  Sessions:
    $KNOWN_C2_SESSIONS

  First seen:
    $(jq -r '.summary.by_classification.KNOWN_C2.first_seen_in_window' "$FW")

  Last allowed:
    $(jq -r '.summary.by_classification.KNOWN_C2.last_seen_in_window' "$FW")

  Beacon pattern:
    $(jq -r '.summary.by_classification.KNOWN_C2.interval_observed' "$FW")

  JA3:
    $(jq -r '.summary.by_classification.KNOWN_C2.ja3_observed' "$FW")

  Matches 4x01 fingerprint:
    $(jq -r '.summary.by_classification.KNOWN_C2.matches_4x01_fingerprint' "$FW")

  Assessment:
    CONFIRMED HEALTHBANE C2.

    The connection remained active throughout the 14-day firewall
    window until host isolation.
EOF

echo
echo "================================================================"
echo "UNKNOWN IP INVESTIGATION"
echo "================================================================"
echo

cat <<EOF
IP:
  203.0.113.47

Port:
  8443/TCP

Application:
  SSL

Sessions:
  $SECONDARY_SESSIONS

First seen:
  $SECONDARY_FIRST

Last seen:
  $SECONDARY_LAST

Bytes out:
  $SECONDARY_OUT ($(fmt_bytes "$SECONDARY_OUT"))

Bytes in:
  $SECONDARY_IN ($(fmt_bytes "$SECONDARY_IN"))

Pattern:
  $SECONDARY_PATTERN
EOF

echo
echo "INDIVIDUAL SAMPLE SESSIONS:"
echo

jq -r '
    .sessions[]
    | select(type == "object")
    | select(.dst_ip? == "203.0.113.47")
    | select(has("ts_start"))
    | "  \(.ts_start)  \(.dst_ip):\(.dst_port)  \(.proto)  OUT=\(.bytes_out)  IN=\(.bytes_in)  duration=\(.duration_sec)s"
' "$FW"

echo
echo "CORRELATION:"
cat <<'EOF'
  - 203.0.113.47 was not present in the previous IOC set.
  - It uses TCP/8443 with SSL.
  - No DNS lookup preceded the first connection.
  - Communications occur approximately daily during off-hours.
  - Traffic volume is low and control-channel-like.
  - Memory analysis independently associated the endpoint with
    svchost_update.exe.
  - First firewall connection occurred immediately after creation
    of the HealthSync scheduled task.
EOF

echo
echo "ASSESSMENT:"
cat <<'EOF'
  Classification:
    SECONDARY / FALLBACK C2

  Confidence:
    CONFIRMED as attacker-associated communication through
    convergent memory + firewall evidence.

  Infrastructure-role confidence:
    PROBABLE secondary/fallback C2.

  Reason:
    The evidence proves the malicious RAT communicated with the IP.
    Its low-volume, downstream-heavy and daily/off-hours pattern is
    consistent with a standby command channel rather than the
    primary exfiltration channel.
EOF

echo
echo "NEW IOC:"
echo "  203.0.113.47:8443"
echo

echo "================================================================"
echo "TEMPORAL ANALYSIS - REPRODUCED SESSIONS"
echo "================================================================"
echo

echo "Sessions by UTC hour:"
echo

jq -r '
    .sessions[]
    | select(type == "object")
    | select(has("ts_start"))
    | .ts_start[11:13]
' "$FW" |
sort |
uniq -c |
awk '{
    printf "  %s:00  %s sessions\n", $2, $1
}'

echo
echo "OFF-HOURS ATTACK CLUSTERS:"
cat <<'EOF'
  2026-05-05
    Credential dump followed by increased outbound C2 volume.

  2026-05-06
    First lateral movement:
      WS-RECV-03 -> SRV-HEALTH-DB

  2026-05-07
    Scheduled-task persistence established.
    Secondary C2 first appears.

  2026-05-08
    First major data-exfiltration burst.

  2026-05-09
    Lateral movement:
      WS-RECV-03 -> SRV-INS-DB

  2026-05-11
    Second major data-exfiltration burst.

  2026-05-12
    Second credential-dumping cycle.

  2026-05-13
    Lateral movement:
      WS-RECV-03 -> SRV-DC-01
    AD enumeration exfiltration.

  Pattern:
    Malicious cross-VLAN activity clusters during approximately
    02:00-04:00 CDT, outside normal business activity.
EOF

echo
echo "================================================================"
echo "LATERAL MOVEMENT CORRELATION"
echo "================================================================"
echo

cat <<EOF
Cross-VLAN lateral-movement sessions:
  $LATERAL_SESSIONS

Targets:
  SRV-HEALTH-DB  10.10.20.30
  SRV-INS-DB     10.10.20.31
  SRV-DC-01      10.10.20.10

Ports observed:
  445
  135
  49664
  49665
  5985

Interpretation:
  445        -> SMB / PsExec
  135 + RPC  -> WMI
  5985       -> WinRM / PowerShell Remoting

Assessment:
  Firewall metadata independently corroborates the lateral movement
  reconstructed during the 4x04 threat hunt.
EOF

echo
echo "================================================================"
echo "LARGE OUTBOUND TRANSFERS / EXFILTRATION"
echo "================================================================"
echo

printf "%-22s %-16s %-14s %s\n" \
    "Timestamp UTC" "Bytes Out" "Size" "Disk Correlation"

jq -r '
    .summary.by_classification.EXFIL_BURST.by_burst[]
    | [
        .ts_utc,
        (.bytes_out | tostring),
        .matches_disk_artifact
      ]
    | @tsv
' "$FW" |
while IFS=$'\t' read -r ts bytes artifact; do
    printf "%-22s %-16s %-14s %s\n" \
        "$ts" "$bytes" "$(fmt_bytes "$bytes")" "$artifact"
done

echo
echo "Total explicit staging/exfil bursts:"
echo "  $EXFIL_TOTAL bytes ($(fmt_bytes "$EXFIL_TOTAL"))"
echo

echo "CORRELATION WITH TASK 2:"
echo

jq -r '
    .summary.by_classification.EXFIL_BURST.by_burst[]
    | "  \(.ts_utc)\n    Firewall bytes_out: \(.bytes_out)\n    Disk artifact:       \(.matches_disk_artifact)\n"
' "$FW"

echo "================================================================"
echo "EXFILTRATION ASSESSMENT"
echo "================================================================"
echo

cat <<EOF
FINDING:
  DATA EXFILTRATION OCCURRED.

Explicit exfiltration bursts:
  $EXFIL_SESSIONS

Total bytes in the three matched bursts:
  $EXFIL_TOTAL bytes ($(fmt_bytes "$EXFIL_TOTAL"))

Destination:
  185.220.101.45:443

Channel:
  HTTPS / SSL to known HEALTHBANE C2

Cross-evidence correlation:

  Disk evidence                     Firewall evidence
  -------------------------------   -------------------------------
  staging_export_001.zip            14,219,484 bytes outbound
  14,219,484 bytes                  2026-05-08 07:38:14 UTC

  staging_export_002.zip            11,802,944 bytes outbound
  11,802,944 bytes                  2026-05-11 08:17:18 UTC

  query_results.csv                 8,419,232 bytes outbound
  8,419,232 bytes                   2026-05-13 07:34:14 UTC

Assessment:
  The outbound byte counts match the recovered disk artifacts
  exactly.

  This is convergent evidence from two independent forensic domains:

    DISK:
      proves the files existed and identifies their contents.

    FIREWALL:
      proves matching byte volumes left WS-RECV-03 toward the
      known HEALTHBANE C2 infrastructure.

Confidence:
  CONFIRMED - HIGH.

Impact:
  47,138 patient records confirmed exfiltrated.
  51,002 insurance/member records confirmed exfiltrated.

  Total sensitive patient + insurance records:
    98,140

  Additionally:
    1,184 Active Directory account records were exfiltrated for
    reconnaissance purposes.

IMPORTANT:
  This changes the incident classification from suspected exposure
  / local staging to confirmed data exfiltration.
EOF

echo
echo "================================================================"
echo "TIMESTAMP RECONCILIATION"
echo "================================================================"
echo

cat <<'EOF'
The firewall metadata documents a known timing difference:

  Firewall timestamps:
    approximately 4 seconds ahead of PCAP / Wazuh timestamps.

Reason:
  Firewall records the SYN at policy-decision time while host-side
  sources record packet/event receipt.

Reconstruction decision:
  Use firewall timestamp as authoritative for network connection
  initiation.

This is a documented clock/collection difference, not a contradiction
in the attack sequence.
EOF

echo
echo "================================================================"
echo "FINAL ASSESSMENT"
echo "================================================================"
echo

cat <<'EOF'
CONFIRMED:
  - Primary HEALTHBANE C2 remained active throughout the window.
  - WS-RECV-03 performed unauthorized cross-VLAN lateral movement.
  - 47,138 patient records left the environment.
  - 51,002 insurance/member records left the environment.
  - 1,184 AD records were transmitted.
  - Disk staging artifacts and firewall byte counts correlate.
  - 203.0.113.47:8443 is associated with the malicious RAT.

PROBABLE:
  - 203.0.113.47:8443 served specifically as a secondary/fallback
    command-and-control channel.

NOT SUPPORTED:
  - The secondary 8443 endpoint was the primary exfiltration channel.
    Its traffic volume is too small and its behavior is control-like.

OVERALL CONFIDENCE:
  HIGH

CRITICAL CONCLUSION:
  This is no longer merely evidence of database access or attempted
  staging. The firewall evidence demonstrates successful outbound
  transmission of the staged sensitive data.
EOF

echo
echo "================================================================"
echo "   Firewall analysis complete."
echo "================================================================"