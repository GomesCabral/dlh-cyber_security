#!/bin/bash
#
# 4x05 - Attack Reconstruction
# Task 5 - Stage 1-2 Reconstruction
#
# Reconstructs HEALTHBANE initial access through persistent
# command-and-control establishment.
#

set -euo pipefail

PHISH="previous_findings/4x00_phishing_summary.txt"
NETWORK="previous_findings/4x01_network_timeline.txt"
ATTACK="previous_findings/4x02_attack_mapping.json"
MALWARE="previous_findings/4x03_malware_summary.txt"
FIREWALL="ir_evidence/firewall_sessions_ws_recv_03.json"
IOC_DB="reference/healthbane_ioc_master.json"

FILES=(
    "$PHISH"
    "$NETWORK"
    "$ATTACK"
    "$MALWARE"
    "$FIREWALL"
    "$IOC_DB"
)

for file in "${FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Required evidence source missing: $file" >&2
        exit 1
    fi
done

for cmd in jq grep date; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $cmd" >&2
        exit 1
    fi
done

line() {
    printf '%*s\n' 64 '' | tr ' ' '='
}

# ------------------------------------------------------------------
# Extract firewall facts dynamically
# ------------------------------------------------------------------

FW_START="$(
    jq -r '.metadata.time_range_utc.start // "UNKNOWN"' "$FIREWALL"
)"

PRIMARY_C2="$(
    jq -r '
        .summary.by_classification.KNOWN_C2.destinations[0]
        // "UNKNOWN"
    ' "$FIREWALL"
)"

PRIMARY_COUNT="$(
    jq -r '
        .summary.by_classification.KNOWN_C2.session_count
        // 0
    ' "$FIREWALL"
)"

PRIMARY_FIRST_FW="$(
    jq -r '
        .summary.by_classification.KNOWN_C2.first_seen_in_window
        // "UNKNOWN"
    ' "$FIREWALL"
)"

PRIMARY_LAST_FW="$(
    jq -r '
        .summary.by_classification.KNOWN_C2.last_seen_in_window
        // "UNKNOWN"
    ' "$FIREWALL"
)"

PRIMARY_INTERVAL="$(
    jq -r '
        .summary.by_classification.KNOWN_C2.interval_observed
        // "UNKNOWN"
    ' "$FIREWALL"
)"

PRIMARY_JA3="$(
    jq -r '
        .summary.by_classification.KNOWN_C2.ja3_observed
        // "UNKNOWN"
    ' "$FIREWALL"
)"

SECONDARY_C2="$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.destinations[0]
        // "UNKNOWN"
    ' "$FIREWALL"
)"

SECONDARY_FIRST="$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.first_seen_in_window
        // "UNKNOWN"
    ' "$FIREWALL"
)"

SECONDARY_LAST="$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.last_seen_in_window
        // "UNKNOWN"
    ' "$FIREWALL"
)"

SECONDARY_COUNT="$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.session_count
        // 0
    ' "$FIREWALL"
)"

SECONDARY_OUT="$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.total_bytes_out
        // 0
    ' "$FIREWALL"
)"

SECONDARY_IN="$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.total_bytes_in
        // 0
    ' "$FIREWALL"
)"

SECONDARY_PATTERN="$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.interval_observed
        // "UNKNOWN"
    ' "$FIREWALL"
)"

# ------------------------------------------------------------------
# Known temporal anchors from the consolidated evidence
# ------------------------------------------------------------------

EMAIL_TIME="2026-04-14T13:14:22Z"
CLICK_TIME="2026-04-14T13:18:05Z"
CRED_TIME="2026-04-14T13:18:42Z"

SECOND_WAVE_TIME="2026-04-15T08:43:18Z"
PAYLOAD_DNS_TIME="2026-04-15T08:51:09Z"
PAYLOAD_GET_TIME="2026-04-15T08:51:11Z"
FIRST_C2_TIME="2026-04-15T08:51:38Z"

# Difference between credential submission and first C2 beacon.
CRED_EPOCH="$(date -d "$CRED_TIME" +%s)"
C2_EPOCH="$(date -d "$FIRST_C2_TIME" +%s)"
DELTA_SECONDS=$((C2_EPOCH - CRED_EPOCH))
DELTA_HOURS=$((DELTA_SECONDS / 3600))
DELTA_MINUTES=$(((DELTA_SECONDS % 3600) / 60))

# ------------------------------------------------------------------
# Header
# ------------------------------------------------------------------

line
echo "   ATTACK RECONSTRUCTION: Stages 1-2"
echo "   Initial Access through C2 Establishment"
line
echo

echo "Victim host: WS-RECV-03 (10.10.3.21)"
echo "Initial user: MEDDEFENSE\\dmarsh (Diane Marsh)"
echo

# ------------------------------------------------------------------
# Stage 1
# ------------------------------------------------------------------

line
echo "STAGE 1: INITIAL ACCESS - PHISHING"
line
echo

echo "Campaign window:"
echo "  2026-04-14 through 2026-04-21"
echo

echo "[$EMAIL_TIME] HEALTHBANE phishing email E1 delivered"
echo
echo "  Host/User:"
echo "    Recipient pool included Diane Marsh / WS-RECV-03."
echo
echo "  Message:"
echo "    Subject:"
echo "      Action required: update your MedDefense portal password"
echo "      before 2026-04-15"
echo
echo "    Sender:"
echo "      no-reply@meddefense-portal.com"
echo
echo "    Display name:"
echo "      MedDefense IT"
echo
echo "    URL:"
echo "      https://meddefense-portal.com/login.aspx"
echo
echo "  Email authentication evidence:"
echo "    SPF:   HARDFAIL"
echo "    DKIM:  MISSING"
echo "    DMARC: FAIL"
echo
echo "  Infrastructure:"
echo "    meddefense-portal.com"
echo "    91.219.236.117"
echo
echo "  Evidence:"
echo "    previous_findings/4x00_phishing_summary.txt"
echo "    previous_findings/4x01_network_timeline.txt"
echo
echo "  ATT&CK:"
echo "    T1566.001 - Phishing: Spearphishing Link"
echo
echo "  Confidence:"
echo "    CONFIRMED"
echo "    Convergent email-investigation + network evidence."
echo

echo "[$CLICK_TIME] Diane Marsh clicks the credential-harvesting link"
echo
echo "  Host:"
echo "    WS-RECV-03 (10.10.3.21)"
echo
echo "  User:"
echo "    MEDDEFENSE\\dmarsh"
echo
echo "  Sequence:"
echo "    Browser resolves meddefense-portal.com."
echo "    DNS returns 91.219.236.117."
echo "    TLS connection follows to 91.219.236.117:443."
echo
echo "  Evidence:"
echo "    4x00 browser-history finding"
echo "    4x01 DNS + TLS PCAP timeline"
echo
echo "  ATT&CK:"
echo "    T1566.001 - Spearphishing Link"
echo
echo "  Confidence:"
echo "    CONFIRMED"
echo "    Two independent investigative domains support the event."
echo

echo "[$CRED_TIME] Diane submits credentials to attacker infrastructure"
echo
echo "  Host:"
echo "    WS-RECV-03"
echo
echo "  User:"
echo "    MEDDEFENSE\\dmarsh"
echo
echo "  Destination:"
echo "    meddefense-portal.com /collect.php"
echo "    91.219.236.117:443"
echo
echo "  Network evidence:"
echo "    HTTP POST over TLS"
echo "    743 outbound bytes"
echo "    HTTP 302 redirect to login.microsoft.com"
echo
echo "  Evidence:"
echo "    4x00 credential-exposure investigation"
echo "    4x01 PCAP POST observation"
echo
echo "  ATT&CK:"
echo "    T1078 - Valid Accounts"
echo "    Credential obtained through phishing."
echo
echo "  Confidence:"
echo "    CONFIRMED"
echo "    Convergent 4x00 + 4x01 evidence."
echo
echo "  TEMPORAL ANCHOR:"
echo "    $CRED_TIME"
echo "    This is the exact confirmed credential-exposure timestamp."
echo

echo "Stage-1 interpretation:"
echo
echo "  Diane's credentials were compromised, but the evidence does NOT"
echo "  show persistent attacker access through dmarsh."
echo
echo "  Her password was rapidly rotated and her session revoked."
echo "  The later long-term foothold on WS-RECV-03 is therefore"
echo "  reconstructed through malware deployment, not continuing use"
echo "  of Diane's harvested password."
echo

# ------------------------------------------------------------------
# Transition between stages
# ------------------------------------------------------------------

line
echo "STAGE 1 -> STAGE 2 TRANSITION"
line
echo

echo "Important reconstruction finding:"
echo
echo "  Stage 2 was NOT established directly from the credential POST."
echo
echo "  A second phishing wave delivered the malware approximately"
echo "  one day later."
echo

echo "[$SECOND_WAVE_TIME] Second-wave phishing email E1B arrives"
echo
echo "  Attachment:"
echo "    April-Invoice-MD2026.docm"
echo
echo "  Malware identity:"
echo "    HEALTHBANE_S2_invoice.docm"
echo
echo "  Evidence:"
echo "    previous_findings/4x01_network_timeline.txt"
echo "    previous_findings/4x03_malware_summary.txt"
echo
echo "  Confidence:"
echo "    CONFIRMED"
echo

# ------------------------------------------------------------------
# Stage 2
# ------------------------------------------------------------------

line
echo "STAGE 2: MALWARE DELIVERY AND C2 ESTABLISHMENT"
line
echo

echo "[$PAYLOAD_DNS_TIME] Dropper resolves HEALTHBANE infrastructure"
echo
echo "  Host:"
echo "    WS-RECV-03 (10.10.3.21)"
echo
echo "  User context:"
echo "    Diane Marsh / dmarsh"
echo
echo "  DNS:"
echo "    update.healthbane-c2.net -> 185.220.101.45"
echo
echo "  Evidence:"
echo "    4x01 DNS PCAP"
echo "    4x03 dropper analysis"
echo
echo "  ATT&CK:"
echo "    T1568 - Dynamic Resolution"
echo "    Applicable because malware resolves attacker-controlled"
echo "    infrastructure through DNS before communication."
echo
echo "  Confidence:"
echo "    CONFIRMED"
echo

echo "[$PAYLOAD_GET_TIME] Stage-2 RAT downloaded"
echo
echo "  Host:"
echo "    WS-RECV-03"
echo
echo "  Destination:"
echo "    185.220.101.45:443"
echo
echo "  Request:"
echo "    GET /update/svchost_update.exe"
echo
echo "  Payload:"
echo "    svchost_update.exe"
echo "    287,444 bytes"
echo
echo "  Evidence:"
echo "    4x01 network timeline"
echo "    4x03 malware analysis"
echo
echo "  Confidence:"
echo "    CONFIRMED"
echo

echo "[$FIRST_C2_TIME] First confirmed HEALTHBANE C2 beacon"
echo
echo "  Source:"
echo "    WS-RECV-03 (10.10.3.21)"
echo
echo "  Destination:"
echo "    185.220.101.45:443"
echo
echo "  SNI:"
echo "    sync.healthbane-c2.net"
echo
echo "  Request:"
echo "    POST /api/v1/checkin"
echo
echo "  Traffic:"
echo "    412 bytes outbound"
echo "    96 bytes inbound"
echo
echo "  Payload protection:"
echo "    JSON wrapped with RC4 using a hardcoded symmetric key."
echo
echo "  Beacon pattern:"
echo "    300 +/- 10 seconds"
echo "    Mean observed interval in 4x01: approximately 304 seconds."
echo
echo "  ATT&CK:"
echo "    T1071.001 - Application Layer Protocol: Web Protocols"
echo "    T1573.001 - Encrypted Channel: Symmetric Cryptography"
echo
echo "  Evidence:"
echo "    previous_findings/4x01_network_timeline.txt"
echo "    previous_findings/4x03_malware_summary.txt"
echo
echo "  Confidence:"
echo "    CONFIRMED"
echo

# ------------------------------------------------------------------
# Firewall correlation
# ------------------------------------------------------------------

line
echo "LONGITUDINAL FIREWALL CORRELATION"
line
echo

echo "Firewall collection begins:"
echo "  $FW_START"
echo

echo "IMPORTANT:"
echo "  The IR firewall dataset begins AFTER the first C2 beacon."
echo "  It therefore cannot independently timestamp the initial"
echo "  2026-04-15 C2 establishment."
echo
echo "  Instead, it independently demonstrates persistence of the"
echo "  same C2 pattern into May."
echo

echo "Known C2:"
echo "  Destination: $PRIMARY_C2"
echo "  First seen in 14-day firewall window: $PRIMARY_FIRST_FW"
echo "  Last allowed: $PRIMARY_LAST_FW"
echo "  Sessions: $PRIMARY_COUNT"
echo "  Interval: $PRIMARY_INTERVAL"
echo "  JA3: $PRIMARY_JA3"
echo
echo "  Correlation:"
echo "    Destination matches 4x01."
echo "    5-minute jittered interval matches 4x01."
echo "    JA3 fingerprint matches 4x01."
echo
echo "  Assessment:"
echo "    CONFIRMED persistent HEALTHBANE C2."
echo
echo "  Reconstruction meaning:"
echo "    PCAP proves initial C2 establishment."
echo "    Firewall proves the same C2 remained active weeks later."
echo

# ------------------------------------------------------------------
# Timestamp discrepancy
# ------------------------------------------------------------------

line
echo "TIMESTAMP RECONCILIATION"
line
echo

cat <<'EOF'
4x01 PCAP and later firewall observations use different collection
points.

The IR firewall metadata documents that firewall timestamps are
approximately four seconds ahead of PCAP/Wazuh timestamps because:

  Firewall:
    timestamps the TCP SYN at policy-decision time.

  PCAP / host telemetry:
    timestamps the packet/event when received at its collection point.

Resolution:
  This is normal collection-point variance rather than contradictory
  attacker activity.

Authoritative rule:
  Use the firewall timestamp for connection initiation when the same
  session exists in both sources.

For the FIRST C2 beacon on 2026-04-15, however, only the 4x01 PCAP
covers that period. Therefore the authoritative timestamp remains:

  2026-04-15T08:51:38Z
EOF

echo

# ------------------------------------------------------------------
# Secondary C2
# ------------------------------------------------------------------

line
echo "SECONDARY / FALLBACK C2 ANALYSIS"
line
echo

echo "Destination:"
echo "  $SECONDARY_C2"
echo
echo "First seen:"
echo "  $SECONDARY_FIRST"
echo
echo "Last seen:"
echo "  $SECONDARY_LAST"
echo
echo "Sessions:"
echo "  $SECONDARY_COUNT"
echo
echo "Bytes:"
echo "  Out: $SECONDARY_OUT"
echo "  In:  $SECONDARY_IN"
echo
echo "Pattern:"
echo "  $SECONDARY_PATTERN"
echo

cat <<'EOF'
Stage determination:

  This infrastructure was NOT active during the original Stage-2
  establishment visible in the 4x01 PCAP.

  Primary C2:
    established 2026-04-15.

  Secondary endpoint:
    first observed 2026-05-07.

Therefore 203.0.113.47:8443 must NOT be represented as part of the
initial Stage-2 C2 establishment.

Its first appearance is approximately simultaneous with creation of
the "HealthSync Update Service" scheduled task during the later
post-compromise phase.

ATT&CK:
  T1571 - Non-Standard Port

Role assessment:
  PROBABLE secondary / standby / fallback C2.

Why not CONFIRMED for the exact role?
  Memory and firewall prove attacker-associated communication to the
  endpoint, but they do not expose the encrypted command content
  necessary to prove its exact operational function.
EOF

echo

# ------------------------------------------------------------------
# Duration
# ------------------------------------------------------------------

line
echo "STAGE 1-2 TEMPORAL RELATIONSHIP"
line
echo

echo "Credential exposure:"
echo "  $CRED_TIME"
echo
echo "First confirmed C2 beacon:"
echo "  $FIRST_C2_TIME"
echo
echo "Elapsed time:"
echo "  ${DELTA_HOURS}h ${DELTA_MINUTES}m"
echo

cat <<'EOF'
Interpretation:

  The elapsed time must NOT be described as the attacker spending
  that entire period converting Diane's credential into C2 access.

  Evidence shows a second phishing wave delivered the Stage-2 malware
  on 2026-04-15.

  Therefore the reconstructed chain is:

    E1 credential phishing
            |
            v
    dmarsh credential exposure
            |
            v
    rapid password rotation / session revocation
            |
            v
    second-wave malicious DOCM
            |
            v
    PowerShell/dropper execution
            |
            v
    svchost_update.exe download
            |
            v
    HEALTHBANE RAT execution
            |
            v
    first persistent C2 beacon
EOF

echo

# ------------------------------------------------------------------
# Confidence table
# ------------------------------------------------------------------

line
echo "CONFIDENCE ASSESSMENT"
line
echo

printf "%-29s %-14s %s\n" \
    "Event" "Confidence" "Basis"

printf "%-29s %-14s %s\n" \
    "E1 phishing delivery" "CONFIRMED" "4x00 + 4x01"

printf "%-29s %-14s %s\n" \
    "Diane clicked link" "CONFIRMED" "Browser history + PCAP"

printf "%-29s %-14s %s\n" \
    "Credential submission" "CONFIRMED" "4x00 + 4x01 POST"

printf "%-29s %-14s %s\n" \
    "Second-wave DOCM" "CONFIRMED" "4x01 + 4x03"

printf "%-29s %-14s %s\n" \
    "RAT download" "CONFIRMED" "4x01 + 4x03"

printf "%-29s %-14s %s\n" \
    "Primary C2 established" "CONFIRMED" "4x01 + malware evidence"

printf "%-29s %-14s %s\n" \
    "Primary C2 persistence" "CONFIRMED" "4x01 + IR firewall"

printf "%-29s %-14s %s\n" \
    "Secondary endpoint" "CONFIRMED" "Memory + firewall"

printf "%-29s %-14s %s\n" \
    "Secondary C2 role" "PROBABLE" "Pattern + timing + context"

echo

# ------------------------------------------------------------------
# Final summary
# ------------------------------------------------------------------

line
echo "STAGE 1-2 SUMMARY"
line
echo

cat <<EOF
Temporal anchors:

  Initial malicious email:
    $EMAIL_TIME

  Credential exposure:
    $CRED_TIME

  Second-wave malware delivery:
    $SECOND_WAVE_TIME

  First confirmed C2:
    $FIRST_C2_TIME

  Credential exposure -> first C2:
    ${DELTA_HOURS}h ${DELTA_MINUTES}m

Primary C2:
  $PRIMARY_C2
  sync.healthbane-c2.net
  HTTPS / 443
  5-minute jittered beacon

Secondary endpoint:
  $SECONDARY_C2
  First observed: $SECONDARY_FIRST
  NOT part of initial Stage-2 establishment.
  Appears during the later persistence / post-compromise phase.

ATT&CK techniques:

  T1566.001  Phishing: Spearphishing Link
  T1078      Valid Accounts
  T1568      Dynamic Resolution
  T1071.001  Application Layer Protocol: Web Protocols
  T1573.001  Encrypted Channel: Symmetric Cryptography

Later secondary-channel technique:

  T1571      Non-Standard Port

Overall confidence:
  HIGH

KEY FINDING:

  HEALTHBANE's durable foothold on WS-RECV-03 was established through
  the Stage-2 malware chain, not through prolonged reuse of Diane
  Marsh's harvested credential.

  The primary C2 established on 2026-04-15 remained active into the
  4x05 firewall collection window.

  The 203.0.113.47:8443 channel appeared only on 2026-05-07 and is
  therefore a later redundancy/fallback mechanism rather than part
  of the original Stage-2 C2 establishment.
EOF

echo
line
echo "   Stage 1-2 reconstruction complete."
line