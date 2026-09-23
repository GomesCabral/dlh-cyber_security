#!/bin/bash

# Task 4 - The Lateral Trail
# Usage: ./4-lateral_movement.sh lateral_movement.pcap

set -u

PCAP="${1:-}"

if [[ -z "$PCAP" || ! -f "$PCAP" ]]; then
    echo "Usage: $0 <lateral_movement.pcap>"
    exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "Error: tshark is required."
    exit 1
fi

echo "=== LATERAL MOVEMENT INVESTIGATION ==="
echo "PCAP: $PCAP"
echo

# =========================================================
# 1. Cross-subnet traffic
# =========================================================

echo "=== TSHARK FILTERS USED ==="
echo "Cross-subnet:"
echo '(ip.src == 10.10.2.0/24 && ip.dst == 10.10.1.0/24) ||'
echo '(ip.src == 10.10.1.0/24 && !(ip.dst == 10.10.1.0/24))'
echo
echo "RDP: tcp.port == 3389"
echo "SMB: tcp.port == 445 || smb || smb2"
echo "Kerberos: kerberos"
echo "NTLM: ntlmssp"
echo "TCP resets: tcp.flags.reset == 1"
echo

echo "=== CROSS-SUBNET TRAFFIC ==="

CROSS_FILTER='(ip.src == 10.10.2.0/24 && ip.dst == 10.10.1.0/24) || (ip.src == 10.10.1.0/24 && !(ip.dst == 10.10.1.0/24))'

TOTAL_CROSS=$(
    tshark -r "$PCAP" -Y "$CROSS_FILTER" \
        -T fields -e tcp.stream 2>/dev/null |
    awk 'NF' |
    sort -u |
    wc -l
)

PAIRS=$(
    tshark -r "$PCAP" -Y "$CROSS_FILTER" \
        -T fields -e ip.src -e ip.dst 2>/dev/null |
    awk 'NF' |
    sort -u |
    wc -l
)

NURSE_STREAMS=$(
    tshark -r "$PCAP" \
        -Y 'ip.addr == 10.10.2.15 && tcp' \
        -T fields -e tcp.stream 2>/dev/null |
    awk 'NF' |
    sort -u |
    wc -l
)

echo "Total cross-subnet TCP connections: $TOTAL_CROSS"
echo "Unique source-destination pairs: $PAIRS"
echo "TCP connections involving WS-NURSE-04 (10.10.2.15): $NURSE_STREAMS"
echo

echo "Source -> Destination pairs:"
tshark -r "$PCAP" -Y "$CROSS_FILTER" \
    -T fields -e ip.src -e ip.dst 2>/dev/null |
awk 'NF' |
sort -u

echo

# =========================================================
# 2. Authentication activity
# =========================================================

echo "=== AUTHENTICATION EVENTS ==="

echo
echo "--- RDP / NLA ---"
tshark -r "$PCAP" \
    -Y 'tcp.port == 3389' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.flags.syn \
    -e tcp.flags.ack 2>/dev/null |
awk 'NF' |
head -30

echo
echo "--- NTLM ---"
tshark -r "$PCAP" \
    -Y 'ntlmssp' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e ntlmssp.auth.username 2>/dev/null |
awk 'NF'

echo
echo "--- Kerberos ---"
tshark -r "$PCAP" \
    -Y 'kerberos' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e kerberos.CNameString \
    -e kerberos.msg_type 2>/dev/null |
awk 'NF'

echo

# =========================================================
# 3. SMB activity
# =========================================================

echo "=== SMB ACTIVITY ==="

tshark -r "$PCAP" \
    -Y 'smb2 || smb' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e smb2.cmd \
    -e smb2.nt_status \
    -e smb2.tree \
    -e smb2.filename 2>/dev/null |
awk 'NF' |
head -100

echo

# =========================================================
# 4. Failed connections / TCP RST
# =========================================================

echo "=== FAILED / REFUSED CONNECTIONS ==="

tshark -r "$PCAP" \
    -Y 'tcp.flags.reset == 1' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e tcp.srcport \
    -e ip.dst \
    -e tcp.dstport 2>/dev/null |
awk 'NF'

echo

# =========================================================
# 5. SMB Access Denied
# NTSTATUS 0xc0000022 = STATUS_ACCESS_DENIED
# =========================================================

echo "=== SMB ACCESS DENIED ==="

tshark -r "$PCAP" \
    -Y 'smb2.nt_status == 0xc0000022' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e smb2.nt_status \
    -e smb2.filename 2>/dev/null |
awk 'NF'

echo

# =========================================================
# 6. SMB shares / files
# =========================================================

echo "=== SMB SHARES / FILES ==="

tshark -r "$PCAP" \
    -Y 'smb2.tree || smb2.filename' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e smb2.tree \
    -e smb2.filename 2>/dev/null |
awk 'NF' |
sort -u

echo

# =========================================================
# 7. Attack path
# =========================================================

echo "=== ATTACK PATH EVIDENCE ==="

echo
echo "[RDP involving WS-NURSE-04]"
tshark -r "$PCAP" \
    -Y 'ip.src == 10.10.2.15 && tcp.dstport == 3389 && tcp.flags.syn == 1 && tcp.flags.ack == 0' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport 2>/dev/null

echo
echo "[SMB originating from billing-srv-01]"
tshark -r "$PCAP" \
    -Y 'ip.src == 10.10.1.10 && tcp.dstport == 445 && tcp.flags.syn == 1' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport 2>/dev/null

echo

# =========================================================
# 8. Baseline comparison
# =========================================================

echo "=== BASELINE COMPARISON ==="
echo "Task 0 baseline did not establish routine RDP from"
echo "WS-NURSE-04 (10.10.2.15) to billing-srv-01 (10.10.1.10)."
echo
echo "The baseline also did not establish routine SMB enumeration"
echo "from billing-srv-01 across multiple internal systems."
echo
echo "Therefore these patterns should be treated as deviations from"
echo "the observed baseline, not as proof that they never occur."
echo

# =========================================================
# 9. MITRE ATT&CK
# =========================================================

echo "=== MITRE ATT&CK MAPPING ==="
echo "T1078.002  Valid Accounts: Domain Accounts"
echo "T1021.001  Remote Services: Remote Desktop Protocol"
echo "T1021.002  Remote Services: SMB/Windows Admin Shares"
echo "T1135      Network Share Discovery"
echo "T1083      File and Directory Discovery"
echo

echo "=== ANALYST CONCLUSION ==="
echo "Packet evidence shows lateral movement beginning with RDP from"
echo "WS-NURSE-04 (10.10.2.15) to billing-srv-01 (10.10.1.10)."
echo
echo "billing-srv-01 subsequently initiated SMB connections to:"
echo "10.10.1.20, 10.10.1.30, 10.10.1.31, 10.10.4.100,"
echo "10.10.4.101 and 10.10.1.60."
echo
echo "RST traffic was observed immediately after the attempts toward"
echo "10.10.4.100 and 10.10.4.101, indicating those connection"
echo "attempts were refused or blocked."
echo
echo "SMB/NTLM application details were not decoded by tshark in this"
echo "capture, so account names, share names and access-denied results"
echo "are not asserted without packet evidence."