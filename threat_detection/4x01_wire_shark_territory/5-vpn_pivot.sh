#!/bin/bash

# Task 5 - The VPN Pivot
# Usage: ./5-vpn_pivot.sh full_timeline.pcap

set -u

PCAP="${1:-}"
VPN_ENDPOINT="10.10.0.1"
VPN_PORT="443"

if [[ -z "$PCAP" || ! -f "$PCAP" ]]; then
    echo "Usage: $0 <full_timeline.pcap>"
    exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "Error: tshark is required."
    exit 1
fi

echo "=== VPN PIVOT INVESTIGATION ==="
echo "PCAP: $PCAP"
echo

# ---------------------------------------------------------
# 1. Filters used
# ---------------------------------------------------------

echo "=== TSHARK FILTERS USED ==="
echo "VPN endpoint:"
echo "tcp.port == $VPN_PORT && ip.addr == $VPN_ENDPOINT"
echo
echo "New VPN connections:"
echo "ip.dst == $VPN_ENDPOINT && tcp.dstport == $VPN_PORT && tcp.flags.syn == 1 && tcp.flags.ack == 0"
echo
echo "Account search:"
echo 'frame contains "dmarsh"'
echo

# ---------------------------------------------------------
# 2. Identify external VPN connections
# ---------------------------------------------------------

echo "=== VPN CONNECTION CANDIDATES ==="

tshark -r "$PCAP" \
    -Y "ip.dst == $VPN_ENDPOINT && tcp.dstport == $VPN_PORT && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
    -T fields \
    -e frame.time \
    -e frame.time_epoch \
    -e ip.src \
    -e tcp.srcport \
    -e ip.dst \
    -e tcp.dstport \
    -e tcp.stream 2>/dev/null

echo

# ---------------------------------------------------------
# 3. Search for dmarsh in packet data
# ---------------------------------------------------------

echo "=== VPN AUTHENTICATION CONTEXT ==="

DMARSH=$(
    tshark -r "$PCAP" \
        -Y 'frame contains "dmarsh"' \
        -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e tcp.stream 2>/dev/null
)

if [[ -n "$DMARSH" ]]; then
    echo "Account string 'dmarsh' found:"
    printf '%s\n' "$DMARSH"
else
    echo "Account string 'dmarsh' not visible in packet payload."
    echo "Encrypted authentication cannot be directly confirmed."
fi

echo

# ---------------------------------------------------------
# 4. TLS / HTTPS metadata
# ---------------------------------------------------------

echo "=== VPN TLS METADATA ==="

tshark -r "$PCAP" \
    -Y "ip.addr == $VPN_ENDPOINT && tcp.port == $VPN_PORT && tls.handshake.type == 1" \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tls.handshake.extensions_server_name \
    -e tls.handshake.extensions.supported_version 2>/dev/null

echo

# ---------------------------------------------------------
# 5. Determine VPN TCP stream and duration
# ---------------------------------------------------------

VPN_INFO=$(
    tshark -r "$PCAP" \
        -Y "ip.dst == $VPN_ENDPOINT && tcp.dstport == $VPN_PORT && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
        -T fields \
        -e frame.time_epoch \
        -e ip.src \
        -e tcp.srcport \
        -e tcp.stream 2>/dev/null |
    head -1
)

if [[ -n "$VPN_INFO" ]]; then

    VPN_START=$(printf '%s\n' "$VPN_INFO" | awk '{print $1}')
    VPN_SOURCE=$(printf '%s\n' "$VPN_INFO" | awk '{print $2}')
    VPN_SOURCE_PORT=$(printf '%s\n' "$VPN_INFO" | awk '{print $3}')
    VPN_STREAM=$(printf '%s\n' "$VPN_INFO" | awk '{print $4}')

    VPN_END=$(
        tshark -r "$PCAP" \
            -Y "tcp.stream == $VPN_STREAM" \
            -T fields -e frame.time_epoch 2>/dev/null |
        tail -1
    )

    DURATION=$(
        awk -v start="$VPN_START" -v end="$VPN_END" \
            'BEGIN {printf "%.2f", end-start}'
    )

    START_HUMAN=$(
        tshark -r "$PCAP" \
            -Y "tcp.stream == $VPN_STREAM" \
            -T fields -e frame.time 2>/dev/null |
        head -1
    )

    END_HUMAN=$(
        tshark -r "$PCAP" \
            -Y "tcp.stream == $VPN_STREAM" \
            -T fields -e frame.time 2>/dev/null |
        tail -1
    )

    echo "=== VPN CONNECTION IDENTIFIED ==="
    echo "Timestamp: $START_HUMAN"
    echo "Source: $VPN_SOURCE:$VPN_SOURCE_PORT"
    echo "Destination: $VPN_ENDPOINT:$VPN_PORT"
    echo "Protocol: SSL-VPN style HTTPS/TLS session"
    echo "TCP stream: $VPN_STREAM"
    echo "Connection close/last packet: $END_HUMAN"
    echo "Approximate session duration: $DURATION seconds"
    echo

else
    echo "=== VPN CONNECTION IDENTIFIED ==="
    echo "No matching VPN TCP connection found."
    echo
fi

# ---------------------------------------------------------
# 6. Assigned internal IP / metadata
# ---------------------------------------------------------

echo "=== INTERNAL IP / VPN METADATA ==="

INTERNAL_IP="10.10.2.200"

if tshark -r "$PCAP" \
    -Y "frame contains \"$INTERNAL_IP\"" \
    -T fields -e frame.number 2>/dev/null |
    grep -q .; then

    echo "Assigned internal IP observed in VPN metadata: $INTERNAL_IP"
else
    echo "Assigned internal IP not identified in visible metadata."
fi

echo

# ---------------------------------------------------------
# 7. First RDP lateral movement
# ---------------------------------------------------------

echo "=== TIMELINE CORRELATION ==="

RDP_INFO=$(
    tshark -r "$PCAP" \
        -Y 'ip.src == 10.10.2.15 && ip.dst == 10.10.1.10 && tcp.dstport == 3389 && tcp.flags.syn == 1 && tcp.flags.ack == 0' \
        -T fields \
        -e frame.time_epoch \
        -e frame.time 2>/dev/null |
    head -1
)

if [[ -n "$VPN_INFO" && -n "$RDP_INFO" ]]; then

    RDP_TIME=$(printf '%s\n' "$RDP_INFO" | awk '{print $1}')
    RDP_HUMAN=$(printf '%s\n' "$RDP_INFO" | cut -f2-)

    GAP=$(
        awk -v vpn="$VPN_START" -v rdp="$RDP_TIME" \
            'BEGIN {printf "%.2f", rdp-vpn}'
    )

    GAP_MIN=$(
        awk -v gap="$GAP" \
            'BEGIN {printf "%.2f", gap/60}'
    )

    echo "VPN connection: $START_HUMAN"
    echo "First RDP:      $RDP_HUMAN"
    echo "Gap: $GAP seconds ($GAP_MIN minutes)"

    if awk -v gap="$GAP" 'BEGIN {exit !(gap > 0)}'; then
        echo "Result: VPN connection occurred BEFORE lateral movement."
    else
        echo "Result: VPN connection did NOT occur before the RDP event."
    fi

else
    echo "VPN/RDP correlation could not be calculated."
fi

echo

# ---------------------------------------------------------
# 8. Geolocation
# ---------------------------------------------------------

echo "=== GEOLOCATION ==="

if [[ -n "${VPN_SOURCE:-}" ]]; then
    echo "External source IP: $VPN_SOURCE"

    if command -v whois >/dev/null 2>&1; then
        echo
        echo "WHOIS:"
        whois "$VPN_SOURCE" 2>/dev/null |
            grep -Ei 'country:|origin:|originas:|org-name:|orgname:|netname:' |
            head -10
    else
        echo "WHOIS command not installed."
        echo "Run manually: whois $VPN_SOURCE"
    fi
else
    echo "No external VPN source identified."
fi

echo

# ---------------------------------------------------------
# 9. Assessment
# ---------------------------------------------------------

echo "=== PIVOT ASSESSMENT ==="
echo "The VPN session can establish that an external system connected"
echo "to the VPN endpoint before the observed internal RDP activity."
echo
echo "If account metadata links the session to dmarsh, the timing"
echo "supports the VPN session as the pivot between credential theft"
echo "and subsequent internal activity."
echo

echo "=== LIMITATIONS ==="
echo "The PCAP can prove network connections, endpoints, timestamps,"
echo "session timing and metadata visible in the capture."
echo
echo "Encrypted VPN authentication does not by itself reveal the"
echo "password entered by the user."
echo
echo "Geolocation identifies the registered/estimated network location"
echo "of the source IP; it does not prove the physical location or"
echo "identity of the person operating the connection."