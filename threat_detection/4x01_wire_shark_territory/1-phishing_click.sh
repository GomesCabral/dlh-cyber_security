#!/bin/bash

# Task 1 - The Click in the Wire
# Analyze the phishing click using packet-level evidence.
#
# Usage:
#   ./1-phishing_click.sh phishing_click.pcap

PCAP="$1"
PHISH_DOMAIN="meddefense-portal.com"
PHISH_IP="91.234.99.107"
REAL_DOMAIN="meddefense.com"

if [ -z "$PCAP" ]; then
    echo "Usage: $0 <pcap_file>"
    exit 1
fi

if [ ! -f "$PCAP" ]; then
    echo "Error: PCAP not found: $PCAP"
    exit 1
fi

command -v tshark >/dev/null 2>&1 || {
    echo "Error: tshark is not installed."
    exit 1
}

echo "=== PHISHING CLICK INVESTIGATION ==="
echo "PCAP: $PCAP"
echo

# ---------------------------------------------------------
# DNS RESOLUTION
# ---------------------------------------------------------

echo "=== DNS RESOLUTION ==="

echo "[Filter]"
echo "dns.qry.name == \"$PHISH_DOMAIN\""
echo

tshark -r "$PCAP" \
    -Y "dns.qry.name == \"$PHISH_DOMAIN\"" \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e dns.flags.response \
    -e dns.qry.name \
    -e dns.a \
    -e dns.resp.ttl 2>/dev/null

echo

# ---------------------------------------------------------
# TCP CONNECTION
# ---------------------------------------------------------

echo "=== TCP CONNECTION ==="

echo "[Filter]"
echo "ip.addr == $PHISH_IP && tcp.port == 443"
echo

tshark -r "$PCAP" \
    -Y "ip.addr == $PHISH_IP && tcp.port == 443" \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e tcp.flags.syn \
    -e tcp.flags.ack \
    -e tcp.flags.fin \
    -e tcp.flags.reset \
    -e tcp.stream 2>/dev/null

echo

# ---------------------------------------------------------
# TLS CLIENT HELLO
# ---------------------------------------------------------

echo "=== TLS CLIENT HELLO ==="

echo "[Filter]"
echo "ip.dst == $PHISH_IP && tls.handshake.type == 1"
echo

tshark -r "$PCAP" \
    -Y "ip.dst == $PHISH_IP && tls.handshake.type == 1" \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tls.handshake.extensions_server_name \
    -e tls.handshake.version \
    -e tls.handshake.extensions.supported_version \
    -e tls.handshake.ciphersuite 2>/dev/null

echo

# ---------------------------------------------------------
# TLS CERTIFICATE
# ---------------------------------------------------------

echo "=== TLS CERTIFICATE DETAILS ==="

echo "[Filter]"
echo "ip.src == $PHISH_IP && tls.handshake.type == 11"
echo

tshark -r "$PCAP" \
    -Y "ip.src == $PHISH_IP && tls.handshake.type == 11" \
    -T fields \
    -e frame.time \
    -e x509sat.uTF8String \
    -e x509af.serialNumber \
    -e x509af.validity_element 2>/dev/null

echo

echo "[*] If certificate fields are empty, the certificate details"
echo "    were not available through these dissected fields."
echo "    No certificate information should be invented."
echo

# ---------------------------------------------------------
# DATA EXCHANGE
# ---------------------------------------------------------

echo "=== DATA EXCHANGE ==="

CLIENT_IP=$(tshark -r "$PCAP" \
    -Y "ip.dst == $PHISH_IP && tcp.dstport == 443" \
    -T fields \
    -e ip.src 2>/dev/null |
    grep -v '^$' |
    head -1)

echo "Detected client: ${CLIENT_IP:-unknown}"
echo

if [ -n "$CLIENT_IP" ]; then

    CLIENT_BYTES=$(tshark -r "$PCAP" \
        -Y "ip.src == $CLIENT_IP && ip.dst == $PHISH_IP && tcp.port == 443" \
        -T fields \
        -e tcp.len 2>/dev/null |
        awk '{sum += $1} END {print sum+0}')

    SERVER_BYTES=$(tshark -r "$PCAP" \
        -Y "ip.src == $PHISH_IP && ip.dst == $CLIENT_IP && tcp.port == 443" \
        -T fields \
        -e tcp.len 2>/dev/null |
        awk '{sum += $1} END {print sum+0}')

    CLIENT_SEGMENTS=$(tshark -r "$PCAP" \
        -Y "ip.src == $CLIENT_IP && ip.dst == $PHISH_IP && tcp.len > 0" \
        -T fields \
        -e frame.number 2>/dev/null |
        wc -l)

    SERVER_SEGMENTS=$(tshark -r "$PCAP" \
        -Y "ip.src == $PHISH_IP && ip.dst == $CLIENT_IP && tcp.len > 0" \
        -T fields \
        -e frame.number 2>/dev/null |
        wc -l)

    echo "Client -> Server TCP payload: $CLIENT_BYTES bytes"
    echo "Client -> Server data segments: $CLIENT_SEGMENTS"

    echo "Server -> Client TCP payload: $SERVER_BYTES bytes"
    echo "Server -> Client data segments: $SERVER_SEGMENTS"

    echo
    echo "Largest client TLS/application-data packets:"

    tshark -r "$PCAP" \
        -Y "ip.src == $CLIENT_IP && ip.dst == $PHISH_IP && tcp.len > 0" \
        -T fields \
        -e frame.time \
        -e tcp.len 2>/dev/null |
        sort -t $'\t' -k2,2nr |
        head -5
fi

echo

# ---------------------------------------------------------
# TIMELINE
# ---------------------------------------------------------

echo "=== SESSION TIMELINE ==="

echo "Connection start:"
tshark -r "$PCAP" \
    -Y "ip.dst == $PHISH_IP && tcp.dstport == 443 && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
    -T fields \
    -e frame.time 2>/dev/null |
    head -1

echo "First client data:"
tshark -r "$PCAP" \
    -Y "ip.dst == $PHISH_IP && tcp.dstport == 443 && tcp.len > 0" \
    -T fields \
    -e frame.time 2>/dev/null |
    head -1

echo "Last client/server data:"
tshark -r "$PCAP" \
    -Y "ip.addr == $PHISH_IP && tcp.port == 443 && tcp.len > 0" \
    -T fields \
    -e frame.time 2>/dev/null |
    tail -1

echo "Connection close:"
tshark -r "$PCAP" \
    -Y "ip.addr == $PHISH_IP && tcp.port == 443 && (tcp.flags.fin == 1 || tcp.flags.reset == 1)" \
    -T fields \
    -e frame.time 2>/dev/null |
    tail -1

echo

# ---------------------------------------------------------
# POST-CLICK ACTIVITY
# ---------------------------------------------------------

echo "=== POST-CLICK BEHAVIOR ==="

echo "[Filter]"
echo "dns.qry.name == \"$REAL_DOMAIN\""
echo

tshark -r "$PCAP" \
    -Y "dns.qry.name == \"$REAL_DOMAIN\"" \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e dns.flags.response \
    -e dns.qry.name \
    -e dns.a \
    -e dns.resp.ttl 2>/dev/null

echo

# ---------------------------------------------------------
# CORRELATION
# ---------------------------------------------------------

echo "=== 4x00 CORRELATION ==="

DOMAIN_MATCH=$(tshark -r "$PCAP" \
    -Y "dns.qry.name == \"$PHISH_DOMAIN\"" \
    -T fields \
    -e dns.qry.name 2>/dev/null |
    head -1)

IP_MATCH=$(tshark -r "$PCAP" \
    -Y "ip.addr == $PHISH_IP" \
    -T fields \
    -e ip.dst 2>/dev/null |
    head -1)

if [ -n "$DOMAIN_MATCH" ]; then
    echo "IOC domain observed: YES ($PHISH_DOMAIN)"
else
    echo "IOC domain observed: NO"
fi

if [ -n "$IP_MATCH" ]; then
    echo "IOC IP observed: YES ($PHISH_IP)"
else
    echo "IOC IP observed: NO"
fi

echo
echo "=== ANALYST NOTE ==="
echo "HTTPS payload content is encrypted."
echo "Outbound data volume and timing may be consistent with a form"
echo "submission, but packet metadata alone does not prove that a"
echo "username or password was submitted."
echo
echo "Investigation complete."