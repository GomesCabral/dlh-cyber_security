#!/bin/bash

# Task 0 - Clinical Network Baseline Analysis
# Usage: ./0-baseline_analysis.sh normal_baseline_clinical.pcap

PCAP="$1"
OUTPUT="baseline_clinical.json"

if [ -z "$PCAP" ]; then
    echo "Usage: $0 <pcap_file>"
    exit 1
fi

if [ ! -f "$PCAP" ]; then
    echo "Error: PCAP file not found: $PCAP"
    exit 1
fi

command -v tshark >/dev/null 2>&1 || {
    echo "Error: tshark is not installed."
    exit 1
}

echo "=== PCAP INFORMATION ==="

TOTAL=$(tshark -r "$PCAP" -T fields -e frame.number 2>/dev/null | wc -l)

FIRST_TS=$(tshark -r "$PCAP" -T fields -e frame.time_epoch 2>/dev/null | head -1)
LAST_TS=$(tshark -r "$PCAP" -T fields -e frame.time_epoch 2>/dev/null | tail -1)

DURATION=$(awk -v first="$FIRST_TS" -v last="$LAST_TS" \
    'BEGIN {printf "%.2f", last-first}')

echo "Packets: $TOTAL"
echo "Duration: $DURATION seconds"

echo
echo "=== PROTOCOL DISTRIBUTION ==="
echo "Filter: tcp"
TCP=$(tshark -r "$PCAP" -Y "tcp" -T fields -e frame.number 2>/dev/null | wc -l)

echo "Filter: udp"
UDP=$(tshark -r "$PCAP" -Y "udp" -T fields -e frame.number 2>/dev/null | wc -l)

echo "Filter: icmp || icmpv6"
ICMP=$(tshark -r "$PCAP" -Y "icmp || icmpv6" -T fields -e frame.number 2>/dev/null | wc -l)

OTHER=$((TOTAL - TCP - UDP - ICMP))

awk -v total="$TOTAL" -v tcp="$TCP" -v udp="$UDP" \
    -v icmp="$ICMP" -v other="$OTHER" '
BEGIN {
    printf "TCP:   %.2f%% (%d packets)\n", tcp/total*100, tcp
    printf "UDP:   %.2f%% (%d packets)\n", udp/total*100, udp
    printf "ICMP:  %.2f%% (%d packets)\n", icmp/total*100, icmp
    printf "Other: %.2f%% (%d packets)\n", other/total*100, other
}'

echo
echo "=== APPLICATION BREAKDOWN ==="

declare -A FILTERS=(
    ["HTTPS"]="tcp.port == 443"
    ["DNS"]="udp.port == 53 || tcp.port == 53"
    ["Kerberos"]="tcp.port == 88 || udp.port == 88"
    ["LDAP"]="tcp.port == 389 || udp.port == 389"
    ["SMB"]="tcp.port == 445"
    ["NTP"]="udp.port == 123"
    ["Printing"]="tcp.port == 9100"
)

for SERVICE in HTTPS DNS Kerberos LDAP SMB NTP Printing; do
    FILTER="${FILTERS[$SERVICE]}"
    COUNT=$(tshark -r "$PCAP" -Y "$FILTER" \
        -T fields -e frame.number 2>/dev/null | wc -l)

    PERCENT=$(awk -v count="$COUNT" -v total="$TOTAL" \
        'BEGIN {printf "%.2f", count/total*100}')

    printf "%-12s %6s%% (%d packets)\n" \
        "$SERVICE" "$PERCENT" "$COUNT"
done

echo
echo "=== TOP 10 SOURCE IPS BY BYTES ==="
echo "Fields: ip.src + frame.len"

tshark -r "$PCAP" \
    -Y "ip.src" \
    -T fields \
    -e ip.src \
    -e frame.len 2>/dev/null |
awk 'NF >= 2 {bytes[$1]+=$2}
END {
    for (ip in bytes)
        print bytes[ip], ip
}' |
sort -nr |
head -10 |
awk '{printf "%-16s %.2f MB\n", $2, $1/1024/1024}'

echo
echo "=== TOP 10 DESTINATION IPS ==="
echo "Fields: ip.dst + tcp.stream"

tshark -r "$PCAP" \
    -Y "ip.dst && tcp" \
    -T fields \
    -e ip.dst \
    -e tcp.stream 2>/dev/null |
awk 'NF >= 2 {key=$1 FS $2; if (!seen[key]++) count[$1]++}
END {
    for (ip in count)
        print count[ip], ip
}' |
sort -nr |
head -10

echo
echo "=== DNS QUERY PROFILE ==="
echo "Filter: dns.flags.response == 0"

DNS_FILE=$(mktemp)

tshark -r "$PCAP" \
    -Y "dns.flags.response == 0" \
    -T fields \
    -e frame.time_epoch \
    -e dns.qry.name \
    -e dns.qry.type 2>/dev/null > "$DNS_FILE"

DNS_TOTAL=$(awk 'NF >= 2' "$DNS_FILE" | wc -l)

echo "Total DNS queries: $DNS_TOTAL"

if awk -v d="$DURATION" 'BEGIN {exit !(d > 0)}'; then
    DNS_RATE=$(awk -v q="$DNS_TOTAL" -v d="$DURATION" \
        'BEGIN {printf "%.2f", q/(d/60)}')
else
    DNS_RATE="0"
fi

echo "Average DNS queries/min: $DNS_RATE"

echo
echo "Top 20 queried domains:"
awk 'NF >= 2 {print $2}' "$DNS_FILE" |
sort |
uniq -c |
sort -nr |
head -20

echo
echo "DNS Query Types:"
awk '
$3 == 1  {a++}
$3 == 28 {aaaa++}
$3 == 16 {txt++}
$3 == 15 {mx++}
END {
    printf "A: %d\n", a
    printf "AAAA: %d\n", aaaa
    printf "TXT: %d\n", txt
    printf "MX: %d\n", mx
}' "$DNS_FILE"

TXT_COUNT=$(awk '$3 == 16 {count++} END {print count+0}' "$DNS_FILE")

TXT_RATE=$(awk -v q="$TXT_COUNT" -v d="$DURATION" \
    'BEGIN {
        if (d > 0)
            printf "%.3f", q/(d/60)
        else
            print "0"
    }')

echo "TXT queries: $TXT_COUNT"
echo "TXT queries/min: $TXT_RATE"

echo
echo "=== TLS ANALYSIS ==="

echo
echo "Observed SNI values:"
echo "Filter: tls.handshake.extensions_server_name"

tshark -r "$PCAP" \
    -Y "tls.handshake.extensions_server_name" \
    -T fields \
    -e tls.handshake.extensions_server_name 2>/dev/null |
sort -u

echo
echo "Observed TLS versions:"

tshark -r "$PCAP" \
    -Y "tls" \
    -T fields \
    -e tls.record.version 2>/dev/null |
grep -v '^$' |
sort |
uniq -c |
sort -nr

echo
echo "Certificate issuers where available:"

tshark -r "$PCAP" \
    -Y "x509sat.uTF8String" \
    -T fields \
    -e x509sat.uTF8String 2>/dev/null |
grep -v '^$' |
sort -u |
head -20

echo
echo "=== CONNECTION DURATION DISTRIBUTION ==="
echo "Using TCP stream first/last packet timestamps"

tshark -r "$PCAP" \
    -Y "tcp" \
    -T fields \
    -e tcp.stream \
    -e frame.time_epoch 2>/dev/null |
awk '
NF >= 2 {
    stream=$1
    time=$2

    if (!(stream in first))
        first[stream]=time

    last[stream]=time
}
END {
    short=0
    medium=0
    long=0

    for (s in first) {
        duration=last[s]-first[s]

        if (duration < 1)
            short++
        else if (duration <= 30)
            medium++
        else
            long++
    }

    total=short+medium+long

    if (total > 0) {
        printf "Short (<1s):    %.2f%% (%d)\n", short/total*100, short
        printf "Medium (1-30s): %.2f%% (%d)\n", medium/total*100, medium
        printf "Long (>30s):    %.2f%% (%d)\n", long/total*100, long
    }
}'

echo
echo "=== TEMPORAL PATTERN ==="
echo "Packets per one-minute bin:"

tshark -r "$PCAP" \
    -T fields \
    -e frame.time_epoch 2>/dev/null |
awk '
NF {
    minute=int($1/60)*60
    count[minute]++
}
END {
    for (m in count)
        print m, count[m]
}' |
sort -n |
while read -r TS COUNT; do
    DATE=$(date -d "@$TS" "+%Y-%m-%d %H:%M" 2>/dev/null || echo "$TS")
    echo "$DATE  $COUNT packets"
done

echo
echo "=== BASELINE SIGNATURES ==="
echo "Normal DNS rate: $DNS_RATE queries/min"
echo "Normal TXT rate: $TXT_RATE queries/min"
echo "Total baseline packets: $TOTAL"
echo "Capture duration: $DURATION seconds"

echo
echo "Known-good DNS domains:"
awk 'NF >= 2 {print $2}' "$DNS_FILE" |
sort |
uniq -c |
sort -nr |
head -20

echo
echo "Known-good TLS SNI:"
tshark -r "$PCAP" \
    -Y "tls.handshake.extensions_server_name" \
    -T fields \
    -e tls.handshake.extensions_server_name 2>/dev/null |
sort -u |
head -30

echo
echo "=== SAVING BASELINE ==="

cat > "$OUTPUT" <<EOF
{
  "pcap": "$PCAP",
  "total_packets": $TOTAL,
  "duration_seconds": $DURATION,
  "dns_queries": $DNS_TOTAL,
  "dns_queries_per_minute": $DNS_RATE,
  "txt_queries": $TXT_COUNT,
  "txt_queries_per_minute": $TXT_RATE
}
EOF

rm -f "$DNS_FILE"

echo "BASELINE SAVED: $OUTPUT"
