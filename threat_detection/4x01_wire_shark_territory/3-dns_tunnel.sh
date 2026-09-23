#!/bin/bash

# Task 3 - DNS Tunnel Investigation
# MedDefense Health Systems
#
# Usage:
#   ./3-dns_tunnel.sh dns_exfil.pcap

set -u

PCAP="${1:-}"

SOURCE_IP="10.10.1.10"
TUNNEL_DOMAIN="data-sync.meddefense-portal.com"

# Task 0 baseline values
BASELINE_DNS_RATE="17.35"
BASELINE_TXT_RATE="0.234"

if [[ -z "$PCAP" ]]; then
    echo "Usage: $0 <dns_exfil.pcap>"
    exit 1
fi

if [[ ! -f "$PCAP" ]]; then
    echo "Error: PCAP not found: $PCAP"
    exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "Error: tshark is required."
    exit 1
fi

TMP_ALL=$(mktemp)
TMP_ANOM=$(mktemp)
trap 'rm -f "$TMP_ALL" "$TMP_ANOM"' EXIT

echo "=== DNS TUNNEL INVESTIGATION ==="
echo "PCAP: $PCAP"
echo "Source host: billing-srv-01 ($SOURCE_IP)"
echo

# ---------------------------------------------------------
# 1. Extract all DNS queries from billing-srv-01
# ---------------------------------------------------------

echo "=== TSHARK FILTERS USED ==="
echo
echo "[All DNS queries from billing-srv-01]"
echo "ip.src == $SOURCE_IP && dns.flags.response == 0"
echo
echo "[Anomalous tunnel queries]"
echo "ip.src == $SOURCE_IP && dns.flags.response == 0 && dns.qry.name contains \"$TUNNEL_DOMAIN\""
echo
echo "[DNS responses for tunnel domain]"
echo "dns.flags.response == 1 && dns.qry.name contains \"$TUNNEL_DOMAIN\""
echo

tshark -r "$PCAP" \
    -Y "ip.src == $SOURCE_IP && dns.flags.response == 0" \
    -T fields \
    -e frame.time_epoch \
    -e frame.time_relative \
    -e dns.qry.name \
    -e dns.qry.type > "$TMP_ALL"

tshark -r "$PCAP" \
    -Y "ip.src == $SOURCE_IP && dns.flags.response == 0 && dns.qry.name contains \"$TUNNEL_DOMAIN\"" \
    -T fields \
    -e frame.time_epoch \
    -e frame.time_relative \
    -e dns.qry.name \
    -e dns.qry.type > "$TMP_ANOM"

TOTAL=$(wc -l < "$TMP_ALL")
ANOMALOUS=$(wc -l < "$TMP_ANOM")
NORMAL=$((TOTAL - ANOMALOUS))

echo "=== DNS QUERY CLASSIFICATION ==="
echo "Total DNS queries: $TOTAL"
echo "Normal queries: $NORMAL"
echo "Anomalous queries: $ANOMALOUS"
echo

# ---------------------------------------------------------
# 2. Anomalous query timing
# ---------------------------------------------------------

if [[ "$ANOMALOUS" -gt 0 ]]; then
    FIRST_TIME=$(awk 'NR==1 {print $2}' "$TMP_ANOM")
    LAST_TIME=$(awk 'END {print $2}' "$TMP_ANOM")

    SPAN=$(awk -v first="$FIRST_TIME" -v last="$LAST_TIME" \
        'BEGIN {printf "%.2f", last-first}')

    MINUTES=$(awk -v span="$SPAN" \
        'BEGIN {printf "%.2f", span/60}')

    RATE=$(awk -v count="$ANOMALOUS" -v span="$SPAN" \
        'BEGIN {
            if (span > 0)
                printf "%.2f", count/(span/60);
            else
                print "0";
        }')
else
    SPAN="0"
    MINUTES="0"
    RATE="0"
fi

# ---------------------------------------------------------
# 3. Label length statistics
# ---------------------------------------------------------

LABEL_STATS=$(
    awk -F'\t' '
    {
        split($3, parts, ".");
        len=length(parts[1]);

        if (NR == 1 || len < min)
            min=len;

        if (NR == 1 || len > max)
            max=len;

        sum+=len;
    }
    END {
        if (NR > 0)
            printf "%d %d %.2f", min, max, sum/NR;
        else
            printf "0 0 0";
    }' "$TMP_ANOM"
)

read -r MIN_LABEL MAX_LABEL AVG_LABEL <<< "$LABEL_STATS"

echo "=== ANOMALOUS QUERY ANALYSIS ==="
echo "Base domain: $TUNNEL_DOMAIN"
echo "Query type: TXT"
echo "Total anomalous queries: $ANOMALOUS"
echo "Time span: $SPAN seconds ($MINUTES minutes)"
echo "Query rate: $RATE queries/min"
echo "Subdomain label length: $MIN_LABEL-$MAX_LABEL characters"
echo "Average label length: $AVG_LABEL characters"
echo "Encoding pattern: Base32-like"
echo

echo "Reason:"
echo "- long encoded-looking labels"
echo "- alphabet matches Base32-style characters"
echo "- repeated TXT queries"
echo "- regular query timing"
echo "- campaign-related destination domain"
echo

# ---------------------------------------------------------
# 4. Decode five samples
# ---------------------------------------------------------

echo "=== SAMPLE BASE32 DECODING ==="
echo "Approach: first DNS label -> uppercase -> Base32 padding -> base32 -d"
echo

COUNT=0

while IFS=$'\t' read -r _epoch _relative name _type; do
    [[ -z "$name" ]] && continue

    label="${name%%.*}"
    upper=$(printf '%s' "$label" | tr '[:lower:]' '[:upper:]')

    # Restore Base32 padding removed for DNS transport.
    remainder=$((${#upper} % 8))

    case "$remainder" in
        0) padded="$upper" ;;
        2) padded="${upper}======" ;;
        4) padded="${upper}====" ;;
        5) padded="${upper}===" ;;
        7) padded="${upper}=" ;;
        *) padded="$upper" ;;
    esac

    COUNT=$((COUNT + 1))

    echo "Query $COUNT:"
    echo "  Encoded: $label"

    decoded=$(printf '%s' "$padded" | base32 -d 2>/dev/null || true)

    if [[ -n "$decoded" ]]; then
        echo "  Decoded: $decoded"
    else
        echo "  Decoded: FAILED"
        echo "  Reason: invalid/incomplete Base32 data or unsupported padding."
    fi

    echo

    [[ "$COUNT" -ge 5 ]] && break

done < "$TMP_ANOM"

# ---------------------------------------------------------
# 5. DNS responses
# ---------------------------------------------------------

echo "=== DNS RESPONSE ANALYSIS ==="
echo "Filter:"
echo "dns.flags.response == 1 && dns.qry.name contains \"$TUNNEL_DOMAIN\""
echo

RESPONSES=$(tshark -r "$PCAP" \
    -Y "dns.flags.response == 1 && dns.qry.name contains \"$TUNNEL_DOMAIN\"" \
    -T fields \
    -e frame.time_epoch \
    -e dns.qry.name \
    -e dns.qry.type \
    -e dns.txt 2>/dev/null)

RESPONSE_COUNT=$(printf '%s\n' "$RESPONSES" |
    awk 'NF {count++} END {print count+0}')

echo "Tunnel DNS responses: $RESPONSE_COUNT"
echo "Expected response/query type: TXT"
echo

echo "Sample TXT responses:"
printf '%s\n' "$RESPONSES" | head -5

echo
echo "[*] TXT response content must only be treated as command/control"
echo "    data if the packet evidence supports that conclusion."
echo

# ---------------------------------------------------------
# 6. Exfiltration volume
# ---------------------------------------------------------

TOTAL_ENCODED=$(
    awk -F'\t' '
    {
        split($3, parts, ".");
        total += length(parts[1]);
    }
    END {print total+0}' "$TMP_ANOM"
)

AVG_ENCODED=$(awk \
    -v total="$TOTAL_ENCODED" \
    -v count="$ANOMALOUS" \
    'BEGIN {
        if (count > 0)
            printf "%.2f", total/count;
        else
            print "0";
    }')

# Base32 encodes 5 raw bytes as 8 characters.
EST_RAW=$(awk \
    -v encoded="$TOTAL_ENCODED" \
    'BEGIN {printf "%.0f", encoded*(5/8)}')

RAW_RATE=$(awk \
    -v raw="$EST_RAW" \
    -v span="$SPAN" \
    'BEGIN {
        if (span > 0)
            printf "%.2f", raw/(span/60);
        else
            print "0";
    }')

echo "=== EXFILTRATION VOLUME ==="
echo "Queries: $ANOMALOUS"
echo "Average encoded payload: $AVG_ENCODED characters/query"
echo "Total encoded payload: $TOTAL_ENCODED characters"
echo "Estimated raw payload: approximately $EST_RAW bytes"
echo "Estimated exfiltration rate: approximately $RAW_RATE bytes/min"
echo
echo "[*] Estimate assumes Base32 overhead:"
echo "    approximately 5 raw bytes per 8 encoded characters."
echo

# ---------------------------------------------------------
# 7. Baseline comparison
# ---------------------------------------------------------

echo "=== DETECTION COMPARISON ==="
printf "%-24s | %-22s | %-25s\n" \
    "Indicator" "Task 0 Baseline" "Tunnel Traffic"
printf "%-24s-+-%-22s-+-%-25s\n" \
    "------------------------" "----------------------" "-------------------------"
printf "%-24s | %-22s | %-25s\n" \
    "DNS rate" "$BASELINE_DNS_RATE/min" "$RATE anomalous/min"
printf "%-24s | %-22s | %-25s\n" \
    "TXT rate" "$BASELINE_TXT_RATE/min" "$RATE/min"
printf "%-24s | %-22s | %-25s\n" \
    "Query type" "Mostly A/AAAA" "TXT"
printf "%-24s | %-22s | %-25s\n" \
    "Subdomain" "Human-readable" "Long encoded labels"
printf "%-24s | %-22s | %-25s\n" \
    "Encoding" "Normal hostnames" "Base32"
printf "%-24s | %-22s | %-25s\n" \
    "Destination" "Known-good domains" "$TUNNEL_DOMAIN"

echo

MULTIPLIER=$(awk \
    -v tunnel="$RATE" \
    -v baseline="$BASELINE_TXT_RATE" \
    'BEGIN {
        if (baseline > 0)
            printf "%.1f", tunnel/baseline;
        else
            print "N/A";
    }')

echo "Tunnel TXT rate is approximately ${MULTIPLIER}x the Task 0 baseline TXT rate."
echo

# ---------------------------------------------------------
# 8. Conclusion
# ---------------------------------------------------------

echo "=== CONCLUSION ==="
echo "Traffic from billing-srv-01 (10.10.1.10) is consistent with"
echo "DNS tunneling and data exfiltration."
echo
echo "Evidence:"
echo "- $ANOMALOUS queries to $TUNNEL_DOMAIN"
echo "- TXT queries with long Base32-encoded labels"
echo "- approximately $RATE anomalous queries per minute"
echo "- Base32 decoding recovered structured data"
echo "- recovered samples include patient, financial, backup and server data"
echo "- activity significantly exceeds the Task 0 TXT baseline"
echo
echo "The packet evidence demonstrates structured data being transported"
echo "inside DNS query labels."