#!/bin/bash
#
# 11-pcap_investigation.sh
#
# Investigates a single PCAP with tshark and produces a structured finding
# report: conversation statistics, DNS queries, HTTP requests, TLS SNI,
# file-transfer indicators and protocol distribution.
#
# No Suricata, no ruleset, no signature -- just bytes. This is the Tier 2
# follow-up to a Suricata alert (task 9): open the capture, walk the
# protocol stack, and characterize what actually happened.
#
# Usage:
#   ./11-pcap_investigation.sh [path/to/file.pcap]
#
set -uo pipefail
 
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
DEFAULT_PCAP="/home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap"
if [[ -n "${1:-}" ]]; then
  PCAP="$1"
else
  PCAP="$DEFAULT_PCAP"
fi
OUTPUT="${OUTPUT:-${SCRIPT_DIR}/pcap_findings.json}"
TOP_N="${TOP_N:-10}"
 
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
 
command -v tshark >/dev/null 2>&1 || die "tshark is not installed / not on PATH"
command -v jq     >/dev/null 2>&1 || die "jq is required to assemble pcap_findings.json"
[[ -f "$PCAP" ]] || die "PCAP not found: $PCAP"
 
echo "[*] PCAP: $PCAP"
 
# ---------------------------------------------------------------------------
# Duration / packet count (capinfos if available, else derived from tshark)
# ---------------------------------------------------------------------------
if command -v capinfos >/dev/null 2>&1; then
  DURATION="$(capinfos -T -u "$PCAP" 2>/dev/null | tail -1 | awk -F'\t' '{print $2}')"
  PACKET_COUNT="$(capinfos -T -c "$PCAP" 2>/dev/null | tail -1 | awk -F'\t' '{print $2}')"
fi
if [[ -z "${DURATION:-}" || -z "${PACKET_COUNT:-}" ]]; then
  FIRST_LAST="$(tshark -r "$PCAP" -T fields -e frame.time_epoch 2>/dev/null | awk '
    NR==1{first=$1} {last=$1; n++} END{printf "%s %s %s", first, last, n}')"
  read -r FIRST LAST PACKET_COUNT <<< "$FIRST_LAST"
  DURATION="$(awk -v a="$FIRST" -v b="$LAST" 'BEGIN{printf "%.2f", (b-a)}')"
fi
PACKET_COUNT_FMT="$(printf "%'d" "$PACKET_COUNT" 2>/dev/null || echo "$PACKET_COUNT")"
printf '[*] Duration: %s s     Packets: %s\n' "$DURATION" "$PACKET_COUNT_FMT"
 
TMPDIR="$(mktemp -d /tmp/pcap_investigation.XXXXXX)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT
 
# ---------------------------------------------------------------------------
# Helper: parse a `tshark -q -z conv,<proto>` table into JSON rows.
# Columns: srcip, srcport, dstip, dstport, frames_total, bytes_total
# ---------------------------------------------------------------------------
parse_conv() {
  local proto="$1"
  tshark -q -z "conv,${proto}" -r "$PCAP" 2>/dev/null | awk -v proto="$proto" '
    /<->/ {
      # e.g.: 10.10.1.10:53621 <-> 10.10.1.50:443   3 120 bytes   4 178 bytes   7 298 bytes  0.0  0.5
      n = split($0, f, /[ \t]+/)
      left = f[1]; right = f[3]
      split(left, lp, ":"); split(right, rp, ":")
      src_ip = lp[1]; src_port = (length(lp) > 1 ? lp[2] : "")
      dst_ip = rp[1]; dst_port = (length(rp) > 1 ? rp[2] : "")
      # locate the "Total" frames/bytes pair: they are fields 10 and 11
      # (2 fields per side x 3 sides [<-, ->, Total] preceded by the addr fields)
      total_frames = f[10]; total_bytes = f[11]
      gsub(/,/, "", total_frames); gsub(/,/, "", total_bytes)
      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", proto, src_ip, src_port, dst_ip, dst_port, total_frames, total_bytes
    }
  '
}
 
echo -n "[*] Extracting TCP conversations..."
TCP_CONV_RAW="$(parse_conv tcp)"
TCP_CONV_COUNT="$(echo -n "$TCP_CONV_RAW" | grep -c . || true)"
printf '      (%s)\n' "$TCP_CONV_COUNT"
 
echo -n "[*] Extracting UDP conversations..."
UDP_CONV_RAW="$(parse_conv udp)"
UDP_CONV_COUNT="$(echo -n "$UDP_CONV_RAW" | grep -c . || true)"
printf '      (%s)\n' "$UDP_CONV_COUNT"
 
echo -n "[*] Extracting DNS queries..."
DNS_RAW="$(tshark -r "$PCAP" -Y 'dns.flags.response==0' -T fields \
  -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type 2>/dev/null)"
DNS_COUNT="$(echo -n "$DNS_RAW" | grep -c . || true)"
printf '            (%s)\n' "$DNS_COUNT"
 
echo -n "[*] Extracting HTTP requests..."
HTTP_RAW="$(tshark -r "$PCAP" -Y 'http.request' -T fields \
  -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri 2>/dev/null)"
HTTP_COUNT="$(echo -n "$HTTP_RAW" | grep -c . || true)"
printf '            (%s)\n' "$HTTP_COUNT"
 
echo -n "[*] Extracting TLS SNI..."
TLS_RAW="$(tshark -r "$PCAP" -Y 'tls.handshake.type==1' -T fields \
  -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null)"
TLS_COUNT="$(echo -n "$TLS_RAW" | grep -c . || true)"
printf '                   (%s)\n' "$TLS_COUNT"
 
echo -n "[*] Extracting file transfers..."
FILES_RAW="$(tshark -r "$PCAP" -Y 'http.content_type or smb2.filename' -T fields \
  -e frame.time_epoch -e ip.src -e ip.dst -e http.file_data -e smb2.filename 2>/dev/null)"
FILES_COUNT="$(echo -n "$FILES_RAW" | grep -c . || true)"
printf '            (%s)\n' "$FILES_COUNT"
 
echo -n "[*] Protocol distribution..."
PHS_RAW="$(tshark -q -z io,phs -r "$PCAP" 2>/dev/null)"
# Build a rough top-level percentage summary (tcp/udp/icmp/other, relative to total frames)
PHS_SUMMARY="$(echo "$PHS_RAW" | awk -v total="$PACKET_COUNT" '
  BEGIN{tcp=0; udp=0; icmp=0}
  /^  tcp / {tcp=$2; gsub("frames:","",tcp)}
  /^  udp / {udp=$2; gsub("frames:","",tcp)}
  /^  udp / {udp=$2; gsub("frames:","",udp)}
  /^  icmp / {icmp=$2; gsub("frames:","",icmp)}
  END{
    if (total+0 == 0) { print "n/a"; exit }
    other = total - tcp - udp - icmp
    printf "tcp %.0f%%, udp %.0f%%, icmp %.0f%%, other %.0f%%", \
      (tcp/total)*100, (udp/total)*100, (icmp/total)*100, (other/total)*100
  }')"
printf '     (%s)\n' "$PHS_SUMMARY"
 
# ---------------------------------------------------------------------------
# Aggregate raw per-4-tuple conversation rows by unordered {ip_a, ip_b, proto}
# so the human summary reads as "host <-> host", matching how an analyst
# actually talks about a conversation rather than a single TCP/UDP socket.
# ---------------------------------------------------------------------------
aggregate_top_conversations() {
  { echo -n "$TCP_CONV_RAW"; echo; echo -n "$UDP_CONV_RAW"; } | awk -F'\t' '
    NF>=7 {
      proto=$1; a=$2; b=$4; frames=$6; bytes=$7
      # unordered pair key: sort the two IPs so A<->B and B<->A collapse together
      if (a < b) { key = proto SUBSEP a SUBSEP b } else { key = proto SUBSEP b SUBSEP a }
      fsum[key] += frames
      bsum[key] += bytes
      ipa[key] = (a < b ? a : b)
      ipb[key] = (a < b ? b : a)
      pr[key] = proto
    }
    END {
      for (k in fsum) {
        printf "%s\t%s\t%s\t%s\t%s\n", pr[k], ipa[k], ipb[k], fsum[k], bsum[k]
      }
    }' | sort -t$'\t' -k4,4nr
}
 
TOP_CONV="$(aggregate_top_conversations)"
 
human_bytes() {
  awk -v b="$1" 'BEGIN{
    if (b >= 1048576) printf "%.1f MB", b/1048576
    else if (b >= 1024) printf "%.0f KB", b/1024
    else printf "%.0f B", b
  }'
}
 
echo "Top conversations:"
echo "$TOP_CONV" | head -5 | while IFS=$'\t' read -r proto ipa ipb frames bytes; do
  [[ -z "$proto" ]] && continue
  frames_fmt="$(printf "%'d" "$frames" 2>/dev/null || echo "$frames")"
  bytes_fmt="$(human_bytes "$bytes")"
  printf '  %-15s <-> %-15s %-4s %8s pkts  %8s\n' "$ipa" "$ipb" "$proto" "$frames_fmt" "$bytes_fmt"
done
 
echo "Long DNS labels (> 50 chars):"
LONG_LABELS="$(echo "$DNS_RAW" | awk -F'\t' '
  NF>=3 {
    split($3, labels, ".")
    leftmost = labels[1]
    if (length(leftmost) > 50) printf "%s\t%d\n", $3, length(leftmost)
  }' | sort -u)"
if [[ -n "$LONG_LABELS" ]]; then
  echo "$LONG_LABELS" | while IFS=$'\t' read -r qname len; do
    [[ -z "$qname" ]] && continue
    printf '  %s  (%s chars)\n' "$qname" "$len"
  done
else
  echo "  (none)"
fi
 
# ---------------------------------------------------------------------------
# Build pcap_findings.json. Every field is always present, even if empty --
# a query that returns zero rows still yields an empty JSON array, never a
# missing key (per the task's resilience requirement).
# ---------------------------------------------------------------------------
tsv_to_json() {
  # $1 = raw TSV text, remaining args = field names (in column order)
  local raw="$1"; shift
  local fields=("$@")
  if [[ -z "$raw" ]]; then
    echo "[]"
    return
  fi
  echo "$raw" | awk -F'\t' -v OFS='\t' 'NF>0' | jq -R -s --argjson keys "$(printf '%s\n' "${fields[@]}" | jq -R . | jq -s .)" '
    split("\n") | map(select(length > 0)) | map(
      split("\t") as $cols |
      reduce range(0; ($keys | length)) as $i ({}; . + {($keys[$i]): ($cols[$i] // "")})
    )
  '
}
 
TCP_CONV_JSON="$(tsv_to_json "$TCP_CONV_RAW" proto src_ip src_port dst_ip dst_port frames bytes)"
UDP_CONV_JSON="$(tsv_to_json "$UDP_CONV_RAW" proto src_ip src_port dst_ip dst_port frames bytes)"
TOP_CONV_JSON="$(tsv_to_json "$TOP_CONV" proto ip_a ip_b frames bytes)"
DNS_JSON="$(tsv_to_json "$DNS_RAW" time_epoch src_ip query_name query_type)"
HTTP_JSON="$(tsv_to_json "$HTTP_RAW" time_epoch src_ip dst_ip host method uri)"
TLS_JSON="$(tsv_to_json "$TLS_RAW" time_epoch src_ip dst_ip sni)"
FILES_JSON="$(tsv_to_json "$FILES_RAW" time_epoch src_ip dst_ip http_file_data smb2_filename)"
LONG_LABELS_JSON="$(tsv_to_json "$LONG_LABELS" query_name leftmost_label_length)"
 
# top 10 per protocol, sorted by total bytes
TCP_CONV_TOP10="$(echo "$TCP_CONV_JSON" | jq '[.[] | .bytes |= (tonumber? // 0)] | sort_by(-.bytes) | .[:10]')"
UDP_CONV_TOP10="$(echo "$UDP_CONV_JSON" | jq '[.[] | .bytes |= (tonumber? // 0)] | sort_by(-.bytes) | .[:10]')"
TOP_CONV_TOP10="$(echo "$TOP_CONV_JSON" | jq '[.[] | .bytes |= (tonumber? // 0) | .frames |= (tonumber? // 0)] | sort_by(-.frames) | .[:10]')"
 
jq -n \
  --arg pcap "$PCAP" \
  --arg duration_seconds "$DURATION" \
  --argjson packet_count "${PACKET_COUNT:-0}" \
  --arg protocol_distribution_summary "$PHS_SUMMARY" \
  --arg protocol_hierarchy_raw "$PHS_RAW" \
  --argjson tcp_conversations "$TCP_CONV_TOP10" \
  --argjson udp_conversations "$UDP_CONV_TOP10" \
  --argjson top_conversations "$TOP_CONV_TOP10" \
  --argjson dns_queries "$DNS_JSON" \
  --argjson http_requests "$HTTP_JSON" \
  --argjson tls_sni "$TLS_JSON" \
  --argjson file_transfers "$FILES_JSON" \
  --argjson long_dns_labels "$LONG_LABELS_JSON" \
  '{
    pcap: $pcap,
    duration_seconds: ($duration_seconds | tonumber? // $duration_seconds),
    packet_count: $packet_count,
    protocol_distribution: {
      summary: $protocol_distribution_summary,
      raw: $protocol_hierarchy_raw
    },
    tcp_conversations: $tcp_conversations,
    udp_conversations: $udp_conversations,
    top_conversations: $top_conversations,
    dns_queries: $dns_queries,
    long_dns_labels: $long_dns_labels,
    http_requests: $http_requests,
    tls_sni: $tls_sni,
    file_transfers: $file_transfers
  }' > "$OUTPUT"
 
echo
echo "[*] Wrote $OUTPUT"