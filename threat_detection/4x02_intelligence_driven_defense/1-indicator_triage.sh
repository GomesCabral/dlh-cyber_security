#!/bin/bash
set -euo pipefail

# Task 1 — Signal vs Noise
# HEALTHBANE indicator triage
#
# Usage:
#   ./1-indicator_triage.sh
#   ./1-indicator_triage.sh > 1-indicator_triage.txt
#
# The script expects Task 0 and the commercial feed in the current directory.
# It preserves the evidence discrepancy documented in Task 0: the supplied
# source files yield 49 distinct literal indicator values, while the lab
# reference states 64 unique indicators.

INTAKE="${INTAKE:-0-intel_intake.md}"
FEED="${FEED:-commercial_feed_extract.json}"

[[ -f "$INTAKE" ]] || { echo "ERROR: $INTAKE not found" >&2; exit 1; }
[[ -f "$FEED" ]] || { echo "ERROR: $FEED not found" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || {
    echo "ERROR: jq is required to parse $FEED" >&2
    exit 1
}

jq empty "$FEED" >/dev/null

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# type|value|sources|category|justification|confidence|uncertainty
#
# Classification principles:
# ACTIONABLE = safe/useful for immediate detection, hunting or tightly scoped blocking.
# CONTEXTUAL = useful for enrichment/historical correlation, but not strong enough
#              for direct blocking by itself.
# NOISE      = overbroad/shared/weakly clustered or otherwise unsafe operationally.
#
# ACTIONABLE does NOT automatically mean "block everywhere".

cat > "$tmp" <<'EOF'
domain|meddefense-portal.com|HC3;Commercial;Researcher;MedDefense|ACTIONABLE|Confirmed phishing domain corroborated by government, commercial, researcher and internal evidence.|HIGH|false
domain|medequip-supplies.net|HC3;Commercial;Researcher;MedDefense|ACTIONABLE|Confirmed healthcare-themed phishing infrastructure corroborated across four sources.|HIGH|false
domain|meddefense-benefits.org|HC3;Commercial;MedDefense|ACTIONABLE|Confirmed Stage 1 phishing domain observed internally and by HC3.|HIGH|false
domain|outlook-protection.com|HC3;Commercial;Researcher|ACTIONABLE|Confirmed lookalike credential-harvesting domain; valid SPF/DKIM does not make the impersonation benign.|HIGH|false
domain|healthbane-c2.net|HC3;Commercial;Researcher|ACTIONABLE|High-confidence Stage 2/3 C2 domain corroborated by multiple independent sources.|HIGH|false
domain|data-sync.healthbane-c2.net|HC3;Commercial|ACTIONABLE|Confirmed DNS-tunneling domain used for Stage 3 exfiltration.|HIGH|false
domain|update-healthbane.net|HC3;Commercial|ACTIONABLE|Stage 2 infrastructure reported by HC3 and commercial intelligence.|MEDIUM|true
domain|portal-secure-meddefense.com|HC3;Researcher|ACTIONABLE|HC3 reports Stage 1 infrastructure and researcher observed it staged in the phishing kit.|MEDIUM|true
domain|rx-benefits-portal.com|Commercial|CONTEXTUAL|Predates the HEALTHBANE window and is linked mainly by infrastructure pattern; useful for historical hunting.|MEDIUM|true
domain|healthcare-login.com|Commercial|CONTEXTUAL|Sinkholed domain is useful for historical correlation but no longer appropriate as an active blocking signal.|MEDIUM|true
domain|verify-health-portal.net|Commercial|CONTEXTUAL|Registered during campaign window with matching naming pattern, but no active phishing was observed.|MEDIUM|true
domain|secure-insurance-login.com|Commercial|NOISE|Only ML name-similarity clustering supports association and no human review was performed.|LOW|true
domain|claims-verify-portal.net|Commercial|NOISE|Keyword-only clustering provides weak evidence of attacker association.|LOW|true
ip|91.234.99.107|HC3;Commercial;Researcher;MedDefense|ACTIONABLE|Confirmed attacker infrastructure corroborated across all four intelligence sources.|HIGH|false
ip|185.176.43.22|HC3;Commercial;MedDefense|ACTIONABLE|Confirmed Stage 1 phishing infrastructure with HC3 and internal corroboration.|HIGH|false
ip|164.90.218.73|HC3;Commercial;MedDefense|ACTIONABLE|Confirmed Stage 1 infrastructure observed by HC3 and MedDefense.|HIGH|false
ip|51.38.42.17|HC3;Commercial|ACTIONABLE|HC3 high-confidence Stage 1 IP corroborated by the commercial feed.|HIGH|false
ip|51.38.42.191|HC3;Commercial;Researcher|ACTIONABLE|Confirmed Stage 2/3 C2 and DNS-tunneling infrastructure.|HIGH|false
ip|45.77.218.9|HC3;Commercial|ACTIONABLE|HC3 identifies this as Stage 2 infrastructure, though with lower confidence than core C2 IPs.|MEDIUM|true
ip|159.89.112.45|Commercial|NOISE|DigitalOcean shared IP hosts 200+ unrelated sites; blocking would create broad false positives.|HIGH|false
ip|23.94.138.222|Commercial|CONTEXTUAL|Possible bulletproof-hosting relationship but association is similarity-based and uncorroborated.|LOW|true
ip|104.168.34.58|Commercial|NOISE|Healthcare-keyword/ML clustering without external corroboration is insufficient for operational use.|LOW|true
ip|167.71.222.30|Commercial;Researcher|CONTEXTUAL|Researcher labels this only as an operator-overlap hypothesis and commercial confidence is low.|LOW|true
ip|192.99.207.114|Commercial|NOISE|Shared OVH CDN infrastructure is explicitly identified by the feed as likely noise.|HIGH|false
ip|20.83.144.56|Commercial|NOISE|Azure CDN/shared infrastructure is unsafe to block and is explicitly marked DO NOT BLOCK.|HIGH|false
ip|13.107.42.14|Commercial|NOISE|Microsoft Outlook cloud IP is clustering noise; blocking it could disrupt legitimate Microsoft services.|HIGH|false
ip|172.67.192.40|Commercial|NOISE|Cloudflare front-end IP is shared infrastructure and not attacker-specific.|HIGH|false
ip|104.21.35.7|Commercial|NOISE|Cloudflare shared front-end IP is not sufficiently specific for campaign detection or blocking.|HIGH|false
sha256|a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456|HC3;Commercial;Researcher|ACTIONABLE|High-confidence malicious macro document hash corroborated by three sources.|HIGH|false
sha256|b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654|HC3;Commercial|ACTIONABLE|High-confidence svchost_update.exe malware hash confirmed by HC3 and commercial reporting.|HIGH|false
sha256|c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6|HC3;Commercial;Researcher|ACTIONABLE|High-confidence PowerShell exfiltration artifact corroborated by three sources.|HIGH|false
sha256|2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f|HC3;Researcher;MedDefense|CONTEXTUAL|Reported as a lure hash by multiple sources, but the supplied value is malformed at 62 hex characters and must be validated.|HIGH|true
sha256|dd5efb6d1ab4c67890abcdef1234567890abcdef1234567890abcdef12345678|HC3;Commercial|ACTIONABLE|Medium-confidence Stage 2 dropper variant corroborated by HC3 and commercial reporting.|MEDIUM|true
sha256|ee1122334455667788990011223344556677889900aabbccddeeff0011223344|Commercial|CONTEXTUAL|Commercial feed calls it a trojan variant but it lacks corroboration from the stronger sources.|MEDIUM|true
sha256|1122aabbccddeeff00112233445566778899aabbccddeeff0011223344556677|Commercial|NOISE|Feed explicitly labels this as an unrelated similarity cluster with no external corroboration.|HIGH|false
sha256|3344556677889900aabbccddeeff00112233445566778899aabbccddeeff0011|Commercial|NOISE|Unrelated-cluster hash has low commercial confidence and no corroboration.|HIGH|false
sha256|5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344|Commercial|NOISE|Healthcare-keyword and similarity clustering alone do not establish HEALTHBANE association.|LOW|true
sha256|7788990011223344556677aabbccddeeff0011223344556677aabbccddeeff00|Commercial|NOISE|Weak ML similarity with no external source support is insufficient for operational detection.|LOW|true
sha256|ffaabbccdd0011223344556677889900aabbccddeeff00112233445566778899|Researcher|CONTEXTUAL|Researcher extracted the phishing kit ZIP but cannot confirm whether it is operator-owned or vendor-supplied.|MEDIUM|true
url|https://meddefense-portal.com/verify/staff?id=<user>&token=<8hex>|HC3;Researcher|ACTIONABLE|High-confidence credential-capture URL pattern corroborated by HC3 and researcher evidence.|HIGH|false
url|https://meddefense-portal.com/verify/staff?id=<user>&token=<hex>|Commercial|ACTIONABLE|Commercial representation of the corroborated credential-capture endpoint pattern.|HIGH|false
url|https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1|MedDefense|ACTIONABLE|Concrete phishing URL observed directly in the MedDefense incident.|HIGH|false
url|https://medequip-supplies.net/invoices/pay?id=INV-<YYYY-NNNNN>|HC3;Commercial|ACTIONABLE|High-confidence Stage 1 credential-capture endpoint corroborated by two sources.|HIGH|false
url|https://meddefense-benefits.org/enroll|HC3;Commercial|ACTIONABLE|High-confidence phishing endpoint associated with confirmed Stage 1 infrastructure.|HIGH|false
url|https://healthbane-c2.net/update/svchost_update.exe|HC3;Commercial|ACTIONABLE|Confirmed Stage 2 malware download URL suitable for immediate detection.|HIGH|false
url|https://outlook-protection.com/verify|Commercial|ACTIONABLE|Specific credential-harvesting URL on a domain independently confirmed by HC3 and researcher reporting.|HIGH|false
url|https://healthbane-c2.net/api/ingest|Researcher|ACTIONABLE|Specific exfiltration endpoint extracted from the attacker's kit; useful for network detection despite single-source provenance.|MEDIUM|true
email|noreply@meddefense-portal.com|MedDefense|ACTIONABLE|Sender address was directly observed in the confirmed MedDefense phishing campaign.|HIGH|false
email|invoices@medequip-supplies.net|MedDefense|ACTIONABLE|Sender address was directly observed in the confirmed MedDefense phishing campaign.|HIGH|false
email|hr-notifications@meddefense-benefits.org|MedDefense|ACTIONABLE|Sender address was directly observed in the confirmed MedDefense phishing campaign.|HIGH|false
EOF

total="$(wc -l < "$tmp" | tr -d ' ')"
actionable="$(awk -F'|' '$4=="ACTIONABLE"{n++} END{print n+0}' "$tmp")"
contextual="$(awk -F'|' '$4=="CONTEXTUAL"{n++} END{print n+0}' "$tmp")"
noise="$(awk -F'|' '$4=="NOISE"{n++} END{print n+0}' "$tmp")"

pct() {
    awk -v n="$1" -v t="$total" 'BEGIN { printf "%.1f", (t ? n*100/t : 0) }'
}

echo "# HEALTHBANE Indicator Triage"
echo
echo "Task 0 reference expectation: 64 unique indicators"
echo "Literal unique indicator values represented by the supplied evidence: $total"
echo "NOTE: The 64-vs-$total discrepancy is preserved as a data-quality issue."
echo
printf '%-8s | %-72s | %-34s | %-10s | %-6s | %-11s | %s\n' \
    "TYPE" "VALUE" "SOURCES" "CATEGORY" "CONF" "UNCERTAINTY" "JUSTIFICATION"
printf '%s\n' "$(printf '%*s' 190 '' | tr ' ' '-')"

while IFS='|' read -r type value sources category justification confidence uncertainty; do
    printf '%-8s | %-72s | %-34s | %-10s | %-6s | %-11s | %s\n' \
        "$type" "$value" "$sources" "$category" "$confidence" "$uncertainty" "$justification"
done < "$tmp"

echo
echo "## Summary"
echo "Total reviewed: $total"
echo "ACTIONABLE: $actionable ($(pct "$actionable")%)"
echo "CONTEXTUAL: $contextual ($(pct "$contextual")%)"
echo "NOISE: $noise ($(pct "$noise")%)"

echo
echo "## Top downgrade reasons"
echo "1. Shared cloud/CDN/hosting infrastructure would create false positives if blocked."
echo "2. Single-source indicators lack corroboration."
echo "3. Weak ML/name/keyword similarity is not sufficient evidence of campaign membership."
echo "4. Expired/sinkholed or historical infrastructure is better for correlation than active blocking."
echo "5. Malformed or unvalidated hashes must not be operationalized until corrected."

echo
echo "## Immediate detection priorities"
echo "- healthbane-c2.net and data-sync.healthbane-c2.net"
echo "- meddefense-portal.com, medequip-supplies.net, meddefense-benefits.org"
echo "- 91.234.99.107 and 51.38.42.191"
echo "- Confirmed Stage 2 hashes: a1b2...3456, b9c8...7654, c7d6...c5d6"
echo "- https://healthbane-c2.net/update/svchost_update.exe"
echo "- Credential-harvesting URL patterns under the confirmed phishing domains"

echo
echo "## Attribution handling"
echo "VITALSCORE is retained only as Acme's proprietary cluster label."
echo "It is NOT treated as proof of a named threat actor."
echo "Campaign name: HEALTHBANE. Threat-actor attribution: UNCONFIRMED."
