#!/bin/bash

# Task 8 - Evidence Cross-Check
# Separates direct packet evidence from analytical inference.
# Usage: ./8-evidence_crosscheck.sh

set -u

TOTAL_PHASES=7
VISIBLE_PHASES=6
VISIBILITY=$((VISIBLE_PHASES * 100 / TOTAL_PHASES))

echo "================================================================"
echo "   EVIDENCE CROSS-CHECK - PCAP VISIBILITY"
echo "================================================================"
echo

printf "%-5s | %-24s | %-14s | %s\n" \
    "Phase" "Attack Action" "PCAP Evidence?" "Verdict"

echo "------|--------------------------|----------------|------------------"
printf "%-5s | %-24s | %-14s | %s\n" "1" "Phishing delivery" "No"  "NOT VISIBLE IN PCAP"
printf "%-5s | %-24s | %-14s | %s\n" "2" "Credential harvesting" "Yes" "STRONG INFERENCE"
printf "%-5s | %-24s | %-14s | %s\n" "3" "C2 beaconing" "Yes" "CONFIRMED*"
printf "%-5s | %-24s | %-14s | %s\n" "4" "VPN pivot" "Yes" "STRONG INFERENCE"
printf "%-5s | %-24s | %-14s | %s\n" "5" "RDP lateral movement" "Yes" "CONFIRMED"
printf "%-5s | %-24s | %-14s | %s\n" "6" "SMB internal activity" "Yes" "CONFIRMED"
printf "%-5s | %-24s | %-14s | %s\n" "7" "DNS exfiltration" "Yes" "CONFIRMED"

echo
echo "* C2 traffic pattern is visible, but final Task 2 analysis is"
echo "  still required before asserting exact beacon counts/intervals."
echo

# ================================================================
# PHASE 1
# ================================================================

echo "=== PHASE 1 - PHISHING DELIVERY ==="
echo "Verdict: NOT VISIBLE IN PCAP"
echo
echo "Confirmed:"
echo "  Nothing about email delivery is independently confirmed by"
echo "  the network PCAPs analyzed in this project."
echo
echo "Context:"
echo "  The phishing delivery comes from the 4x00 investigation."
echo
echo "Additional evidence needed:"
echo "  - Mail gateway logs"
echo "  - Email headers"
echo "  - Mailbox audit logs"
echo

# ================================================================
# PHASE 2
# ================================================================

echo "=== PHASE 2 - CREDENTIAL HARVESTING ==="
echo "Verdict: STRONG INFERENCE"
echo
echo "CONFIRMED:"
echo "  - 10.10.2.15 queried meddefense-portal.com."
echo "  - Domain resolved to 91.234.99.107."
echo "  - Workstation established TCP/443 connectivity."
echo "  - TLS SNI contained meddefense-portal.com."
echo "  - Client later sent a 487-byte encrypted TLS payload."
echo
echo "STRONG INFERENCE:"
echo "  The outbound encrypted payload is consistent with a small"
echo "  web-form submission."
echo
echo "UNCONFIRMED:"
echo "  Packet evidence cannot show that the payload contained"
echo "  username/password credentials."
echo
echo "Additional evidence needed:"
echo "  - Phishing web-server logs"
echo "  - Browser/endpoint artifacts"
echo "  - User interview"
echo

# ================================================================
# PHASE 3
# ================================================================

echo "=== PHASE 3 - C2 BEACONING ==="
echo "Verdict: CONFIRMED PATTERN / FINAL METRICS PENDING"
echo
echo "CONFIRMED:"
echo "  Repeated network communication is visible in"
echo "  c2_beaconing.pcap."
echo
echo "UNCONFIRMED/PENDING:"
echo "  Exact beacon count, mean interval and jitter should be taken"
echo "  from the completed Task 2 analysis."
echo
echo "Additional evidence useful:"
echo "  - EDR process/network telemetry"
echo "  - Proxy logs"
echo "  - Firewall/NetFlow logs"
echo

# ================================================================
# PHASE 4
# ================================================================

echo "=== PHASE 4 - VPN PIVOT ==="
echo "Verdict: STRONG INFERENCE"
echo
echo "CONFIRMED:"
echo "  - 154.118.42.89 connected to 10.10.0.1:443."
echo "  - TLS SNI was vpn.meddefense.com."
echo "  - Account string 'dmarsh' appeared in VPN-related traffic."
echo "  - Internal IP 10.10.2.200 appeared in VPN metadata."
echo "  - Connection began at 2026-04-15 15:45:22 +0200."
echo "  - RDP activity followed approximately 44.84 minutes later."
echo
echo "STRONG INFERENCE:"
echo "  The VPN session is a plausible pivot from external access to"
echo "  subsequent internal activity."
echo
echo "UNCONFIRMED:"
echo "  The PCAP does not prove which password was entered or who"
echo "  physically operated the external system."
echo
echo "Additional evidence needed:"
echo "  - VPN authentication logs"
echo "  - MFA logs"
echo "  - Identity-provider logs"
echo "  - Domain controller authentication logs"
echo

# ================================================================
# PHASE 5
# ================================================================

echo "=== PHASE 5 - RDP LATERAL MOVEMENT ==="
echo "Verdict: CONFIRMED"
echo
echo "CONFIRMED:"
echo "  10.10.2.15 initiated TCP/3389 communication to"
echo "  billing-srv-01 (10.10.1.10) at 16:30:12.445 +0200."
echo
echo "INFERENCE:"
echo "  Correlation with the preceding VPN activity supports the"
echo "  lateral-movement narrative."
echo
echo "UNCONFIRMED FROM PACKETS ALONE:"
echo "  Exact interactive actions performed inside the RDP session."
echo
echo "Additional evidence needed:"
echo "  - Windows Security logs"
echo "  - RDP operational logs"
echo "  - EDR/process telemetry"
echo

# ================================================================
# PHASE 6
# ================================================================

echo "=== PHASE 6 - SMB INTERNAL ACTIVITY ==="
echo "Verdict: CONFIRMED NETWORK ACTIVITY"
echo
echo "CONFIRMED:"
echo "  billing-srv-01 initiated TCP/445 connections toward multiple"
echo "  internal destinations:"
echo "    10.10.1.20"
echo "    10.10.1.30"
echo "    10.10.1.31"
echo "    10.10.4.100"
echo "    10.10.4.101"
echo "    10.10.1.60"
echo
echo "  Attempts toward 10.10.4.100 and 10.10.4.101 were followed"
echo "  by reset/refusal behavior."
echo
echo "UNCONFIRMED:"
echo "  Our tshark analysis did not independently confirm exact share"
echo "  names, directory contents or STATUS_ACCESS_DENIED responses."
echo
echo "Additional evidence needed:"
echo "  - SMB server logs"
echo "  - Windows Security logs"
echo "  - File-server audit logs"
echo "  - Better SMB application-layer decoding"
echo

# ================================================================
# PHASE 7
# ================================================================

echo "=== PHASE 7 - DNS EXFILTRATION ==="
echo "Verdict: CONFIRMED"
echo
echo "CONFIRMED:"
echo "  - 120 anomalous TXT queries were observed."
echo "  - Queries targeted data-sync.meddefense-portal.com."
echo "  - Encoded labels were approximately 44-60 characters."
echo "  - TXT rate was approximately 20.7x the Task 0 baseline."
echo "  - Base32 decoding recovered structured data fragments."
echo
echo "STRONG INFERENCE:"
echo "  The pattern is consistent with DNS tunneling used for"
echo "  exfiltration."
echo
echo "UNCONFIRMED:"
echo "  The PCAP does not prove that every complete record was"
echo "  successfully reconstructed or received by the attacker."
echo
echo "Additional evidence needed:"
echo "  - Authoritative DNS/server logs"
echo "  - DNS resolver logs"
echo "  - Endpoint artifacts"
echo "  - Attacker-side infrastructure, if available"
echo

# ================================================================
# SUMMARY
# ================================================================

echo "================================================================"
echo "   CONFIRMED FROM PCAP"
echo "================================================================"
echo
echo "- DNS resolution and TLS contact with meddefense-portal.com"
echo "- Repeated C2-like communication pattern"
echo "- External TLS/VPN-style connection"
echo "- Internal RDP traffic"
echo "- Internal SMB connection attempts"
echo "- DNS TXT tunneling behavior and encoded data fragments"
echo

echo "=== STRONG INFERENCE ==="
echo "- Encrypted phishing traffic may contain credential submission."
echo "- VPN activity using dmarsh context represents the likely"
echo "  external-to-internal pivot."
echo "- DNS tunnel behavior represents data exfiltration."
echo

echo "=== NOT CONFIRMED FROM PCAP ALONE ==="
echo "- Exact plaintext password entered"
echo "- Identity of the attacker"
echo "- User intent"
echo "- Exact endpoint processes executed"
echo "- MFA approval/denial details"
echo "- Whether a SIEM alert fired"
echo "- Complete contents received by attacker"
echo

echo "=== ADDITIONAL EVIDENCE NEEDED ==="
echo "- Mail gateway and mailbox logs"
echo "- VPN authentication and MFA logs"
echo "- Domain controller authentication logs"
echo "- Windows Security logs"
echo "- EDR/process telemetry"
echo "- SMB/file-server audit logs"
echo "- DNS resolver/authoritative-server logs"
echo "- User interview where appropriate"
echo

echo "=== PACKET VISIBILITY SCORE ==="
echo "Direct network evidence exists for $VISIBLE_PHASES of $TOTAL_PHASES phases."
echo "Packet visibility: ${VISIBILITY}%"
echo

echo "=== PACKET EVIDENCE VS LOG EVIDENCE ==="
echo "Packet evidence is strongest for:"
echo "  who communicated, with whom, when, over which protocol,"
echo "  how often and how much data was transferred."
echo
echo "Packet evidence is limited when:"
echo "  traffic is encrypted or the question concerns endpoint"
echo "  processes, authentication decisions or user intent."
echo
echo "Log evidence can add:"
echo "  usernames, authentication results, process execution,"
echo "  file access, MFA decisions and application actions."
echo

echo "================================================================"
echo "KEY LESSON"
echo "Packets show communication and network behavior."
echo "Logs provide system and application context."
echo
echo "A defensible investigation separates CONFIRMED packet facts"
echo "from STRONG INFERENCE and UNCONFIRMED conclusions."
echo "================================================================"