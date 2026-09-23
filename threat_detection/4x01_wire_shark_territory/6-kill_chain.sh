#!/bin/bash

# Task 6 - Complete Kill Chain Reconstruction
# Combines findings from Tasks 1-5.
# Run: ./6-kill_chain.sh

set -u

echo "================================================================"
echo "   COMPLETE KILL CHAIN RECONSTRUCTION"
echo "   Incident: Phishing -> VPN Access -> Lateral Movement ->"
echo "             DNS Exfiltration"
echo "================================================================"
echo

# ================================================================
# PHASE 1
# ================================================================

echo "PHASE 1: INITIAL ACCESS"
echo "MITRE: T1566.002 - Phishing: Spearphishing Link"
echo "Evidence source: 4x00 phishing investigation"
echo
echo "Evidence:"
echo "- Phishing campaign targeted MedDefense users."
echo "- dmarsh was associated with the phishing/credential context."
echo
echo "Status: CONTEXT FROM 4x00"
echo "This phase is not independently proven by the PCAPs analyzed here."
echo

# ================================================================
# PHASE 2
# ================================================================

echo "PHASE 2: PHISHING CLICK / CREDENTIAL-HARVESTING SESSION"
echo "MITRE: T1056.003 - Input Capture: Web Portal Capture"
echo "PCAP: phishing_click.pcap"
echo "Time: 2026-04-14 17:02:33 to 17:03:20 +0200"
echo
echo "Packet evidence:"
echo "- 10.10.2.15 queried meddefense-portal.com."
echo "- DNS resolved meddefense-portal.com to 91.234.99.107."
echo "- 10.10.2.15 immediately established TCP/443 connectivity."
echo "- TLS SNI: meddefense-portal.com."
echo "- TLS 1.3 was offered by the client."
echo "- Client sent a 487-byte encrypted payload at 17:02:58."
echo "- Legitimate meddefense.com was queried shortly after the session."
echo
echo "CONFIRMED:"
echo "The workstation contacted the phishing infrastructure over TLS."
echo
echo "INFERENCE:"
echo "The encrypted outbound data is consistent with a small form"
echo "submission, but packet evidence does not reveal the plaintext"
echo "credentials."
echo

# ================================================================
# PHASE 3
# ================================================================

echo "PHASE 3: BEACONING / COMMAND AND CONTROL"
echo "MITRE: T1071.001 - Application Layer Protocol: Web Protocols"
echo "PCAP: c2_beaconing.pcap"
echo
echo "Status: PENDING FINAL TASK 2 ANALYSIS"
echo "Do not infer session count, interval or C2 contents until the"
echo "c2_beaconing PCAP analysis has been completed."
echo

# ================================================================
# PHASE 4
# ================================================================

echo "PHASE 4: EXTERNAL ACCESS / VPN PIVOT"
echo "MITRE: T1133 - External Remote Services"
echo "PCAP: full_timeline.pcap"
echo "Time: 2026-04-15 15:45:22 +0200"
echo
echo "Packet evidence:"
echo "- External source: 154.118.42.89:49872"
echo "- VPN endpoint: 10.10.0.1:443"
echo "- TLS SNI: vpn.meddefense.com"
echo "- TLS 1.3 offered."
echo "- Account string 'dmarsh' observed in VPN stream."
echo "- Internal IP 10.10.2.200 observed in VPN-related metadata."
echo "- Session lasted approximately 2904.97 seconds (~48.4 min)."
echo
echo "CONFIRMED:"
echo "An external TLS/VPN-style connection occurred before lateral"
echo "movement and contained dmarsh account context."
echo
echo "LIMITATION:"
echo "Packet evidence does not reveal the plaintext password."
echo

# ================================================================
# PHASE 5
# ================================================================

echo "PHASE 5: LATERAL MOVEMENT - RDP"
echo "MITRE: T1021.001 - Remote Services: Remote Desktop Protocol"
echo "PCAP: lateral_movement.pcap"
echo "Time: 2026-04-15 16:30:12.445 +0200"
echo
echo "Packet evidence:"
echo "- 10.10.2.15 -> 10.10.1.10:3389"
echo "- WS-NURSE-04 initiated RDP traffic to billing-srv-01."
echo "- Activity began approximately 44.84 minutes after VPN access."
echo
echo "Assessment:"
echo "The timing links external VPN access with subsequent internal"
echo "remote-access activity."
echo

# ================================================================
# PHASE 6
# ================================================================

echo "PHASE 6: INTERNAL SMB ACTIVITY"
echo "MITRE: T1021.002 - SMB/Windows Admin Shares"
echo "PCAP: lateral_movement.pcap"
echo "Time: 2026-04-15 16:35:22 onward +0200"
echo
echo "Packet evidence:"
echo "- 10.10.1.10 -> 10.10.1.20:445"
echo "- 10.10.1.10 -> 10.10.1.30:445"
echo "- 10.10.1.10 -> 10.10.1.31:445"
echo "- 10.10.1.10 -> 10.10.4.100:445"
echo "- 10.10.1.10 -> 10.10.4.101:445"
echo "- 10.10.1.10 -> 10.10.1.60:445"
echo
echo "Packet evidence also showed reset/refusal behavior immediately"
echo "after attempts toward 10.10.4.100 and 10.10.4.101."
echo
echo "LIMITATION:"
echo "Our tshark output did not decode sufficient SMB application"
echo "details to independently confirm share names, directory listings"
echo "or STATUS_ACCESS_DENIED events."
echo

# ================================================================
# PHASE 7
# ================================================================

echo "PHASE 7: DNS EXFILTRATION"
echo "MITRE: T1048.003 - Exfiltration Over Alternative Protocol"
echo "PCAP: dns_exfil.pcap"
echo "Source: billing-srv-01 (10.10.1.10)"
echo
echo "Packet evidence:"
echo "- 487 total DNS queries from billing-srv-01."
echo "- 367 classified as normal."
echo "- 120 anomalous TXT queries."
echo "- Destination domain: data-sync.meddefense-portal.com."
echo "- Encoded labels were 44-60 characters (avg 52.19)."
echo "- Query rate: approximately 4.85/min."
echo "- Task 0 TXT baseline: 0.234/min."
echo "- Tunnel TXT rate: approximately 20.7x baseline."
echo "- Total encoded payload: 6263 characters."
echo "- Estimated raw data: approximately 3914 bytes."
echo "- Estimated rate: approximately 158.18 bytes/min."
echo
echo "Base32 decoding recovered structured fragments including:"
echo "- patient_record"
echo "- financial_record"
echo "- backup_metadata"
echo "- server_config"
echo
echo "CONFIRMED:"
echo "Structured data was transported inside DNS query labels."
echo

# ================================================================
# VISIBILITY
# ================================================================

echo "=== VISIBILITY / DEFENSE LAYERS ==="
echo
echo "Email policy:"
echo "  Phishing reached the target according to 4x00 context."
echo
echo "User click:"
echo "  Confirmed network contact with phishing domain."
echo
echo "TLS encryption:"
echo "  Protected application payload from direct packet inspection."
echo
echo "Beaconing:"
echo "  Pending final Task 2 analysis."
echo
echo "VPN:"
echo "  External VPN-style TLS session visible before lateral movement."
echo
echo "RDP:"
echo "  Internal RDP activity visible on TCP/3389."
echo
echo "SMB:"
echo "  Multiple TCP/445 attempts visible from billing-srv-01."
echo
echo "DNS exfiltration:"
echo "  Highly visible through encoded TXT query patterns."
echo

# ================================================================
# CRITICAL PIVOTS
# ================================================================

echo "=== CRITICAL PIVOT POINTS ==="
echo "1. Phishing email reached the target."
echo "2. Workstation contacted the phishing domain."
echo "3. External VPN session appeared using dmarsh context."
echo "4. RDP activity reached billing-srv-01."
echo "5. billing-srv-01 initiated SMB connections to other systems."
echo "6. Encoded DNS TXT traffic transported structured data."
echo

# ================================================================
# IMPACT
# ================================================================

echo "=== IMPACT ASSESSMENT ==="
echo
echo "Confirmed systems involved:"
echo "- WS-NURSE-04 / 10.10.2.15"
echo "- VPN endpoint / 10.10.0.1"
echo "- billing-srv-01 / 10.10.1.10"
echo "- Additional internal destinations contacted over SMB"
echo
echo "Likely data affected:"
echo "- Patient record fragments"
echo "- Financial record fragments"
echo "- Backup metadata"
echo "- Server configuration information"
echo
echo "Systems showing resistance:"
echo "- Attempts toward 10.10.4.100 and 10.10.4.101 were followed"
echo "  by TCP reset/refusal behavior."
echo
echo "Unconfirmed:"
echo "- Exact plaintext phishing credentials"
echo "- Exact identity/location of the attacker"
echo "- Whether endpoint malware executed"
echo "- Whether MFA was present"
echo "- Full contents of all exfiltrated records"
echo "- Detailed SMB share/file enumeration"
echo

# ================================================================
# TIMELINE
# ================================================================

echo "=== MASTER TIMELINE ==="
echo "2026-04-14 17:02:33  Phishing domain contacted"
echo "2026-04-14 17:02:58  487-byte encrypted client TLS payload"
echo "2026-04-14 17:03:20  Phishing TLS connection closes"
echo "2026-04-15 15:45:22  External VPN connection begins"
echo "2026-04-15 16:30:12  RDP to billing-srv-01"
echo "2026-04-15 16:35:22  SMB activity begins from billing-srv-01"
echo "2026-04-15 16:38:07  Attempts toward restricted endpoints"
echo "2026-04-15 16:40:33  SMB connection attempt to 10.10.1.60"
echo "DNS exfiltration         See dns_exfil.pcap Task 3 timestamps"
echo

echo "=== DWELL TIME ==="
echo "Exact total dwell time requires the absolute timestamp of the"
echo "last DNS exfiltration event."
echo "Do not calculate it from relative PCAP timestamps alone."
echo

echo "================================================================"
echo "FINAL ASSESSMENT"
echo "================================================================"
echo "Packet evidence supports a multi-stage compromise progressing"
echo "from phishing-domain contact to external VPN access, internal"
echo "RDP/SMB activity and DNS-based data exfiltration."
echo
echo "Conclusions requiring unavailable plaintext or application-layer"
echo "evidence are explicitly treated as inference or unconfirmed."