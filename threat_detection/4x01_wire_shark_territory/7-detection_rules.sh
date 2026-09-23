#!/bin/bash

# Task 7 - Detection Engineering
# Converts forensic findings into operational detection logic.
# Usage: ./7-detection_rules.sh

set -u

echo "================================================================"
echo "   DETECTION ENGINEERING PLAN"
echo "================================================================"
echo

# ================================================================
# DETECTION 1 - C2 BEACONING
# ================================================================

echo "[*] Detection 1: C2 Beaconing"
echo "    Attack phase: Command and Control"
echo "    MITRE: T1071.001 - Application Layer Protocol: Web Protocols"
echo
echo "    Logic:"
echo "      Group outbound connections by src_ip and dst_ip."
echo "      IF connections > 10 within 3600 seconds"
echo "      THEN calculate intervals between consecutive connections."
echo "      mean = average(intervals)"
echo "      stddev = standard_deviation(intervals)"
echo
echo "      IF stddev < mean * 0.15"
echo "      THEN alert: Possible C2 beaconing"
echo
echo "    Required data source:"
echo "      PCAP session data, Zeek conn.log, NetFlow or proxy logs."
echo
echo "    Test scenario:"
echo "      Internal host repeatedly connects to the same external IP"
echo "      at highly regular intervals for more than 10 sessions/hour."
echo
echo "    Would detect:"
echo "      Phase 3 behavior in c2_beaconing.pcap."
echo
echo "    False positives:"
echo "      Monitoring agents, update services, health checks and"
echo "      backup software can generate regular connections."
echo
echo "    Implementation options:"
echo "      - SIEM aggregation/correlation rule"
echo "      - Zeek script"
echo "      - Scheduled Python analysis"
echo "      - NetFlow behavioral analytics"
echo

# ================================================================
# DETECTION 2 - DNS LABEL LENGTH
# ================================================================

echo "[*] Detection 2: DNS Query Length Anomaly"
echo "    Attack phase: Exfiltration / DNS tunneling"
echo "    MITRE: T1048.003 - Exfiltration Over Alternative Protocol"
echo
echo "    Logic:"
echo "      Extract the left-most label from each DNS query."
echo
echo "      IF length(left_most_label) > 40"
echo "      THEN alert: Abnormally long DNS label"
echo
echo "      Increase severity if:"
echo "        - query type is TXT"
echo "        - labels appear Base32/Base64/hex encoded"
echo "        - queries repeatedly target the same base domain"
echo
echo "    Required data source:"
echo "      DNS logs, Zeek dns.log, PCAP or DNS resolver logs."
echo
echo "    Test scenario:"
echo "      A query to data-sync.meddefense-portal.com contains"
echo "      a 44-60 character encoded left-most label."
echo
echo "    Would detect:"
echo "      DNS exfiltration observed in dns_exfil.pcap."
echo
echo "    False positives:"
echo "      CDNs, security products, tracking systems and legitimate"
echo "      applications may generate long DNS labels."
echo

# ================================================================
# DETECTION 3 - VPN GEO ANOMALY
# ================================================================

echo "[*] Detection 3: VPN Geo-Anomaly"
echo "    Attack phase: External Access"
echo "    MITRE: T1133 - External Remote Services"
echo
echo "    Logic:"
echo "      Enrich VPN source IP with GeoIP and ASN information."
echo
echo "      IF country NOT IN organization_expected_countries"
echo "      OR ASN NOT IN account_historical_ASNs"
echo "      THEN alert: Suspicious VPN login"
echo
echo "      Increase severity when:"
echo "        account has never authenticated from that country/ASN."
echo
echo "    Required data source:"
echo "      VPN authentication logs"
echo "      + source IP"
echo "      + GeoIP database"
echo "      + ASN database"
echo "      + account login history."
echo
echo "    Test scenario:"
echo "      dmarsh authenticates to the MedDefense VPN from an"
echo "      external IP with previously unseen geography or ASN."
echo
echo "    Would detect:"
echo "      Phase 4 VPN connection from 154.118.42.89."
echo
echo "    False positives:"
echo "      Employee travel, mobile networks, corporate proxies,"
echo "      commercial VPNs and ISP changes."
echo

# ================================================================
# DETECTION 4 - CROSS-ROLE RDP
# ================================================================

echo "[*] Detection 4: Cross-Role RDP"
echo "    Attack phase: Lateral Movement"
echo "    MITRE: T1021.001 - Remote Desktop Protocol"
echo
echo "    Logic:"
echo "      IF source_account_role IN [clinical, non-IT]"
echo "      AND destination_network == server_subnet"
echo "      AND destination_port == 3389"
echo "      THEN alert: Unexpected cross-role RDP"
echo
echo "    Required data source:"
echo "      Network connection metadata or firewall logs"
echo "      + Windows authentication logs"
echo "      + asset inventory"
echo "      + account/role directory."
echo
echo "    Packet-only alternative:"
echo "      Detect unexpected workstation -> server TCP/3389."
echo "      Packet metadata alone may not identify the account role."
echo
echo "    Test scenario:"
echo "      WS-NURSE-04 (10.10.2.15) initiates RDP to"
echo "      billing-srv-01 (10.10.1.10)."
echo
echo "    Would detect:"
echo "      Phase 5 lateral movement."
echo
echo "    False positives:"
echo "      Authorized support, administrators, approved remote"
echo "      maintenance and exceptional business workflows."
echo

# ================================================================
# DETECTION 5 - DNS TXT TUNNEL
# ================================================================

echo "[*] Detection 5: DNS Tunneling TXT Query Pattern"
echo "    Attack phase: Exfiltration"
echo "    MITRE: T1048.003 - Exfiltration Over Alternative Protocol"
echo
echo "    Logic:"
echo "      Group TXT queries by src_ip and base_domain."
echo
echo "      IF TXT query count > 10 within 120 seconds"
echo "      AND left-most labels appear encoded"
echo "      THEN alert: Possible DNS tunnel"
echo
echo "      Additional indicators:"
echo "        - long labels"
echo "        - repeated destination domain"
echo "        - Base32/Base64/hex-like character distribution"
echo "        - TXT rate significantly above host baseline"
echo
echo "    Required data source:"
echo "      DNS resolver logs, Zeek dns.log or PCAP."
echo
echo "    Test scenario:"
echo "      billing-srv-01 sends repeated TXT queries to"
echo "      data-sync.meddefense-portal.com containing encoded data."
echo
echo "    Would detect:"
echo "      120 anomalous TXT queries observed in dns_exfil.pcap."
echo
echo "    False positives:"
echo "      SPF/DKIM-related activity, service discovery and legitimate"
echo "      applications that use TXT records."
echo

# ================================================================
# DETECTION 6 - TLS SNI / PHISHING IOC
# ================================================================

echo "[*] Detection 6: TLS to Campaign Lookalike Domain"
echo "    Attack phase: Phishing / Credential Access"
echo
echo "    Logic:"
echo "      Maintain an IOC or first-seen-domain table."
echo
echo "      IF TLS SNI matches known campaign IOC"
echo "      OR TLS SNI matches a suspicious lookalike first seen"
echo "      during the phishing campaign"
echo "      THEN alert: TLS connection to phishing infrastructure"
echo
echo "    No live domain-age feed is required."
echo "    The IOC list can be populated from email investigations."
echo
echo "    Required data source:"
echo "      TLS SNI metadata, proxy/firewall logs or Zeek ssl.log"
echo "      + phishing IOC list / first-seen table."
echo
echo "    Test scenario:"
echo "      10.10.2.15 establishes TLS to meddefense-portal.com."
echo
echo "    Would detect:"
echo "      Phase 2 phishing-click session in phishing_click.pcap."
echo
echo "    False positives:"
echo "      Legitimate newly observed domains and domains with names"
echo "      similar to corporate services."
echo

# ================================================================
# COVERAGE
# ================================================================

echo "================================================================"
echo "   DETECTION COVERAGE UPDATE"
echo "================================================================"
echo
echo "Before packet analysis:"
echo "  Campaign primarily visible through email indicators."
echo
echo "After packet analysis:"
echo "  Detection coverage includes:"
echo "    - phishing-domain TLS contact"
echo "    - behavioral C2 beaconing"
echo "    - anomalous VPN access"
echo "    - cross-role RDP"
echo "    - anomalous DNS labels"
echo "    - DNS TXT tunneling/exfiltration"
echo
echo "Remaining gaps:"
echo "  - Endpoint execution requires endpoint/EDR telemetry."
echo "  - Encrypted TLS does not expose plaintext credentials."
echo "  - Account attribution may require authentication logs."
echo "  - VPN geography requires GeoIP/ASN enrichment."
echo
echo "================================================================"