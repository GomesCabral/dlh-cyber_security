# Network Forensics Investigation Report

**Analyst:** Pedro Cabral  
**Project:** 4x01 — Wireshark Territory  
**Repository:** `dlh-cyber_security`  
**Investigation:** MedDefense Network Compromise  
**Incident Period:** 14–15 April 2026  
**Classification:** Confirmed Network Compromise  

---

## Executive Summary

MedDefense network traffic shows that a workstation contacted phishing infrastructure on 14 April 2026 and an external VPN connection associated with the `dmarsh` account context appeared the following day. Approximately 45 minutes after the VPN connection, internal RDP and SMB activity began, including access attempts toward multiple server systems. DNS traffic from the billing server later carried encoded patient, financial, backup and server-configuration data, strongly supporting data exfiltration through DNS tunneling. Some internal connection attempts were reset or refused, indicating that not every targeted system was reachable. The full extent of credential and healthcare-data exposure requires endpoint, authentication and server-log evidence beyond the available packet captures.

---

## Investigation Scope

The investigation analyzed the following packet captures:

| PCAP | Purpose |
|---|---|
| `normal_baseline_clinical.pcap` | Establish normal MedDefense network behavior |
| `phishing_click.pcap` | Investigate post-phishing network activity |
| `c2_beaconing.pcap` | Investigate repeated communications potentially associated with C2 |
| `dns_exfil.pcap` | Investigate anomalous DNS activity and possible exfiltration |
| `lateral_movement.pcap` | Investigate RDP, SMB and internal movement |
| `full_timeline.pcap` | Correlate VPN access with the wider incident timeline |

The observed incident activity covers 14–15 April 2026.

Tools used included:

- `tshark`
- Wireshark
- Bash
- `awk`
- `sort`
- `grep`
- Base32/Base64 decoding utilities
- WHOIS where available

The investigation primarily used network packet evidence.

The following evidence sources were not comprehensively available during this packet investigation:

- EDR telemetry
- Windows process execution logs
- Complete domain-controller authentication logs
- Complete VPN authentication logs
- MFA records
- Mail gateway logs
- Web-server logs from attacker infrastructure
- SIEM alert history
- User interview evidence

These limitations are considered when assigning confidence to findings.

---

## Methodology

### Baseline Establishment

`normal_baseline_clinical.pcap` was analyzed first to establish expected network behavior.

The baseline contained 2,842 packets over approximately 1,798 seconds.

Normal DNS activity averaged:

- 17.35 DNS queries/minute
- 0.234 TXT queries/minute

Common legitimate domains included:

- `pacs.meddefense.com`
- `outlook.office365.com`
- `windows.com`
- `time.windows.com`
- `www.bing.com`
- `login.microsoftonline.com`
- `meddefense.com`
- `ehr.meddefense.com`

The baseline was subsequently used to evaluate anomalous DNS and internal communication patterns.

### Known-IOC Search

Domains and IP addresses identified during the previous 4x00 phishing investigation were searched across packet captures.

The primary campaign infrastructure observed in network traffic included:

- `meddefense-portal.com`
- `91.234.99.107`
- `data-sync.meddefense-portal.com`

### DNS Analysis

DNS queries were analyzed for:

- query frequency
- query type
- destination domain
- label length
- encoded content
- deviations from baseline

### TLS Metadata Analysis

Encrypted sessions were investigated using metadata including:

- source/destination IP
- source/destination port
- TLS SNI
- ClientHello metadata
- supported TLS versions
- packet timing
- TCP payload size

Encrypted TLS application content was not treated as plaintext evidence.

### Timing Analysis

Exact packet timestamps were used to correlate:

- phishing-domain access
- VPN connection
- RDP activity
- SMB activity
- DNS tunneling

### Behavioral Analysis

Repeated communication patterns, unusually long DNS labels, TXT query frequency and unexpected workstation-to-server communications were evaluated as behavioral indicators.

### Cross-PCAP Correlation

Findings from individual captures were combined into a single incident timeline while separating direct packet evidence from analytical inference.

---

# Findings by Attack Phase

## Phase 1 — Initial Access

**MITRE ATT&CK:** T1566.002 — Phishing: Spearphishing Link  
**Evidence:** 4x00 phishing investigation  
**Confidence:** High for campaign context; not independently confirmed by 4x01 PCAP  

The previous investigation identified phishing activity associated with the MedDefense campaign and the `dmarsh` account context.

Email delivery itself is not independently demonstrated by the packet captures analyzed in 4x01.

### Packet Evidence Proves

The 4x01 PCAPs do not independently prove delivery of the phishing email.

---

## Phase 2 — Phishing Infrastructure Contact

**MITRE ATT&CK:** T1056.003 — Input Capture: Web Portal Capture  
**PCAP:** `phishing_click.pcap`  
**Confidence:** High for infrastructure contact; medium/high for credential-harvesting interpretation  

At:

`2026-04-14T17:02:33.142000000+0200`

`10.10.2.15` queried:

`meddefense-portal.com`

The DNS response at:

`2026-04-14T17:02:33.287000000+0200`

returned:

`91.234.99.107`

with TTL 300 seconds.

At:

`2026-04-14T17:02:33.412000000+0200`

the workstation initiated a TCP connection to the phishing infrastructure on TCP/443.

TLS ClientHello at:

`2026-04-14T17:02:33.589000000+0200`

contained SNI:

`meddefense-portal.com`

and offered TLS 1.3.

At:

`2026-04-14T17:02:58.721000000+0200`

a 487-byte client-side encrypted TLS payload was observed.

The TLS connection closed at approximately:

`2026-04-14T17:03:20.764000000+0200`

Shortly afterwards, the workstation queried the legitimate `meddefense.com` domain.

### Packet Evidence Proves

The workstation contacted known phishing infrastructure and established an encrypted session.

### Analytical Inference

The timing and size of the outbound encrypted traffic are consistent with web-form submission.

The plaintext credentials cannot be recovered from the encrypted packet data, so exact credential submission is not directly proven.

---

## Phase 3 — C2 / Repeated Communications

**MITRE ATT&CK:** T1071.001 — Application Layer Protocol: Web Protocols  
**PCAP:** `c2_beaconing.pcap`  
**Confidence:** Pending final Task 2 metrics  

Repeated network communication is visible in the C2 capture.

The final exact beacon count, interval mean, standard deviation and jitter should be populated from the completed Task 2 analysis.

### Packet Evidence Proves

Repeated communication behavior is present.

### Limitation

Exact behavioral statistics should not be asserted until the dedicated beaconing analysis is finalized.

---

## Phase 4 — VPN Pivot

**MITRE ATT&CK:** T1133 — External Remote Services  
**PCAP:** `full_timeline.pcap`  
**Confidence:** High for VPN connection; strong inference for stolen-credential use  

At:

`2026-04-15T15:45:22.000000000+0200`

external IP:

`154.118.42.89:49872`

connected to:

`10.10.0.1:443`

The TLS ClientHello contained:

`vpn.meddefense.com`

as SNI.

The account string:

`dmarsh`

was observed in VPN-related traffic at:

`2026-04-15T15:45:23.399000000+0200`

The internal address `10.10.2.200` was also observed in VPN-related metadata.

The observed TCP session continued until approximately:

`2026-04-15T16:33:46.974869000+0200`

for an approximate duration of 2,904.97 seconds.

### Packet Evidence Proves

An external system established a VPN-style TLS session before lateral movement, and `dmarsh` appeared in associated packet context.

### Analytical Inference

The session is strongly consistent with the attacker using previously obtained account access.

The PCAP does not expose the plaintext password or establish the physical identity of the person operating the source system.

---

## Phase 5 — RDP Lateral Movement

**MITRE ATT&CK:** T1021.001 — Remote Services: Remote Desktop Protocol  
**PCAP:** `lateral_movement.pcap`  
**Confidence:** High for RDP network activity  

At:

`2026-04-15T16:30:12.445000000+0200`

`10.10.2.15` initiated TCP/3389 communication with:

`10.10.1.10`

The activity occurred approximately 44.84 minutes after the external VPN connection began.

### Packet Evidence Proves

The clinical workstation initiated RDP communication toward the billing server.

### Analytical Inference

The timing strongly links this activity with the preceding VPN event, but endpoint and authentication logs are required to reconstruct exact interactive actions.

---

## Phase 6 — SMB Internal Activity

**MITRE ATT&CK:** T1021.002 — SMB/Windows Admin Shares  
**PCAP:** `lateral_movement.pcap`  
**Confidence:** High for network connections; lower for application-level enumeration  

Following RDP activity, `10.10.1.10` initiated TCP/445 connections toward multiple internal systems.

Observed initial connection timestamps included:

| Timestamp | Source | Destination | Service |
|---|---|---|---|
| 2026-04-15 16:35:22.891 +0200 | 10.10.1.10 | 10.10.1.20 | SMB |
| 2026-04-15 16:36:01.334 +0200 | 10.10.1.10 | 10.10.1.30 | SMB |
| 2026-04-15 16:36:45.112 +0200 | 10.10.1.10 | 10.10.1.31 | SMB |
| 2026-04-15 16:38:07.556 +0200 | 10.10.1.10 | 10.10.4.100 | SMB |
| 2026-04-15 16:38:08.112 +0200 | 10.10.1.10 | 10.10.4.101 | SMB |
| 2026-04-15 16:40:33.778 +0200 | 10.10.1.10 | 10.10.1.60 | SMB |

Reset/refusal behavior followed attempts toward `10.10.4.100` and `10.10.4.101`.

### Packet Evidence Proves

The billing server attempted SMB connectivity with multiple internal systems.

### Limitation

The available `tshark` decoding did not independently establish exact share names, directory contents or all claimed application-layer access-denied results.

---

## Phase 7 — DNS Exfiltration

**MITRE ATT&CK:** T1048.003 — Exfiltration Over Alternative Protocol  
**PCAP:** `dns_exfil.pcap`  
**Confidence:** High  

Traffic from:

`billing-srv-01 / 10.10.1.10`

contained:

- 487 total DNS queries
- 367 normal queries
- 120 anomalous queries

The anomalous traffic targeted:

`data-sync.meddefense-portal.com`

and used TXT queries containing long encoded labels.

Observed label characteristics:

- minimum length: 44 characters
- maximum length: 60 characters
- average: 52.19 characters

The anomalous query rate was approximately:

`4.85/minute`

compared with the normal TXT baseline:

`0.234/minute`

This represents approximately:

`20.7x`

the baseline TXT rate.

The anomalous labels contained approximately 6,263 encoded characters, representing an estimated 3,914 bytes of raw data.

Base32 decoding recovered fragments associated with:

- patient records
- financial records
- backup metadata
- server configuration information

### Packet Evidence Proves

Structured information was transported inside DNS query labels.

### Analytical Assessment

The combination of encoded content, repeated TXT queries, abnormal frequency and structured decoded fragments strongly supports DNS tunneling used for data exfiltration.

---

# Network-Level IOC Table

| Type | Value | Source | Confidence | Detection Utility |
|---|---|---|---|---|
| Domain | `meddefense-portal.com` | 4x00 / phishing PCAP | High | DNS, proxy, TLS SNI blocking |
| IPv4 | `91.234.99.107` | phishing PCAP | High | Firewall / network IOC |
| Domain | `data-sync.meddefense-portal.com` | DNS exfil PCAP | High | DNS tunneling detection |
| IPv4 | `154.118.42.89` | full timeline | High | VPN investigation / enrichment |
| Domain | `vpn.meddefense.com` | full timeline | High | VPN service context |
| Account | `dmarsh` | 4x00 / VPN context | High | Authentication hunting |
| IPv4 | `10.10.2.15` | multiple captures | High | Affected workstation |
| IPv4 | `10.10.1.10` | lateral/DNS captures | High | Billing server investigation |
| IPv4 | `10.10.0.1` | full timeline | High | VPN endpoint |
| IPv4 | `10.10.2.200` | VPN metadata | Medium/High | VPN session correlation |

Internal addresses are investigation pivots rather than malicious infrastructure IOCs.

---

# Impact Assessment

## Systems Involved

Confirmed network activity involved:

- WS-NURSE-04 — `10.10.2.15`
- billing-srv-01 — `10.10.1.10`
- VPN endpoint — `10.10.0.1`
- `10.10.1.20`
- `10.10.1.30`
- `10.10.1.31`
- `10.10.1.60`
- `10.10.4.100`
- `10.10.4.101`

## Data Exposure

Decoded DNS tunnel fragments indicate possible exposure of:

- patient information
- financial information
- backup metadata
- server configuration information

Approximately 3.9 KB of raw information is estimated from the observed encoded DNS labels.

This estimate represents captured tunnel data and should not be interpreted as the complete scope of all information potentially exposed.

## Credential Exposure

The investigation strongly supports compromise or unauthorized use of the `dmarsh` account context.

The exact password cannot be recovered from the encrypted network traffic.

## Systems Protected or Not Reached

Attempts toward:

- `10.10.4.100`
- `10.10.4.101`

were followed by reset/refusal behavior.

This supports that the observed connection attempts did not successfully establish the intended TCP/445 sessions.

## Business and Regulatory Concerns

Because decoded traffic contains fragments referring to patient and financial records, the incident requires a formal healthcare-data exposure assessment.

Network evidence alone cannot determine the complete number of affected records or whether all transmitted information was successfully received by attacker-controlled infrastructure.

---

# Detection Gap Analysis

## Phishing Infrastructure

The workstation successfully reached the phishing infrastructure.

Earlier detection could have used:

- campaign IOC blocking
- DNS IOC matching
- proxy filtering
- TLS SNI matching against campaign domains

## Behavioral C2 Detection

Repeated periodic communications require behavioral detection rather than reliance only on static IOCs.

Recommended analytics include:

- repeated source/destination pair detection
- connection interval analysis
- mean interval calculation
- standard deviation/jitter detection

## VPN Anomaly Detection

The external VPN session demonstrates the need to correlate:

- VPN source geography
- ASN
- account history
- MFA
- unusual access times
- subsequent internal activity

## Lateral Movement Detection

Unexpected workstation-to-server RDP and server-to-server SMB activity should be correlated with:

- asset roles
- account roles
- server subnet boundaries
- authentication events

## DNS Tunneling Detection

The DNS tunnel generated multiple detectable characteristics:

- TXT queries
- unusually long labels
- encoded-looking labels
- repeated queries to one base domain
- TXT frequency significantly above baseline

---

# Detection Rules Recommended

| Rule | Required Data | Detects | False Positive Considerations |
|---|---|---|---|
| C2 Beaconing | PCAP, Zeek, NetFlow, proxy | Command and Control | Monitoring/update software |
| DNS Label Length >40 | DNS logs / PCAP | DNS tunneling | CDNs/security applications |
| VPN Geo/ASN Anomaly | VPN + GeoIP + ASN + history | External access | Travel, ISP changes, proxies |
| Cross-Role RDP | Network + asset/account inventory | Lateral movement | Authorized support |
| High-Frequency TXT Tunnel | DNS logs / PCAP | Exfiltration | Legitimate TXT-heavy services |
| TLS SNI Campaign IOC | TLS/proxy + IOC table | Phishing contact | Legitimate lookalike/new domains |

---

# Recommendations

## Immediate — Next 24 Hours

1. Isolate `10.10.2.15` and `10.10.1.10` pending endpoint investigation.
2. Reset and invalidate active sessions associated with `dmarsh`.
3. Block confirmed malicious campaign infrastructure, including `meddefense-portal.com`, `data-sync.meddefense-portal.com` and `91.234.99.107`.
4. Investigate the VPN session associated with `154.118.42.89`.
5. Preserve PCAPs, endpoint artifacts, authentication logs and VPN logs.
6. Search enterprise telemetry for the identified IOCs.

## Short-Term — Next 7 Days

1. Deploy C2 periodicity detection.
2. Deploy DNS label-length and TXT-frequency detection.
3. Review VPN authentication history for `dmarsh`.
4. Review DNS activity from other hosts for the same tunnel domain or similar encoded patterns.
5. Hunt for additional RDP and SMB activity originating from affected systems.
6. Review access involving the internal systems contacted from `10.10.1.10`.

## Medium-Term — Next 30 Days

1. Strengthen email authentication and anti-phishing controls.
2. Improve DNS anomaly monitoring and egress controls.
3. Implement role-based restrictions for RDP.
4. Restrict unnecessary SMB communication between network segments.
5. Improve VPN anomaly detection using GeoIP, ASN and account-history enrichment.
6. Conduct a formal healthcare-data exposure review.
7. Validate MFA coverage for remote-access services.
8. Integrate network, identity and endpoint telemetry in the SOC.

---

# Evidence Chain

| Evidence | Purpose | Observed Period / Context | Integrity / Handling |
|---|---|---|---|
| `normal_baseline_clinical.pcap` | Normal traffic baseline | Baseline capture | Preserve original; hash if available |
| `phishing_click.pcap` | Phishing infrastructure contact | 2026-04-14 | Preserve original; hash if available |
| `c2_beaconing.pcap` | Repeated/C2-style traffic | Incident timeline | Preserve original; hash if available |
| `dns_exfil.pcap` | DNS tunneling investigation | Incident timeline | Preserve original; hash if available |
| `lateral_movement.pcap` | RDP/SMB investigation | 2026-04-15 | Preserve original; hash if available |
| `full_timeline.pcap` | VPN and timeline correlation | 2026-04-15 | Preserve original; hash if available |

Analysis was performed against investigation copies. Original evidence should remain unchanged.

Where SHA-256 hashes are available, they should be recorded alongside the original evidence files.

Example:

```bash
sha256sum *.pcap