# 4x01 — Wireshark Territory

## Network Forensics Investigation

This project investigates a multi-stage compromise of the fictional MedDefense environment using packet-capture analysis.

The investigation follows network evidence from normal baseline activity through phishing infrastructure contact, command-and-control behavior, external VPN access, lateral movement and DNS-based data exfiltration.

The central investigation principle is:

> Packet evidence must be separated from analytical inference.

---

## Project Objectives

The project demonstrates practical network-forensics skills including:

- PCAP analysis with Wireshark and `tshark`
- traffic baselining
- DNS investigation
- TLS metadata analysis
- behavioral C2 detection
- VPN investigation
- RDP and SMB analysis
- lateral-movement reconstruction
- DNS tunneling detection
- MITRE ATT&CK mapping
- kill-chain reconstruction
- detection engineering
- evidence validation
- incident reporting

---

## Tools

Primary tools used:

```text
Wireshark
tshark
Bash
awk
grep
sort
base32
base64
whois
shellcheck
```

All automated PCAP analysis is performed with `tshark`.

---

## Evidence

The project uses six packet captures:

| PCAP | Purpose |
|---|---|
| `normal_baseline_clinical.pcap` | Establish normal network behavior |
| `phishing_click.pcap` | Analyze interaction with phishing infrastructure |
| `c2_beaconing.pcap` | Analyze repeated C2-like communication |
| `dns_exfil.pcap` | Analyze DNS tunneling and exfiltration |
| `lateral_movement.pcap` | Reconstruct internal RDP/SMB activity |
| `full_timeline.pcap` | Correlate VPN access with the incident timeline |

---

# Investigation Tasks

## Task 0 — Normal Baseline

**Objective:** Establish normal MedDefense network behavior.

Script:

```text
0-baseline.sh
```

The baseline capture contained:

- 2,842 packets
- 1,798.08 seconds of traffic
- 61.29% TCP
- 38.71% UDP

Normal DNS activity:

```text
DNS queries:      17.35/min
TXT queries:       0.234/min
```

Common legitimate domains included:

```text
pacs.meddefense.com
outlook.office365.com
windows.com
time.windows.com
www.bing.com
login.microsoftonline.com
meddefense.com
ehr.meddefense.com
```

This baseline is used throughout the investigation to distinguish expected from anomalous activity.

---

## Task 1 — The Click in the Wire

**Objective:** Investigate the network activity generated after interaction with the phishing campaign.

Script:

```text
1-phishing_click.sh
```

Key evidence:

```text
10.10.2.15
      |
      | DNS
      v
meddefense-portal.com
      |
      v
91.234.99.107
      |
      | TLS / 443
      v
Encrypted phishing session
```

The phishing domain resolved to:

```text
91.234.99.107
```

TLS SNI independently confirmed:

```text
meddefense-portal.com
```

A 487-byte encrypted client payload was observed approximately 25 seconds after connection establishment.

The encrypted content cannot be read directly, so credential submission is treated as strong inference rather than confirmed plaintext evidence.

---

## Task 2 — C2 Beaconing

**Objective:** Identify automated repeated communication consistent with command-and-control beaconing.

Script:

```text
2-c2_beaconing.sh
```

The investigation focuses on:

- repeated connections
- source/destination pairs
- communication interval
- mean interval
- standard deviation
- jitter
- session volume
- comparison with baseline behavior

MITRE ATT&CK:

```text
T1071.001 — Application Layer Protocol: Web Protocols
```

> Final exact Task 2 statistics should be populated from the completed dedicated beaconing analysis.

---

## Task 3 — The DNS Tunnel

**Objective:** Detect and analyze DNS-based data exfiltration.

Script:

```text
3-dns_tunnel.sh
```

Source:

```text
billing-srv-01
10.10.1.10
```

Anomalous domain:

```text
data-sync.meddefense-portal.com
```

Results:

```text
Total DNS queries:       487
Normal queries:          367
Anomalous queries:       120

Anomalous TXT rate:      4.85/min
Baseline TXT rate:       0.234/min
Increase:                ~20.7x

Encoded characters:      6263
Estimated raw data:      ~3914 bytes
```

Decoded Base32 fragments referenced:

```text
patient_record
financial_record
backup_metadata
server_config
```

MITRE ATT&CK:

```text
T1048.003 — Exfiltration Over Alternative Protocol
```

---

## Task 4 — The Lateral Trail

**Objective:** Reconstruct lateral movement across the internal network.

Script:

```text
4-lateral_movement.sh
```

Initial RDP activity:

```text
10.10.2.15
     |
     | RDP / TCP 3389
     v
10.10.1.10
billing-srv-01
```

Subsequent SMB activity originated from `10.10.1.10` toward:

```text
10.10.1.20
10.10.1.30
10.10.1.31
10.10.4.100
10.10.4.101
10.10.1.60
```

Attempts toward `10.10.4.100` and `10.10.4.101` were followed by reset/refusal behavior.

MITRE ATT&CK:

```text
T1021.001 — Remote Desktop Protocol
T1021.002 — SMB/Windows Admin Shares
```

Application-level SMB enumeration was not fully decoded and is therefore not overclaimed.

---

## Task 5 — The VPN Pivot

**Objective:** Identify the external VPN connection linking credential compromise with internal activity.

Script:

```text
5-vpn_pivot.sh
```

VPN evidence:

```text
Source:
154.118.42.89:49872

Destination:
10.10.0.1:443

TLS SNI:
vpn.meddefense.com

Account context:
dmarsh
```

VPN connection:

```text
2026-04-15 15:45:22 +0200
```

First RDP activity:

```text
2026-04-15 16:30:12 +0200
```

Gap:

```text
44.84 minutes
```

Observed VPN TCP session duration:

```text
~2904.97 seconds
~48.4 minutes
```

MITRE ATT&CK:

```text
T1133 — External Remote Services
```

---

## Task 6 — The Kill Chain Reconstruction

**Objective:** Combine the individual PCAP findings into a single chronological incident timeline.

Script:

```text
6-kill_chain.sh
```

Attack sequence:

```text
Phishing campaign
        |
        v
Phishing infrastructure contact
        |
        v
Credential exposure suspected
        |
        v
C2-like communication
        |
        v
External VPN access
        |
        v
RDP lateral movement
        |
        v
SMB internal activity
        |
        v
DNS tunneling / exfiltration
```

Each phase is mapped to MITRE ATT&CK and separated into:

```text
CONFIRMED
STRONG INFERENCE
UNCONFIRMED
```

---

## Task 7 — Detection Engineering

**Objective:** Convert forensic findings into operational detection rules.

Script:

```text
7-detection_rules.sh
```

Six detection strategies were developed:

| Detection | Purpose |
|---|---|
| C2 Beaconing | Detect periodic outbound communications |
| DNS Label Length | Detect abnormally long DNS labels |
| VPN Geo/ASN Anomaly | Detect unusual VPN origins |
| Cross-Role RDP | Detect inappropriate workstation-to-server RDP |
| DNS TXT Tunnel | Detect high-frequency encoded TXT queries |
| TLS Campaign IOC | Detect TLS SNI matching phishing infrastructure |

The objective is to transform incident intelligence into reusable defensive controls.

---

## Task 8 — The Evidence Cross-Check

**Objective:** Determine what packet evidence proves and what remains inference.

Script:

```text
8-evidence_crosscheck.sh
```

Evidence is classified as:

```text
CONFIRMED
STRONG INFERENCE
UNCONFIRMED
NOT VISIBLE IN PCAP
```

Direct network evidence exists for six of seven primary kill-chain phases.

Packet visibility:

```text
6 / 7
~85%
```

The central lesson is:

> Packets show communication and network behavior. Logs provide system, identity and application context.

---

## Task 9

Task 9 forms part of the complete 4x01 workflow.

Its final description and findings should be documented here using the results of the completed Task 9 analysis.

> Do not add findings that have not been supported by the corresponding task evidence.

---

## Task 10

Task 10 forms part of the complete 4x01 workflow.

Its final description and findings should be documented here using the results of the completed Task 10 analysis.

> Do not add findings that have not been supported by the corresponding task evidence.

---

## Task 11 — Network Forensics Report

**Objective:** Produce the final incident-response deliverable.

Report:

```text
11-network_forensics_report.md
```

The report contains:

- Executive Summary
- Investigation Scope
- Methodology
- Findings by Attack Phase
- Network-Level IOC Table
- Impact Assessment
- Detection Gap Analysis
- Detection Rules Recommended
- Recommendations
- Evidence Chain
- Continuity with 4x00

The final report maintains a strict distinction between packet evidence and analytical inference.

---

# Master Incident Timeline

| Timestamp | Event |
|---|---|
| 2026-04-14 17:02:33 | Phishing domain resolved |
| 2026-04-14 17:02:33 | TLS connection to phishing infrastructure |
| 2026-04-14 17:02:58 | 487-byte encrypted client TLS payload |
| 2026-04-14 17:03:20 | Phishing TLS session closes |
| 2026-04-15 15:45:22 | External VPN connection begins |
| 2026-04-15 16:30:12 | RDP activity toward billing-srv-01 |
| 2026-04-15 16:35:22 | SMB activity begins from billing-srv-01 |
| 2026-04-15 16:38:07 | Restricted endpoint connection attempts |
| 2026-04-15 16:40:33 | SMB connection toward 10.10.1.60 |
| Later incident activity | DNS tunneling/exfiltration observed |

---

# MITRE ATT&CK Mapping

| Technique | Description | Evidence |
|---|---|---|
| T1566.002 | Spearphishing Link | 4x00 campaign context |
| T1056.003 | Web Portal Capture | Phishing-session context |
| T1071.001 | Web Protocols | C2 communication |
| T1133 | External Remote Services | VPN pivot |
| T1021.001 | Remote Desktop Protocol | RDP lateral movement |
| T1021.002 | SMB/Windows Admin Shares | Internal SMB activity |
| T1048.003 | Exfiltration Over Alternative Protocol | DNS tunnel |

---

# Indicators of Compromise

| Type | Indicator |
|---|---|
| Domain | `meddefense-portal.com` |
| Domain | `data-sync.meddefense-portal.com` |
| IPv4 | `91.234.99.107` |
| External IPv4 | `154.118.42.89` |
| Account Context | `dmarsh` |

Important internal investigation pivots:

```text
10.10.2.15
10.10.1.10
10.10.0.1
10.10.2.200
```

---

# Key Findings

The investigation established direct network contact between a MedDefense workstation and known phishing infrastructure.

An external VPN-style session associated with `dmarsh` context occurred before internal RDP activity.

The billing server subsequently initiated SMB connections toward multiple internal systems.

DNS traffic later carried encoded structured information at a TXT query rate approximately 20.7 times the established baseline.

The observed sequence supports a multi-stage network compromise.

---

# Evidence vs Inference

## Confirmed

Examples:

```text
DNS query occurred.
TCP connection occurred.
TLS SNI contained a specific hostname.
RDP/3389 communication occurred.
SMB/445 communication occurred.
Encoded DNS labels contained structured fragments.
```

## Strong Inference

Examples:

```text
Encrypted web traffic was a credential submission.
VPN activity represents use of previously stolen credentials.
DNS tunneling was used to exfiltrate the observed structured data.
```

## Not Proven by PCAP Alone

Examples:

```text
Exact password entered
Attacker identity
User intent
Endpoint process execution
MFA decision
SIEM alert status
Complete attacker-side receipt of data
```

---

# Detection Recommendations

Priority detections developed from this investigation:

1. C2 periodicity detection.
2. Long DNS label detection.
3. High-frequency TXT query detection.
4. VPN GeoIP/ASN anomaly detection.
5. Cross-role RDP detection.
6. TLS SNI matching against phishing campaign IOCs.

---

# Final Conclusion

This investigation demonstrates how individual packet observations can be transformed into a complete incident narrative.

The evidence supports a progression from phishing infrastructure contact to account-associated VPN access, internal RDP/SMB activity and DNS-based data transfer.

The project also demonstrates an important network-forensics principle:

> Never claim more than the evidence proves.

Network evidence is highly effective for reconstructing communication, timing, protocols and behavioral patterns, but endpoint, identity and application logs are required to answer questions that encrypted packet traffic cannot resolve.