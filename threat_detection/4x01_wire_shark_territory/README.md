# 4x01 — Wireshark Territory

## Project Overview

This project investigates a simulated phishing-driven compromise at **MedDefense Health Systems** using packet capture evidence.

The objective is to reconstruct attacker activity directly from network traffic and identify suspicious behavior including phishing activity, command-and-control communication, DNS tunneling, lateral movement and possible data exfiltration.

The investigation uses **TShark** for automated PCAP analysis and **Wireshark** for manual validation.

---

## Investigation Principles

The following principles are applied throughout the investigation:

- Packet captures are treated as primary network evidence.
- Every significant finding must include an exact timestamp.
- Automated PCAP analysis is performed with `tshark`.
- Wireshark is used for manual investigation and validation.
- Every important filter and command is documented.
- Findings are based on observable packet evidence.
- An anomalous event is not automatically considered malicious.
- Suspicious traffic is compared against the known-good baseline before classification.

---

## Evidence Files

The investigation uses the following PCAP files:

- `normal_baseline_clinical.pcap`
- `phishing_click.pcap`
- `c2_beaconing.pcap`
- `dns_exfil.pcap`
- `lateral_movement.pcap`
- `full_timeline.pcap`

---

# Task 0 — The Baseline

## Objective

Establish what normal MedDefense clinical network traffic looks like before the phishing incident.

The baseline provides a reference for identifying anomalies in later PCAP captures.

The analysis covers:

- protocol distribution
- application/service usage
- top source hosts
- top destinations
- DNS behavior
- DNS query types
- TLS metadata
- TCP connection duration
- traffic volume over time
- known-good domains and services

---

## Evidence

PCAP:

```text
normal_baseline_clinical.pcap
```

Capture duration:

```text
1798.08 seconds
≈ 29.97 minutes
```

Total packets:

```text
2842
```

Average traffic volume:

```text
≈ 95 packets/minute
```

The capture represents approximately 30 minutes of legitimate clinical network activity.

---

## Protocol Distribution

| Protocol | Packets | Percentage |
|---|---:|---:|
| TCP | 1742 | 61.29% |
| UDP | 1100 | 38.71% |
| ICMP | 0 | 0.00% |
| Other | 0 | 0.00% |

TCP is the dominant transport protocol, while UDP represents a significant portion of traffic primarily because of DNS and other UDP-based services.

No ICMP traffic was observed during the baseline period.

### TShark Filters

```bash
tshark -r normal_baseline_clinical.pcap -Y "tcp"
tshark -r normal_baseline_clinical.pcap -Y "udp"
tshark -r normal_baseline_clinical.pcap -Y "icmp || icmpv6"
```

---

## Application Layer Breakdown

| Service | Packets | Percentage |
|---|---:|---:|
| DNS | 1040 | 36.59% |
| HTTPS | 800 | 28.15% |
| Kerberos | 360 | 12.67% |
| Printing | 126 | 4.43% |
| SMB | 96 | 3.38% |
| NTP | 60 | 2.11% |
| LDAP | 0 | 0.00% |

DNS and HTTPS represent the largest portions of observed network activity.

The high DNS volume is important because later DNS-based anomalies must be evaluated against an already active DNS environment rather than assuming that DNS traffic itself is suspicious.

### Relevant Filters

```text
HTTPS:
tcp.port == 443

DNS:
udp.port == 53 || tcp.port == 53

Kerberos:
tcp.port == 88 || udp.port == 88

LDAP:
tcp.port == 389 || udp.port == 389

SMB:
tcp.port == 445

NTP:
udp.port == 123

Printing:
tcp.port == 9100
```

---

## Top Source IPs by Bytes

The most active source systems were:

| Source IP | Data |
|---|---:|
| 10.10.20.5 | 0.25 MB |
| 10.10.1.1 | 0.06 MB |
| 151.101.1.140 | 0.05 MB |
| 140.82.112.4 | 0.04 MB |
| 204.79.197.200 | 0.04 MB |
| 13.107.42.14 | 0.04 MB |
| 10.10.2.41 | 0.04 MB |
| 52.96.10.45 | 0.04 MB |
| 10.10.2.22 | 0.04 MB |
| 10.10.2.31 | 0.03 MB |

`10.10.20.5` generated the largest amount of traffic during the baseline period.

High traffic volume alone is not evidence of malicious activity. These values provide a reference for detecting unusual traffic volume in later captures.

---

## Top Destination IPs

Top destinations by observed TCP connections:

| Destination | Connections |
|---|---:|
| 10.10.20.5 | 180 |
| 10.10.2.70 | 35 |
| 10.10.2.41 | 30 |
| 10.10.2.80 | 29 |
| 10.10.2.31 | 29 |
| 10.10.2.22 | 27 |
| 10.10.2.15 | 26 |
| 10.10.2.75 | 23 |
| 10.10.2.40 | 23 |
| 10.10.2.55 | 22 |

These systems represent frequently contacted destinations during normal network operations.

---

# DNS Baseline

DNS activity is particularly important because later stages of the investigation may involve DNS tunneling.

## DNS Query Volume

```text
Total DNS queries: 520
Average DNS rate: 17.35 queries/minute
```

This establishes:

```text
NORMAL DNS RATE ≈ 17.35 queries/minute
```

Future DNS activity can be compared directly against this value.

---

## Top Queried Domains

| Domain | Queries |
|---|---:|
| pacs.meddefense.com | 77 |
| outlook.office365.com | 71 |
| windows.com | 68 |
| time.windows.com | 66 |
| www.bing.com | 64 |
| login.microsoftonline.com | 60 |
| meddefense.com | 58 |
| ehr.meddefense.com | 56 |

These domains represent known-good DNS activity observed during the baseline.

---

## DNS Query Types

| Type | Queries |
|---|---:|
| A | 421 |
| AAAA | 79 |
| MX | 13 |
| TXT | 7 |

Most queries are standard A and AAAA address resolution requests.

TXT queries are rare.

```text
TXT queries: 7
TXT rate: 0.234 queries/minute
```

Therefore:

```text
NORMAL TXT RATE ≈ 0.234 queries/minute
```

This metric will be especially important when investigating potential DNS tunneling.

A significant increase in TXT queries combined with long encoded subdomains, unusual destinations and regular timing would represent a strong deviation from the baseline.

---

# TLS Baseline

## Observed SNI Values

The following TLS Server Name Indication values were observed:

```text
api.github.com
login.microsoftonline.com
outlook.office365.com
windows.com
www.bing.com
```

These represent known TLS destinations during normal network activity.

SNI metadata can help identify the destination hostname of encrypted HTTPS connections even when the application payload cannot be inspected.

---

## TLS Versions

Observed TLS record versions included:

```text
0x0303
0x0301
```

TLS metadata provides useful information even when encrypted traffic cannot be decrypted.

Network investigations can still analyze:

- source and destination IPs
- ports
- timestamps
- SNI
- TLS metadata
- connection duration
- transferred bytes
- communication frequency

Certificate issuer information was not available from the captured traffic using the selected extraction method.

No certificate issuer values were invented or assumed.

---

# Connection Duration Baseline

TCP streams were classified according to their observed duration.

| Duration | Connections | Percentage |
|---|---:|---:|
| Short (<1 second) | 222 | 75.00% |
| Medium (1–30 seconds) | 68 | 22.97% |
| Long (>30 seconds) | 6 | 2.03% |

Most legitimate TCP connections in the baseline are short.

Therefore, a short connection alone should not be considered suspicious.

For later C2 beaconing analysis, connection **regularity, destination, frequency and transferred data** must also be considered.

---

# Temporal Traffic Pattern

The baseline shows relatively stable network activity throughout the approximately 30-minute capture.

Most one-minute intervals contain approximately:

```text
50–120 packets/minute
```

An observed legitimate peak occurred at:

```text
08:05 → 167 packets
```

The overall average is approximately:

```text
95 packets/minute
```

The network therefore shows normal variation rather than perfectly constant traffic.

Future traffic spikes should be compared against this natural variation before being classified as anomalous.

---

# Baseline Signatures

The following values establish the initial known-good network profile:

| Indicator | Baseline |
|---|---:|
| Capture duration | ~30 minutes |
| Total packets | 2842 |
| Average packet volume | ~95 packets/min |
| TCP | 61.29% |
| UDP | 38.71% |
| ICMP | 0% |
| DNS traffic | 36.59% |
| HTTPS traffic | 28.15% |
| DNS queries | 520 |
| Normal DNS rate | **17.35 queries/min** |
| TXT queries | 7 |
| Normal TXT rate | **0.234 queries/min** |
| Short TCP connections | 75.00% |
| Medium TCP connections | 22.97% |
| Long TCP connections | 2.03% |

---

## Known-Good DNS Domains

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

## Known-Good TLS SNI

```text
api.github.com
login.microsoftonline.com
outlook.office365.com
windows.com
www.bing.com
```

---

# SOC Interpretation

The baseline establishes that the clinical network normally contains significant DNS and HTTPS traffic.

Therefore, future DNS or HTTPS activity should not be considered malicious simply because those protocols are present.

The investigation should instead look for deviations such as:

- previously unseen domains
- unusual external IP addresses
- significant increases in DNS TXT queries
- long or encoded DNS labels
- highly regular connection intervals
- unusual traffic volumes
- unexpected protocols
- abnormal connection durations
- communication patterns not present in the baseline

An important investigation principle is:

> **Anomalous does not automatically mean malicious.**

An anomaly identifies behavior that differs from the known baseline and requires further investigation.

---

# Key Baseline Values for Later Tasks

## DNS Tunneling Comparison

```text
Normal DNS rate: 17.35 queries/min
Normal TXT rate: 0.234 queries/min
TXT queries in 30 minutes: 7
```

These values will be compared against DNS activity observed during the suspected exfiltration period.

## C2 Beaconing Comparison

```text
75% of TCP connections last less than one second.
Normal external communication is expected to have variable timing.
```

Therefore, short connections alone are insufficient to identify C2 activity.

Later beaconing analysis must consider:

```text
same source
      +
same destination
      +
repeated connections
      +
regular intervals
      +
similar duration/size
      +
deviation from baseline
```

---

# Generated Baseline Artifact

The analysis script generates:

```text
baseline_clinical.json
```

Current baseline values:

```json
{
  "pcap": "7fe2b4e3acd872e34f7ec949f63e606fc5496f33.pcap",
  "total_packets": 2842,
  "duration_seconds": 1798.08,
  "dns_queries": 520,
  "dns_queries_per_minute": 17.35,
  "txt_queries": 7,
  "txt_queries_per_minute": 0.234
}
```

This structured baseline can be reused by later investigation scripts to compare suspicious traffic against known-good behavior.

---

## Task 0 Conclusion

The baseline capture represents approximately 30 minutes of legitimate clinical network activity.

Normal traffic is dominated by TCP and UDP, with DNS and HTTPS accounting for a large proportion of observed packets.

DNS activity averages **17.35 queries per minute**, while TXT queries are uncommon at only **0.234 queries per minute**.

Most TCP connections are short-lived, and normal traffic volume is relatively stable with natural minute-to-minute variation.

These measurements establish the reference point that will be used to identify and quantify anomalies throughout the remaining investigation.

---

## Investigation Progress

```text
[✓] Task 0 — The Baseline
[ ] Task 1
[ ] Task 2
[ ] Task 3
[ ] Task 4
[ ] Task 5
[ ] Task 6
[ ] Task 7
[ ] Task 8
[ ] Task 9
[ ] Task 10
[ ] Task 11
[ ] Task 12
```
