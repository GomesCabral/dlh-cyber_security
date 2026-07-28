# 1. The CVE Deep Dive

## Goal

Research CVE-2023-27997 and assess its technical severity, exploit availability, and MedDefense-specific impact.

---

# Part 1 - NVD Research

## CVE

**CVE-2023-27997**

## Full Description

CVE-2023-27997 is a heap-based buffer overflow vulnerability in the SSL-VPN component of Fortinet FortiOS and FortiProxy. A remote, unauthenticated attacker may send specifically crafted requests to the exposed SSL-VPN service and execute arbitrary code or commands on the affected appliance.

Because exploitation occurs before authentication, the attacker does not require:

- a VPN account;
- a password;
- MFA approval;
- an existing authenticated session.

Successful exploitation may provide control of the perimeter firewall and VPN appliance.

---

## CVSS v3.1

**Base Score:** `9.8 — CRITICAL`

**Vector String:**

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Value | Meaning |
|---|---|---|
| Attack Vector | `AV:N` | Remotely exploitable over the network |
| Attack Complexity | `AC:L` | Low complexity |
| Privileges Required | `PR:N` | No account or privileges required |
| User Interaction | `UI:N` | No user action required |
| Scope | `S:U` | Scope unchanged |
| Confidentiality | `C:H` | High confidentiality impact |
| Integrity | `I:H` | High integrity impact |
| Availability | `A:H` | High availability impact |

---

## CWE Classification

- **CWE-122:** Heap-Based Buffer Overflow
- **CWE-787:** Out-of-Bounds Write

CWE-787 is the broader category. CWE-122 specifically identifies that the out-of-bounds write occurs in heap memory.

---

## Affected Products and Versions

### FortiOS

| Branch | Affected Versions |
|---|---|
| 7.2 | 7.2.0 through 7.2.4 |
| 7.0 | 7.0.0 through 7.0.11 |
| 6.4 | 6.4.0 through 6.4.12 |
| 6.2 | 6.2.0 through 6.2.13 |
| 6.0 | 6.0.0 through 6.0.16 |

### FortiProxy

| Branch | Affected Versions |
|---|---|
| 7.2 | 7.2.0 through 7.2.3 |
| 7.0 | 7.0.0 through 7.0.9 |
| 2.0 | 2.0.0 through 2.0.12 |
| 1.2 | Affected 1.2 releases |
| 1.1 | 1.1.0 through 1.1.6 |

---

## MedDefense Version Assessment

```text
Device: FortiGate 100F
Installed version: FortiOS 7.0.9
Affected range: FortiOS 7.0.0 through 7.0.11
Result: VULNERABLE
```

FortiOS 7.0.9 is inside the affected range.

---

## Vendor Advisory and Patch

**Vendor advisory:** `Fortinet PSIRT FG-IR-23-097`

For the FortiOS 7.0 branch, organisations must upgrade to a fixed release. The scenario identifies FortiOS 7.0.14 as available, which is newer than the first fixed 7.0 release.

Recommended action:

```text
Upgrade FortiOS 7.0.9 to FortiOS 7.0.14.
```

Emergency workaround when patching is not immediately possible:

```text
Disable SSL-VPN until the upgrade is completed.
```

---

## References

- NIST NVD — CVE-2023-27997
- Fortinet PSIRT — FG-IR-23-097
- CISA Known Exploited Vulnerabilities Catalog
- CISA Emergency Advisory AA26-077A supplied with the project

---

# Part 2 - Exploit Assessment

## SearchSploit Procedure

Update SearchSploit:

```bash
searchsploit -u
```

Search by CVE:

```bash
searchsploit --cve 2023-27997
```

Alternative searches:

```bash
searchsploit "FortiOS SSL VPN"
searchsploit "FortiGate 27997"
searchsploit -w --cve 2023-27997
```

## Exploit-DB Result

Document the exact result from the local SearchSploit database:

```text
No confirmed Exploit-DB entry was identified during this assessment.
```

An empty SearchSploit result does not prove that no public exploit exists. Exploit-DB is only one repository.

---

## Is There a Public Exploit?

**Yes.**

Public technical research and proof-of-concept material demonstrate exploitation of CVE-2023-27997. Public material includes vulnerability checks, heap-corruption analysis, exploit-development research, and remote-code-execution demonstrations.

A scanner or crash proof of concept is not always a reliable production-grade RCE exploit. However, public research combined with confirmed exploitation in the wild proves that the vulnerability is practically exploitable.

---

## Is It in the CISA KEV Catalog?

**Yes.**

```text
Date added: 13 June 2023
Required action: Apply updates according to vendor instructions
Federal due date: 4 July 2023
```

CISA KEV inclusion means there is evidence of real-world exploitation.

---

## Exploitability Score

**Score: `5/5 — Very High`**

### Scale

| Score | Meaning |
|---|---|
| 1 | Theoretical; no practical exploit known |
| 2 | Technical information exists, but exploitation is difficult |
| 3 | Limited proof of concept exists |
| 4 | Reliable public exploit or strong exploitation evidence |
| 5 | Active exploitation, low complexity, and practical public research |

### Justification

The vulnerability receives 5/5 because it is:

- remotely exploitable;
- pre-authentication;
- low complexity;
- unauthenticated;
- independent of user interaction;
- publicly researched;
- listed in CISA KEV;
- associated with known ransomware use;
- actively used against hospitals in the provided advisory.

---

# Part 3 - MedDefense CVSS Contextualisation

## Base Vector

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

## Base Score

**9.8 — CRITICAL**

---

## MedDefense Environmental Factors

The FortiGate:

- is the only perimeter defence;
- terminates all VPN tunnels;
- supports connectivity for all three sites;
- appears in kill chains 1, 2, and 3;
- provides a route into a flat internal network;
- cannot be patched through the normal process until the expired support contract is renewed.

### Security Requirements

| Metric | Value | Reason |
|---|---|---|
| Confidentiality Requirement | `CR:H` | Compromise may expose VPN credentials, routing data, and access to patient systems |
| Integrity Requirement | `IR:H` | The attacker may modify firewall rules, routes, VPN configuration, or traffic |
| Availability Requirement | `AR:H` | The appliance is the only perimeter defence and all three sites depend on it |

### Modified Metrics

```text
MAV:N
MAC:L
MPR:N
MUI:N
MS:U
MC:H
MI:H
MA:H
```

## Environmental Vector

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H
```

## Adjusted Environmental Score

**9.8 — CRITICAL**

## Higher or Lower Than the Base Score?

The adjusted score remains the same as the base score.

The base vector already represents:

- network exploitation;
- low complexity;
- no authentication;
- no user interaction;
- high confidentiality impact;
- high integrity impact;
- high availability impact.

The MedDefense environment makes remediation more urgent, but CVSS cannot exceed 10 and the base vector is already near the maximum.

---

## Factors Not Fully Represented by CVSS

CVSS does not directly score:

- the expired support contract;
- the delay in obtaining firmware;
- the FortiGate being the only perimeter appliance;
- the regional ransomware campaign;
- three nearby hospitals being affected;
- Hospital C being in active containment;
- clinical and patient-safety consequences.

These must be considered through threat intelligence, business impact, and risk analysis.

```text
CVSS score: 9.8
Exploitability score: 5/5
Operational priority: EMERGENCY
```

---

# Immediate Recommendation

1. Preserve the FortiGate configuration and logs.
2. Search for the advisory IOCs and unusual administrative activity.
3. Disable SSL-VPN if the appliance cannot be patched immediately.
4. Renew the FortiGate support contract or obtain firmware through an authorised channel.
5. Validate the upgrade path.
6. Upgrade FortiOS 7.0.9 to 7.0.14.
7. Verify firewall, VPN, routing, and site-to-site connectivity.
8. Reset VPN and privileged credentials that may have been exposed.
9. Enforce MFA for remote access.
10. Continue investigating for prior compromise after patching.

---

# Final Conclusion

CVE-2023-27997 is a critical pre-authentication remote-code-execution vulnerability affecting the FortiGate SSL-VPN service.

MedDefense runs FortiOS 7.0.9, which is within the affected 7.0.0–7.0.11 range. The vulnerability has a CVSS v3.1 base score of 9.8, is listed in CISA KEV, has public exploit research, and is associated with ransomware activity.

The MedDefense environmental score remains 9.8 because the technical base score is already near maximum. Nevertheless, the lack of perimeter redundancy, dependence on VPN connectivity, flat network, active healthcare targeting, and expired support contract make this an emergency operational risk.


# 1. The CVE Deep Dive

## Goal

Research CVE-2023-27997 and assess its technical severity, exploit availability, and MedDefense-specific impact.

---

# Part 1 - NVD Research

## CVE

**CVE-2023-27997**

## Full Description

CVE-2023-27997 is a heap-based buffer overflow vulnerability in the SSL-VPN component of Fortinet FortiOS and FortiProxy. A remote, unauthenticated attacker may send specifically crafted requests to the exposed SSL-VPN service and execute arbitrary code or commands on the affected appliance.

Because exploitation occurs before authentication, the attacker does not require:

- a VPN account;
- a password;
- MFA approval;
- an existing authenticated session.

Successful exploitation may provide control of the perimeter firewall and VPN appliance.

---

## CVSS v3.1

**Base Score:** `9.8 — CRITICAL`

**Vector String:**

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Value | Meaning |
|---|---|---|
| Attack Vector | `AV:N` | Remotely exploitable over the network |
| Attack Complexity | `AC:L` | Low complexity |
| Privileges Required | `PR:N` | No account or privileges required |
| User Interaction | `UI:N` | No user action required |
| Scope | `S:U` | Scope unchanged |
| Confidentiality | `C:H` | High confidentiality impact |
| Integrity | `I:H` | High integrity impact |
| Availability | `A:H` | High availability impact |

---

## CWE Classification

- **CWE-122:** Heap-Based Buffer Overflow
- **CWE-787:** Out-of-Bounds Write

CWE-787 is the broader category. CWE-122 specifically identifies that the out-of-bounds write occurs in heap memory.

---

## Affected Products and Versions

### FortiOS

| Branch | Affected Versions |
|---|---|
| 7.2 | 7.2.0 through 7.2.4 |
| 7.0 | 7.0.0 through 7.0.11 |
| 6.4 | 6.4.0 through 6.4.12 |
| 6.2 | 6.2.0 through 6.2.13 |
| 6.0 | 6.0.0 through 6.0.16 |

### FortiProxy

| Branch | Affected Versions |
|---|---|
| 7.2 | 7.2.0 through 7.2.3 |
| 7.0 | 7.0.0 through 7.0.9 |
| 2.0 | 2.0.0 through 2.0.12 |
| 1.2 | Affected 1.2 releases |
| 1.1 | 1.1.0 through 1.1.6 |

---

## MedDefense Version Assessment

```text
Device: FortiGate 100F
Installed version: FortiOS 7.0.9
Affected range: FortiOS 7.0.0 through 7.0.11
Result: VULNERABLE
```

FortiOS 7.0.9 is inside the affected range.

---

## Vendor Advisory and Patch

**Vendor advisory:** `Fortinet PSIRT FG-IR-23-097`

For the FortiOS 7.0 branch, organisations must upgrade to a fixed release. The scenario identifies FortiOS 7.0.14 as available, which is newer than the first fixed 7.0 release.

Recommended action:

```text
Upgrade FortiOS 7.0.9 to FortiOS 7.0.14.
```

Emergency workaround when patching is not immediately possible:

```text
Disable SSL-VPN until the upgrade is completed.
```

---

## References

- NIST NVD — CVE-2023-27997
- Fortinet PSIRT — FG-IR-23-097
- CISA Known Exploited Vulnerabilities Catalog
- CISA Emergency Advisory AA26-077A supplied with the project

---

# Part 2 - Exploit Assessment

## SearchSploit Procedure

Update SearchSploit:

```bash
searchsploit -u
```

Search by CVE:

```bash
searchsploit --cve 2023-27997
```

Alternative searches:

```bash
searchsploit "FortiOS SSL VPN"
searchsploit "FortiGate 27997"
searchsploit -w --cve 2023-27997
```

## Exploit-DB Result

Document the exact result from the local SearchSploit database:

```text
No confirmed Exploit-DB entry was identified during this assessment.
```

An empty SearchSploit result does not prove that no public exploit exists. Exploit-DB is only one repository.

---

## Is There a Public Exploit?

**Yes.**

Public technical research and proof-of-concept material demonstrate exploitation of CVE-2023-27997. Public material includes vulnerability checks, heap-corruption analysis, exploit-development research, and remote-code-execution demonstrations.

A scanner or crash proof of concept is not always a reliable production-grade RCE exploit. However, public research combined with confirmed exploitation in the wild proves that the vulnerability is practically exploitable.

---

## Is It in the CISA KEV Catalog?

**Yes.**

```text
Date added: 13 June 2023
Required action: Apply updates according to vendor instructions
Federal due date: 4 July 2023
```

CISA KEV inclusion means there is evidence of real-world exploitation.

---

## Exploitability Score

**Score: `5/5 — Very High`**

### Scale

| Score | Meaning |
|---|---|
| 1 | Theoretical; no practical exploit known |
| 2 | Technical information exists, but exploitation is difficult |
| 3 | Limited proof of concept exists |
| 4 | Reliable public exploit or strong exploitation evidence |
| 5 | Active exploitation, low complexity, and practical public research |

### Justification

The vulnerability receives 5/5 because it is:

- remotely exploitable;
- pre-authentication;
- low complexity;
- unauthenticated;
- independent of user interaction;
- publicly researched;
- listed in CISA KEV;
- associated with known ransomware use;
- actively used against hospitals in the provided advisory.

---

# Part 3 - MedDefense CVSS Contextualisation

## Base Vector

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

## Base Score

**9.8 — CRITICAL**

---

## MedDefense Environmental Factors

The FortiGate:

- is the only perimeter defence;
- terminates all VPN tunnels;
- supports connectivity for all three sites;
- appears in kill chains 1, 2, and 3;
- provides a route into a flat internal network;
- cannot be patched through the normal process until the expired support contract is renewed.

### Security Requirements

| Metric | Value | Reason |
|---|---|---|
| Confidentiality Requirement | `CR:H` | Compromise may expose VPN credentials, routing data, and access to patient systems |
| Integrity Requirement | `IR:H` | The attacker may modify firewall rules, routes, VPN configuration, or traffic |
| Availability Requirement | `AR:H` | The appliance is the only perimeter defence and all three sites depend on it |

### Modified Metrics

```text
MAV:N
MAC:L
MPR:N
MUI:N
MS:U
MC:H
MI:H
MA:H
```

## Environmental Vector

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H
```

## Adjusted Environmental Score

**9.8 — CRITICAL**

## Higher or Lower Than the Base Score?

The adjusted score remains the same as the base score.

The base vector already represents:

- network exploitation;
- low complexity;
- no authentication;
- no user interaction;
- high confidentiality impact;
- high integrity impact;
- high availability impact.

The MedDefense environment makes remediation more urgent, but CVSS cannot exceed 10 and the base vector is already near the maximum.

---

## Factors Not Fully Represented by CVSS

CVSS does not directly score:

- the expired support contract;
- the delay in obtaining firmware;
- the FortiGate being the only perimeter appliance;
- the regional ransomware campaign;
- three nearby hospitals being affected;
- Hospital C being in active containment;
- clinical and patient-safety consequences.

These must be considered through threat intelligence, business impact, and risk analysis.

```text
CVSS score: 9.8
Exploitability score: 5/5
Operational priority: EMERGENCY
```

---

# Immediate Recommendation

1. Preserve the FortiGate configuration and logs.
2. Search for the advisory IOCs and unusual administrative activity.
3. Disable SSL-VPN if the appliance cannot be patched immediately.
4. Renew the FortiGate support contract or obtain firmware through an authorised channel.
5. Validate the upgrade path.
6. Upgrade FortiOS 7.0.9 to 7.0.14.
7. Verify firewall, VPN, routing, and site-to-site connectivity.
8. Reset VPN and privileged credentials that may have been exposed.
9. Enforce MFA for remote access.
10. Continue investigating for prior compromise after patching.

---

# Final Conclusion

CVE-2023-27997 is a critical pre-authentication remote-code-execution vulnerability affecting the FortiGate SSL-VPN service.

MedDefense runs FortiOS 7.0.9, which is within the affected 7.0.0–7.0.11 range. The vulnerability has a CVSS v3.1 base score of 9.8, is listed in CISA KEV, has public exploit research, and is associated with ransomware activity.

The MedDefense environmental score remains 9.8 because the technical base score is already near maximum. Nevertheless, the lack of perimeter redundancy, dependence on VPN connectivity, flat network, active healthcare targeting, and expired support contract make this an emergency operational risk.


