# 6. The ALE Workshop

## Purpose and Method

This workshop converts MedDefense's highest-priority cybersecurity risks into annual financial exposure. Each calculation combines evidence from the Security Posture Assessment (1x00), Threat Landscape (1x01), and Vulnerability Assessment (1x02).

The formulas used are:

```text
SLE = Asset Value (AV) × Exposure Factor (EF)
ALE = Single Loss Expectancy (SLE) × Annualized Rate of Occurrence (ARO)
Net Benefit = ALE Before Control − ALE After Control − Annual Control Cost
```

The values are estimates for decision-making rather than guaranteed losses. They should be reviewed annually and updated when MedDefense obtains better incident, insurance, legal, and operational data.

---

# Risk 1 — EHR Data Breach and Ransomware

## Risk

An external attacker or ransomware affiliate compromises the EHR application environment, steals patient records, and disrupts clinical access.

## Source

- **Gap:** Flat network, no SIEM, weak segmentation, and incomplete patch management
- **Vulnerability Findings:** Finding 031 (Ghostcat), Finding 003 (unrestricted PostgreSQL access), Finding 017 (Tomcat information disclosure)
- **Threat Actor:** Ransomware affiliate or financially motivated cybercriminal
- **Attack Path:** Internal foothold → Ghostcat exploitation → credential theft → EHR database access → exfiltration/encryption

## Asset

`ehr-srv-01` and `ehr-db-01`

## Asset Value (AV)

**AV = $9,075,000**

Reasoning:

- **Replacement/recovery cost:** included in the healthcare breach cost per record
- **Patient records:** 50,000 × $165 = **$8,250,000**
- **Revenue loss during downtime:** included conservatively in incident and lost-business estimates
- **Breach notification and credit monitoring:** **$25,000**
- **Litigation exposure:** **$200,000**
- **Reputation and patient-trust impact:** **$600,000**

```text
AV = $8,250,000 + $25,000 + $200,000 + $600,000
AV = $9,075,000
```

## Exposure Factor (EF)

**EF = 100%**

### Reasoning

A major EHR breach triggers nearly all costs: notification, legal response, regulatory reporting, patient attrition, investigation, recovery, and clinical disruption. The system may be technically restored, but the financial impact of the incident has already occurred.

## Single Loss Expectancy (SLE)

```text
SLE = AV × EF
SLE = $9,075,000 × 1.00
SLE = $9,075,000
```

## Annualized Rate of Occurrence (ARO)

**ARO = 0.33**

### Reasoning

The sector estimate is approximately one significant healthcare breach every three years. MedDefense is above average risk because it has no SIEM, a flat network, known exploitable vulnerabilities, and unrestricted EHR database access.

## Annualized Loss Expectancy (ALE)

```text
ALE = SLE × ARO
ALE = $9,075,000 × 0.33
ALE = $2,994,750
```

## Proposed Control

Patch Tomcat and disable or restrict AJP, restrict PostgreSQL to the EHR application server, rotate database credentials, deploy network segmentation, and implement centralized monitoring.

## Control Annual Cost

**$45,000**

This includes managed SIEM/log monitoring, segmentation work, technical labor, and ongoing vulnerability management.

## Estimated ALE After Control

Assume the control package reduces ARO from **0.33 to 0.08**.

```text
ALE After Control = $9,075,000 × 0.08
ALE After Control = $726,000
```

## Net Benefit

```text
Net Benefit = ALE Before − ALE After − Control Cost
Net Benefit = $2,994,750 − $726,000 − $45,000
Net Benefit = $2,223,750
```

## Confidence

**Medium**

The cost-per-record estimate is evidence-based, but the actual breach size and probability could vary significantly.

---

# Risk 2 — FortiGate VPN Compromise Enables Enterprise-Wide Attack

## Risk

An external attacker exploits a FortiGate vulnerability or stolen VPN credentials and gains access to the flat MedDefense internal network.

## Source

- **Gap:** Sole perimeter gateway, flat internal network, unknown firewall patch cadence
- **Vulnerability Evidence:** FortiOS OSINT finding from 1x02 T9, plus network posture findings
- **Threat Actor:** Ransomware affiliate, initial-access broker, or advanced cybercriminal
- **Attack Path:** VPN compromise → internal discovery → Active Directory/EHR/billing/backup access → data theft and ransomware

## Asset

FortiGate VPN and the MedDefense enterprise network

## Asset Value (AV)

**AV = $9,648,000**

Reasoning:

- **Billing ransomware impact:** **$573,000**
- **EHR breach impact:** **$9,075,000**
- The VPN is the gateway to both environments.

```text
AV = $573,000 + $9,075,000
AV = $9,648,000
```

This estimate does not include every workstation, medical device, or Active Directory recovery cost, so it is conservative.

## Exposure Factor (EF)

**EF = 100%**

### Reasoning

A successful VPN compromise can expose the complete flat network. If the attacker executes the full ransomware and exfiltration chain, nearly the entire modeled loss is realized.

## Single Loss Expectancy (SLE)

```text
SLE = $9,648,000 × 1.00
SLE = $9,648,000
```

## Annualized Rate of Occurrence (ARO)

**ARO = 0.30**

### Reasoning

The scenario data estimates approximately one successful compromise every three years. MedDefense's risk is increased by unknown FortiGate patching, one perimeter device for three sites, and broad internal access after VPN authentication.

## Annualized Loss Expectancy (ALE)

```text
ALE = $9,648,000 × 0.30
ALE = $2,894,400
```

## Proposed Control

Patch FortiOS promptly, require phishing-resistant MFA for VPN administrators and users, restrict administrative access, monitor VPN anomalies, and segment VPN users from critical systems.

## Control Annual Cost

**$35,000**

This includes MFA licensing, managed firewall support, monitoring, configuration review, and segmentation changes.

## Estimated ALE After Control

Assume ARO falls from **0.30 to 0.08**.

```text
ALE After Control = $9,648,000 × 0.08
ALE After Control = $771,840
```

## Net Benefit

```text
Net Benefit = $2,894,400 − $771,840 − $35,000
Net Benefit = $2,087,560
```

## Confidence

**Medium**

The largest uncertainty is whether one VPN compromise would lead to the complete enterprise-loss scenario.

---

# Risk 3 — Negligent Insider Exposes Patient Data

## Risk

An employee accidentally transfers, emails, copies, or loses sensitive patient information through an unmanaged process or removable media.

## Source

- **Gap:** No DLP, unrestricted USB devices, incomplete security awareness training
- **Vulnerability Findings:** Finding 023 (USB storage unrestricted), weak data-handling controls from 1x00
- **Threat Actor:** Negligent insider
- **Attack Path:** Authorized access → accidental copying or disclosure → regulatory reporting and remediation

## Asset

Patient information accessed through approximately 280 clinical workstations

## Asset Value (AV)

**AV = $120,000 per incident**

Reasoning:

- **Investigation:** $30,000
- **Containment:** $25,000
- **Remediation:** $40,000
- **Regulatory reporting:** $25,000

```text
AV = $30,000 + $25,000 + $40,000 + $25,000
AV = $120,000
```

## Exposure Factor (EF)

**EF = 100%**

### Reasoning

The provided average already represents the total cost of one negligent-insider incident, so the entire value is exposed when the event occurs.

## Single Loss Expectancy (SLE)

```text
SLE = $120,000 × 1.00
SLE = $120,000
```

## Annualized Rate of Occurrence (ARO)

**ARO = 2.5**

### Reasoning

MedDefense has 2,000 staff, 280 clinical workstations, no DLP, unrestricted USB use, and no mature awareness program. The scenario estimates two to three incidents per year, so the midpoint is used.

## Annualized Loss Expectancy (ALE)

```text
ALE = $120,000 × 2.5
ALE = $300,000
```

## Proposed Control

Deploy USB restrictions and endpoint DLP, implement role-based data-handling policies, and provide mandatory annual awareness training with phishing and privacy exercises.

## Control Annual Cost

**$30,000**

## Estimated ALE After Control

Assume the controls reduce ARO from **2.5 to 0.75 incidents per year**.

```text
ALE After Control = $120,000 × 0.75
ALE After Control = $90,000
```

## Net Benefit

```text
Net Benefit = $300,000 − $90,000 − $30,000
Net Benefit = $180,000
```

## Confidence

**High**

The average incident cost and expected annual frequency are both supported by healthcare-sector data, although MedDefense's actual reporting culture may change the observed number.

---

# Risk 4 — Ransomware Compromises the Billing Server

## Risk

A ransomware affiliate exploits Apache on `billing-srv-01`, escalates to root, and encrypts or steals billing and financial data.

## Source

- **Gap:** Unsupported Ubuntu, weak patching, flat network, SSH password authentication
- **Vulnerability Findings:** Finding 001 (Apache RCE), Finding 002 (privilege escalation), Finding 006 (MySQL exposure), Finding 011 (Ubuntu without ESM)
- **Threat Actor:** BlackReef-style ransomware group
- **Attack Path:** Apache exploitation → privilege escalation → billing database access → ransomware and exfiltration

## Asset

`billing-srv-01`

## Asset Value (AV)

**AV = $573,000**

Reasoning:

- **Replacement/recovery and forensics:** $85,000
- **Revenue loss:** $16,000/day × 18 days = $288,000
- **Regulatory penalty:** $100,000
- **Financial records and business impact:** $100,000

```text
AV = $85,000 + $288,000 + $100,000 + $100,000
AV = $573,000
```

## Exposure Factor (EF)

**EF = 80%**

### Reasoning

Ransomware would severely disrupt billing and cause recovery, revenue, and regulatory costs, but the hardware and application may ultimately be restored.

## Single Loss Expectancy (SLE)

```text
SLE = $573,000 × 0.80
SLE = $458,400
```

## Annualized Rate of Occurrence (ARO)

**ARO = 0.29**

### Reasoning

The healthcare-sector rate is approximately one ransomware attack every 3–4 years. MedDefense's outdated software and chainable public exploits justify using the midpoint of once every 3.5 years.

## Annualized Loss Expectancy (ALE)

```text
ALE = $458,400 × 0.29
ALE = $132,936
```

## Proposed Control

Patch Apache, remove or disable `mod_lua`, rebuild the server on a supported Ubuntu LTS release, restrict MySQL, enforce SSH keys, and deploy endpoint monitoring.

## Control Annual Cost

**$25,000**

## Estimated ALE After Control

Assume ARO is reduced from **0.29 to 0.08**.

```text
ALE After Control = $458,400 × 0.08
ALE After Control = $36,672
```

## Net Benefit

```text
Net Benefit = $132,936 − $36,672 − $25,000
Net Benefit = $71,264
```

## Confidence

**Medium**

The main uncertainty is the real probability of successful ransomware exploitation and the length of billing downtime.

---

# Risk 5 — Compromise of BD Alaris Infusion Pumps

## Risk

An attacker uses default credentials or flat-network access to disrupt infusion-pump availability or contribute to an unsafe clinical event.

## Source

- **Gap:** Default credentials, no medical-device VLAN, weak device-access controls
- **Vulnerability Findings:** Finding 010 (BD Alaris pumps), Finding 016 (medical-device interfaces)
- **Threat Actor:** Opportunistic attacker, malicious insider, or ransomware operator
- **Attack Path:** Internal foothold → medical-device discovery → unauthorized access → disruption or unsafe operation

## Asset

Seven BD Alaris infusion pumps and their clinical workflow

## Asset Value (AV)

**AV = $5,150,000**

Reasoning for the catastrophic patient-safety scenario:

- **Patient liability:** $5,000,000
- **FDA investigation:** $150,000

The pump replacement cost and five days of manual operations are smaller than the potential patient-safety liability and are not added again to avoid overstating overlapping costs.

## Exposure Factor (EF)

**EF = 100%**

### Reasoning

A successful patient-safety event could trigger the full modeled legal and regulatory impact.

## Single Loss Expectancy (SLE)

```text
SLE = $5,150,000 × 1.00
SLE = $5,150,000
```

## Annualized Rate of Occurrence (ARO)

**ARO = 0.02**

### Reasoning

A catastrophic patient-safety cyber event is rare, estimated at once every 50 years. MedDefense's default credentials and flat network make the event more plausible than in a well-segmented environment.

## Annualized Loss Expectancy (ALE)

```text
ALE = $5,150,000 × 0.02
ALE = $103,000
```

## Proposed Control

Change default credentials, isolate the pumps in a medical-device VLAN, restrict management access, validate firmware with BD, and monitor device communications.

## Control Annual Cost

**$20,000**

## Estimated ALE After Control

Assume ARO falls from **0.02 to 0.005**, or approximately once every 200 years.

```text
ALE After Control = $5,150,000 × 0.005
ALE After Control = $25,750
```

## Net Benefit

```text
Net Benefit = $103,000 − $25,750 − $20,000
Net Benefit = $57,250
```

## Confidence

**Low**

Patient-safety cyber incidents are rare and difficult to model. The assumed liability and ARO are the largest sources of uncertainty.

---

# Risk Prioritization by ALE

| Rank | Risk | ALE Before Control | Control Cost | ALE After Control | Net Benefit |
|---:|---|---:|---:|---:|---:|
| 1 | EHR data breach and ransomware | $2,994,750 | $45,000 | $726,000 | $2,223,750 |
| 2 | FortiGate VPN compromise | $2,894,400 | $35,000 | $771,840 | $2,087,560 |
| 3 | Negligent insider data exposure | $300,000 | $30,000 | $90,000 | $180,000 |
| 4 | Billing-server ransomware | $132,936 | $25,000 | $36,672 | $71,264 |
| 5 | Infusion-pump patient-safety event | $103,000 | $20,000 | $25,750 | $57,250 |

---

# Investment Summary

| Item | Amount |
|---|---:|
| Total ALE before controls | $6,425,086 |
| Total annual control cost | $155,000 |
| Total estimated ALE after controls | $1,650,262 |
| Total gross risk reduction | $4,774,824 |
| Total net benefit | $4,619,824 |

The complete control package exceeds MedDefense's $120,000 annual security budget by **$35,000**. Based on ALE and net benefit, MedDefense should first fund the EHR, VPN, and negligent-insider controls, which together cost **$110,000** and address approximately **$6.19 million** in annualized loss exposure before controls.

The billing and medical-device control packages should not be ignored. Immediate low-cost actions, such as patching Apache and changing default pump credentials, should still be performed, while the more expensive migration and segmentation elements are phased into the following budget period.

---

# Conclusion

The ALE analysis shows that the highest technical CVSS score is not automatically the highest financial risk. EHR compromise and VPN access dominate because they expose large amounts of regulated patient data and provide paths to multiple critical systems. The calculations also demonstrate that relatively modest control investments can produce substantial expected annual risk reduction. This provides MedDefense with a defensible, CFO-oriented basis for selecting security investments within a limited budget.
