# MedDefense Health Systems
# Security Strategy Document

**Project:** 1x03 – The Defense Blueprint  
**Organization:** MedDefense Health Systems  
**Version:** 1.0  
**Prepared by:** Security Analyst  
**Frameworks:** NIST CSF 2.0, CIS Controls v8, ISO/IEC 27001  
**Security Budget:** $120,000  
**Planning Horizon:** 6 Months

---

# 1. Executive Summary

## Current Security Posture

The security assessments performed during Projects 1x00, 1x01 and 1x02 revealed that MedDefense currently faces a **High overall cybersecurity risk**. The organization operates with a flat network architecture, several critical vulnerabilities, limited centralized monitoring, legacy medical systems, and incomplete governance processes. These weaknesses significantly increase the likelihood and impact of ransomware, data breaches, insider threats and operational disruption.

## Strategic Approach

MedDefense will adopt a layered, risk-based cybersecurity strategy using three complementary frameworks:

- **NIST Cybersecurity Framework (CSF) 2.0** to define strategic cybersecurity outcomes.
- **CIS Controls v8** to implement practical technical safeguards.
- **ISO/IEC 27001** to establish governance, policies and continuous improvement.

Security investments are prioritized using quantitative risk analysis (SLE, ARO and ALE) to maximize risk reduction within the approved annual budget.

## Investment Requested

Approved Security Budget:

**$120,000 annually**

Recommended Spending:

**$106,000**

Budget Remaining:

**$14,000**

Estimated Result:

- Significant reduction of enterprise ransomware exposure.
- Strong reduction in Annualized Loss Expectancy (ALE).
- Improved regulatory compliance.
- Increased cyber resilience.
- Better visibility through centralized monitoring.

## Top Three Priorities

1. Deploy Network Segmentation.
2. Enforce Multi-Factor Authentication (MFA).
3. Deploy Enterprise SIEM and Immutable Backups.

---

# 2. Governance Framework

## Framework Selection

### NIST CSF 2.0

Purpose

Provide the strategic cybersecurity framework for MedDefense.

Why Selected

- Widely adopted.
- Risk-based.
- Executive friendly.
- Organizes cybersecurity into Govern, Identify, Protect, Detect, Respond and Recover.

Role

Answers:

> "What should MedDefense achieve?"

---

### CIS Controls v8

Purpose

Provide practical technical implementation guidance.

Why Selected

- Prioritized controls.
- Practical implementation roadmap.
- Excellent mapping to healthcare environments.

Role

Answers:

> "How should MedDefense implement security?"

---

### ISO/IEC 27001

Purpose

Provide governance, documentation and continuous improvement.

Why Selected

- Recognized internationally.
- Strong governance model.
- Supports regulatory compliance.
- Suitable for future certification.

Role

Answers:

> "How can MedDefense demonstrate that security is managed correctly?"

---

## Framework Relationship

The three frameworks complement each other.

```
NIST CSF
        ↓
Defines Security Objectives

CIS Controls
        ↓
Implements Technical Controls

ISO 27001
        ↓
Provides Governance and Continuous Improvement
```

Together they create a complete security program covering governance, operations and compliance.

---

# 3. NIST CSF Current Profile

| Function | Current | Target (6 Months) |
|------------|----------|------------------|
| Govern | Partial | Managed |
| Identify | Partial | Managed |
| Protect | Partial | Managed |
| Detect | Not Implemented | Managed |
| Respond | Partial | Managed |
| Recover | Partial | Managed |

## Major Findings

### Govern

Current

- No formal cybersecurity strategy.
- Vacant CISO position.
- Limited governance documentation.

Target

- Approved security strategy.
- Formal governance structure.
- Risk Register.
- Security policies.

---

### Identify

Current

- Asset inventory recently created.
- Risks identified but not continuously managed.

Target

- Continuous asset inventory.
- Quarterly risk reviews.
- Formal risk management process.

---

### Protect

Current

Major weaknesses include:

- Flat network.
- Weak access controls.
- Legacy operating systems.
- Limited MFA.

Target

- Segmented network.
- MFA.
- Secure configurations.
- Stronger endpoint protection.

---

### Detect

Current

Almost no centralized monitoring.

Target

- Wazuh SIEM.
- Centralized logging.
- Automated alerts.
- Continuous monitoring.

---

### Respond

Current

Incident response exists but remains informal.

Target

- Formal Incident Response Plan.
- Defined responsibilities.
- Tested procedures.

---

### Recover

Current

Backups exist but require improvement.

Target

- Immutable backups.
- Offsite replication.
- Recovery validation.
- Recovery testing.

---

# 4. CIS Controls Maturity Assessment

## Overall Results

| Status | Controls |
|---------|----------|
| Implemented | 0 |
| Partial | 14 |
| Not Implemented | 4 |

## Highest Priority CIS Controls

1. CIS Control 7 – Continuous Vulnerability Management

2. CIS Control 12 – Network Infrastructure Management

3. CIS Control 13 – Network Monitoring and Defense

4. CIS Control 17 – Incident Response Management

5. CIS Control 8 – Audit Log Management

These controls provide the greatest reduction in enterprise risk and directly address the highest ALE values identified during quantitative risk analysis.

---

# 5. Governance Structure

## Executive Leadership

### CEO

Responsible for:

- Budget approval
- Risk acceptance
- Security policy approval
- Executive oversight

---

### Deputy CISO (James Chen)

Responsible for:

- Security strategy
- Risk management
- Security governance
- Board reporting
- Risk Register

---

### IT Director (Sarah Park)

Responsible for:

- Technical implementation
- Infrastructure
- Patch management
- Network administration
- Backup operations

---

### Department Heads

Responsible for:

- Data ownership
- Business risk ownership
- Classification of departmental information
- Operational decision-making

---

### Security Analyst

Responsible for:

- Vulnerability management
- Threat monitoring
- SIEM operations
- Risk assessments
- Security reporting
- Audit support

---

## Governance Recommendation

Because the CISO position remains vacant, MedDefense should adopt a **virtual Chief Information Security Officer (vCISO)** during the next 12–24 months.

A vCISO provides executive cybersecurity leadership without consuming a significant portion of the available $120,000 annual budget.

---

# 6. Quantitative Risk Analysis

The Security Strategy prioritizes investments using **Annualized Loss Expectancy (ALE)** instead of subjective High/Medium/Low ratings.

The five highest financial risks identified are:

| Rank | Risk | Estimated ALE |
|------|-------------------------------|------------:|
| 1 | EHR Data Breach | ~$2,990,000 |
| 2 | VPN Compromise | ~$2,890,000 |
| 3 | Insider Data Theft | ~$300,000 |
| 4 | Billing Server Ransomware | ~$133,000 |
| 5 | Medical Device Compromise | ~$103,000 |

These risks account for the majority of MedDefense's expected annual cyber losses and therefore drive the investment strategy.

---

## Risk Appetite Statement

MedDefense maintains a **moderate risk appetite** for operational and financial cybersecurity risks where mitigation costs exceed expected financial loss.

However, the organization has **zero tolerance** for risks that:

- Endanger patient safety.
- Cause unauthorized disclosure of Protected Health Information (PHI).
- Create major regulatory violations.
- Prevent delivery of critical healthcare services.

Any risk with an **ALE greater than $500,000** or an inherent risk score above **20** requires formal approval from Executive Management and the Board before it can be accepted.

All accepted risks must:

- Be documented.
- Have compensating controls.
- Be assigned an owner.
- Be reviewed every six months.

---

# 7. Control Strategy

## Cost-Benefit Analysis

Each proposed security control was evaluated using quantitative risk analysis based on Annualized Loss Expectancy (ALE). Controls were selected only when the expected reduction in financial risk exceeded their annual implementation cost.

| Control | Annual Cost | Primary Risk Addressed | Estimated ALE Reduction | Verdict |
|---------|------------:|-----------------------|-------------------------:|---------|
| Network Segmentation | $40,000 | Lateral Movement / Ransomware | Very High | Implement |
| MFA Deployment | $8,000 | VPN Compromise | Very High | Implement |
| Enterprise SIEM (Wazuh) | $25,000 | Delayed Detection | High | Implement |
| Immutable Offsite Backups | $18,000 | Ransomware Recovery | High | Implement |
| Dedicated Firewall (Westside Clinic) | $15,000 | Branch Office Exposure | Medium | Implement |
| Sophos Intercept X (EDR) | $32,000 | Endpoint Attacks | Medium | Defer |
| Medical Device Isolation | $28,000 | Medical Device Attacks | Medium | Defer |
| Managed 24/7 SOC | $150,000 | Continuous Monitoring | Low ROI (Current Stage) | Reject |

---

## Budget Allocation

### Funded Controls

| Control | Cost |
|---------|------:|
| Network Segmentation | $40,000 |
| Enterprise SIEM (Wazuh) | $25,000 |
| Immutable Backups | $18,000 |
| MFA Deployment | $8,000 |
| Dedicated Firewall (Westside Clinic) | $15,000 |

**Total Budget Used:** **$106,000**

**Approved Budget:** **$120,000**

**Remaining Budget:** **$14,000**

The remaining funds are reserved for emergency remediation, implementation adjustments, or unexpected security expenses.

---

## Deferred Controls

The following controls provide value but were deferred because the funded controls produce greater immediate risk reduction.

| Control | Reason |
|---------|--------|
| Sophos Intercept X (EDR) | Valuable, but foundational controls reduce greater enterprise risk. |
| Medical Device Network Isolation | General network segmentation already provides partial protection. |

---

## Rejected Control

### Managed 24/7 SOC

The outsourced Managed SOC is **rejected** for the current strategy because:

- Annual operating cost exceeds the total cybersecurity budget.
- Current monitoring maturity is insufficient to fully benefit from a managed SOC.
- Better financial return is achieved by investing in foundational controls first.

The organization may reconsider this investment after implementing EDR and improving overall monitoring maturity.

---

## Control Selection Summary

The selected controls align directly with both NIST CSF and CIS Controls.

| Control | NIST CSF | CIS Controls |
|----------|----------|--------------|
| Network Segmentation | PR.PS | Control 12 |
| MFA Deployment | PR.AA | Controls 5 & 6 |
| SIEM | DE.CM | Controls 8 & 13 |
| Immutable Backups | RC.RP | Control 11 |
| Dedicated Firewall | PR.IR | Control 12 |

---

# 8. Architecture Recommendations

## Network Segmentation

The current flat network represents MedDefense's largest architectural weakness.

The proposed architecture introduces six security zones:

| Zone | Purpose |
|------|----------|
| Server Zone | Critical business servers (EHR, AD, Billing, File Servers) |
| Clinical Workstation Zone | Staff workstations |
| Medical Device Zone | MRI, PACS, Infusion Pumps, Monitors |
| Management Zone | Administrative systems and security tools |
| Guest / IoT Zone | Visitors and non-clinical devices |
| DMZ | VPN Gateway and public-facing services |

Each VLAN communicates only through firewall policies following the principle of least privilege.

---

## Security Benefits

Network segmentation provides several improvements:

- Prevents unrestricted lateral movement.
- Protects Active Directory.
- Isolates medical devices.
- Limits ransomware propagation.
- Reduces insider attack impact.
- Simplifies monitoring.
- Supports Zero Trust principles.

---

## Kill Chain Disruption

The proposed segmentation architecture interrupts the primary ransomware kill chain at multiple stages.

### Stage 1 – Initial Access

Still possible through phishing or VPN compromise.

Impact:

Limited because attackers no longer receive unrestricted network access.

---

### Stage 2 – Credential Theft

Restricted by:

- MFA
- Segmentation
- Administrative isolation

---

### Stage 3 – Lateral Movement

Mostly prevented through VLAN separation and firewall rules.

---

### Stage 4 – Ransomware Deployment

Limited to the compromised security zone.

Enterprise-wide encryption becomes significantly more difficult.

---

### Stage 5 – Recovery

Immutable backups allow recovery without paying ransom.

---

Estimated disruption:

Approximately **80%** of the organization's five highest-priority kill chains are significantly disrupted.

---

# 9. Policy Foundation

## Acceptable Use Policy

The Acceptable Use Policy (AUP) establishes mandatory security requirements for all MedDefense employees, contractors and third-party users.

The policy covers:

- Acceptable use of MedDefense systems.
- Password requirements.
- MFA usage.
- Remote access.
- Data handling.
- Personal devices.
- USB storage.
- Cloud storage.
- Internet usage.
- Monitoring.
- Disciplinary actions.

The policy supports regulatory compliance while remaining practical for a clinical environment.

---

## Policy Roadmap

The Acceptable Use Policy represents only the first layer of MedDefense's governance framework.

The following policies should be developed over the next 12 months:

| Quarter | Policy |
|----------|----------------------------|
| Q1 | Acceptable Use Policy |
| Q1 | Password Policy |
| Q1 | Incident Response Policy |
| Q2 | Vulnerability Management Policy |
| Q2 | Backup & Recovery Policy |
| Q2 | Asset Management Policy |
| Q3 | Third-Party Risk Policy |
| Q3 | Secure Configuration Standard |
| Q4 | Business Continuity Plan |
| Q4 | Disaster Recovery Plan |

---

## Governance Objectives

These policies establish:

- Executive accountability.
- Technical standards.
- Operational consistency.
- Regulatory compliance.
- Repeatable security processes.
- Continuous improvement.

Together they provide the governance foundation required to support ISO/IEC 27001 alignment and long-term cybersecurity maturity.

---

# 10. Residual Risk Assessment

## Red Team Findings

A red team exercise was conducted assuming all funded controls from the security strategy were fully implemented.

The assessment concluded that the overall attack surface is significantly reduced, particularly against ransomware campaigns, external compromise, and unrestricted lateral movement. However, some residual risks remain due to budget limitations and the phased implementation approach.

### Remaining Threats

The most viable remaining attack paths include:

- Insider misuse of legitimate access.
- Phishing attacks targeting privileged users.
- Compromise of legacy medical systems.
- Endpoint malware before EDR deployment.
- Zero-day vulnerabilities affecting Internet-facing services.

Although these risks remain, their potential impact is significantly lower because segmentation, MFA, centralized logging, immutable backups, and improved governance reduce both attacker capability and organizational exposure.

---

## Accepted Risks

The following risks have been formally accepted by Executive Management and documented in the Risk Register.

| Risk | Reason for Acceptance | Compensating Controls |
|------|------------------------|-----------------------|
| Windows XP MRI Workstation | Replacement cost ($2.1M) cannot be justified before lease expiration. | Network isolation, firewall rules, monitoring, restricted access. |
| Delayed Medical Device Isolation | Network segmentation already provides partial protection. | VLAN isolation, firewall filtering, continuous monitoring. |
| No Managed 24/7 SOC | Current budget cannot support the service and foundational controls provide greater ROI. | Wazuh SIEM, business-hours monitoring, incident response procedures. |

All accepted risks include:

- Assigned owner.
- Review date.
- Monitoring requirements.
- Defined review triggers.

---

## Overall Residual Risk

**Residual Risk Rating: Medium**

The funded controls substantially reduce the likelihood and impact of the highest-priority threats.

Remaining risks are considered acceptable because:

- They are documented.
- They have compensating controls.
- They are continuously monitored.
- They are scheduled for future remediation.

---

## Year Two Priorities

The next security investment cycle should focus on completing the remaining defensive capabilities.

Priority projects include:

1. Enterprise Endpoint Detection and Response (EDR).
2. Medical Device Network Isolation.
3. Vulnerability Management Automation.
4. Security Awareness Maturity Program.
5. Outsourced 24/7 Security Operations Center (SOC).
6. ISO/IEC 27001 Readiness Assessment.
7. Regular Penetration Testing.
8. Purple Team Exercises.

---

# 11. Implementation Roadmap

The proposed roadmap is divided into three implementation phases covering six months.

---

## Phase 1 (Months 1–2)

### Objectives

Establish governance and implement immediate security improvements.

### Activities

- Approve Security Strategy.
- Publish Acceptable Use Policy.
- Enable MFA.
- Deploy Quick Wins.
- Procure required hardware and software.
- Configure Dedicated Firewall.
- Build Risk Register.
- Establish governance meetings.

### Success Metrics

- MFA enabled for 100% of privileged accounts.
- Security policies approved.
- Risk Register operational.
- Quick Wins completed.
- Budget fully allocated.

---

## Phase 2 (Months 3–4)

### Objectives

Deploy core security controls.

### Activities

- Implement Network Segmentation.
- Deploy Wazuh SIEM.
- Configure centralized logging.
- Implement immutable offsite backups.
- Harden critical servers.
- Review firewall rules.
- Validate vulnerability remediation.

### Success Metrics

- Network fully segmented.
- Centralized monitoring operational.
- Critical vulnerabilities reduced by at least 80%.
- Backup restoration successfully tested.
- Security dashboards available.

---

## Phase 3 (Months 5–6)

### Objectives

Validate, optimize and transition to continuous operations.

### Activities

- Conduct vulnerability rescans.
- Validate implemented controls.
- Review Risk Register.
- Measure KPIs.
- Perform incident response exercise.
- Conduct internal audit.
- Prepare Year Two roadmap.

### Success Metrics

- All funded controls operational.
- Residual risks documented.
- Incident response exercise completed.
- Board receives first quarterly security report.
- Continuous vulnerability management process established.

---

# 12. Success Metrics

The following Key Performance Indicators (KPIs) will measure the effectiveness of the security program.

| KPI | Target |
|------|---------|
| Critical Vulnerabilities | Reduce by at least 80% |
| High Vulnerabilities | Reduce by at least 70% |
| MFA Coverage | 100% of privileged accounts |
| Backup Success Rate | 100% |
| Vulnerability Scan Frequency | Monthly |
| Mean Time to Detect (MTTD) | Less than 24 hours |
| Mean Time to Respond (MTTR) | Less than 48 hours |
| Security Awareness Completion | 100% |
| Policy Compliance | Greater than 95% |
| Risk Register Reviews | Monthly |

---

# 13. Next Steps

The completion of Project **1x03 – The Defense Blueprint** establishes MedDefense's strategic cybersecurity direction.

The next project, **1x04 – Cryptographic Foundation**, will build upon this strategy by implementing cryptographic protections that directly support several controls recommended in this document.

Future work includes:

- Encryption of sensitive data at rest.
- Encryption of data in transit.
- PKI implementation.
- Certificate lifecycle management.
- Key management.
- Secure authentication mechanisms.
- Digital signatures.
- Cryptographic governance.

These capabilities will strengthen the Protect function of the NIST Cybersecurity Framework and further reduce the likelihood of unauthorized disclosure of Protected Health Information (PHI).

---

# 14. Conclusion

The Security Strategy presented in this document transforms MedDefense from a reactive security posture into a structured, risk-driven cybersecurity program aligned with recognized industry frameworks.

Rather than attempting to eliminate every risk regardless of cost, the strategy prioritizes investments using quantitative risk analysis to maximize business value. The recommended portfolio remains within the approved annual budget of **$120,000**, funds the controls with the highest return on investment, and establishes the governance, architecture and operational processes necessary for continuous improvement.

By implementing this roadmap, MedDefense will significantly reduce its exposure to ransomware, credential theft, insider misuse and regulatory non-compliance while improving resilience, operational continuity and patient safety. Although some residual risks remain, they are formally documented, actively monitored and supported by compensating controls, ensuring that risk acceptance becomes a deliberate governance decision rather than an unmanaged weakness.

---

# End of Document
