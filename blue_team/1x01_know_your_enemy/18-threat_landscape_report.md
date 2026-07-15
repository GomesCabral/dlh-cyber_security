# MedDefense Health Systems – Threat Landscape Report

---

# 1. Executive Summary

MedDefense operates in one of the most targeted industries worldwide. Healthcare organizations are frequently attacked because they manage valuable patient data, rely on continuous clinical operations and often maintain legacy systems that are difficult to replace.

The greatest threat facing MedDefense is a ransomware attack carried out by an organized crime group. The current combination of a flat network, unsupported systems, lack of centralized monitoring and limited identity protection makes ransomware the highest business risk.

### Top 3 Recommendations

1. Implement network segmentation to limit lateral movement.
2. Deploy Multi-Factor Authentication (MFA) and centralized security monitoring (SIEM).
3. Secure legacy systems and improve vendor access management.

These actions will significantly reduce the likelihood and impact of the highest-priority threats identified during this assessment.

---

# 2. Scope and Methodology

## Scope

The assessment covered:

- MedDefense Central Hospital
- Westside Clinic
- Corporate HQ
- Critical servers and infrastructure
- Medical IoT devices
- Active Directory
- EHR, PACS and Billing systems
- Third-party vendors
- Clinical and administrative users

## Intelligence Sources

- CISA Healthcare Advisories
- HC3 Healthcare Threat Briefs
- HHS Breach Statistics
- Marcus Webb Threat Intelligence Dossier
- Project 1x00 Security Posture Assessment

## Analytical Frameworks

- STRIDE Threat Modeling
- MITRE ATT&CK
- Cyber Kill Chain
- Threat Actor Profiling
- Attack Surface Analysis

## Relationship to the Security Posture Assessment

Project 1x00 identified MedDefense's assets, controls and security gaps. This report evaluates how real-world threat actors could exploit those weaknesses and prioritizes risks based on both likelihood and impact.

---

# 3. Healthcare Sector Threat Overview

## Why Healthcare Is Targeted

Healthcare organizations are attractive because they:

- Store valuable Protected Health Information (PHI).
- Depend on continuous clinical operations, increasing ransom payment pressure.
- Operate legacy medical equipment that cannot easily be replaced.
- Frequently have limited cybersecurity resources.

## Current Threat Trends

- Increasing ransomware campaigns using double extortion.
- Growth of phishing and credential theft attacks.
- Increased supply chain attacks against healthcare vendors.
- Greater use of AI-assisted phishing campaigns.

## Sector Statistics

- Healthcare remains the most targeted critical infrastructure sector.
- Approximately 78% of reported healthcare breaches involve hacking or IT incidents.
- Average ransomware recovery costs exceed several million dollars.
- Most ransomware attacks now include data exfiltration before encryption.

---

# 4. MedDefense Threat Actor Profiles

| Threat Actor | Likelihood | Priority |
|--------------|------------|----------|
| Organized Crime (Ransomware) | Critical | 1 |
| Malicious Insider | High | 2 |
| Negligent Insider | High | 3 |
| Opportunistic Attacker | High | 4 |
| Hacktivist | Medium | 5 |
| Nation-State APT | Low | 6 |

## Top 3 Threat Actors

### Organized Crime

Primary motivation is financial gain through ransomware and data extortion. These groups exploit phishing, VPN vulnerabilities and weak internal segmentation.

### Malicious Insider

Employees with legitimate access may steal patient information or abuse privileged accounts for financial gain.

### Negligent Insider

Human error, shadow IT, shared credentials and poor security awareness continue to expose sensitive systems.

---

# 5. Attack Surface Analysis

## External Surface

- Patient Portal
- VPN Gateway
- Microsoft 365
- Public Website
- DNS Services

Main risks include phishing, VPN exploitation and credential theft.

## Internal Surface

- Flat network architecture
- Active Directory
- EHR database
- Billing Server
- Legacy Windows XP workstation
- Medical IoT devices

The lack of segmentation enables unrestricted lateral movement.

## Human Surface

High-risk users include:

- Clinical staff
- IT administrators
- Executives
- Reception staff
- Third-party contractors

Social engineering remains one of the most likely attack methods.

---

# 6. Critical Attack Paths

## Primary Kill Chains

1. Ransomware via phishing
2. VPN exploitation
3. Insider data theft
4. Supply chain compromise
5. Legacy system compromise

## Break Points

- Email filtering
- MFA
- SIEM
- Network segmentation
- DLP
- Incident response procedures

## Most Connected Assets

- Active Directory
- EHR System
- Billing Server

## Most Versatile Attack Vectors

- Phishing
- VPN Exploitation
- Stolen Credentials

---

# 7. STRIDE Analysis Summary

## EHR

Highest risks:

- Information Disclosure
- Elevation of Privilege
- Denial of Service

These directly affect patient safety and regulatory compliance.

## PACS

Primary risks include shared credentials, legacy Windows XP systems and unauthorized image access.

## Active Directory

The compromise of a Domain Controller would provide attackers with administrative control over nearly every MedDefense system.

## Network Infrastructure

The absence of internal segmentation and the presence of a consumer-grade router at Westside significantly increase attack propagation risk.

---

# 8. Threat Scenarios

## Scenario 1

BlackReef ransomware campaign resulting in patient data theft and full network encryption.

**Business Impact**

- Clinical disruption
- Financial loss
- Regulatory penalties

---

## Scenario 2

Malicious insider exporting patient records before leaving the organization.

**Business Impact**

- Data breach
- HIPAA investigation
- Reputational damage

---

## Scenario 3

Compromised vendor account providing unauthorized access to the EHR environment.

**Business Impact**

- Supply chain compromise
- Patient data exposure
- Operational disruption

---

# 9. Gap-Threat Correlation

Threat analysis confirmed that several previously identified gaps directly support multiple attack paths.

## Critical Three

1. GAP-004 – Flat Network
2. GAP-007 – No Centralized Monitoring
3. GAP-011 – Weak Identity Management / No MFA

Closing these three gaps would disrupt most ransomware, insider and supply chain attack scenarios.

## Surprise

GAP-013 (No Data Loss Prevention) increased in priority after analyzing insider threats because sensitive data can currently be exported without detection.

---

# 10. Prioritized Recommendations

| Threat | Recommended Action |
|---------|--------------------|
| Ransomware | Implement Network Segmentation |
| Credential Theft | Deploy MFA |
| Insider Threat | Implement DLP |
| Supply Chain Attack | Restrict Vendor Access |
| Legacy Systems | Isolate Unsupported Devices |

## Strategic Recommendation

If only two security initiatives can be funded during the next budget cycle, MedDefense should prioritize:

1. Network Segmentation.
2. MFA combined with Centralized Security Monitoring.

Together, these initiatives significantly reduce the likelihood and impact of the majority of attack scenarios identified throughout this assessment.

## Next Phase

The next logical step is a Vulnerability Assessment (Project 1x02). While this report identifies who is most likely to attack MedDefense and how they would do it, the vulnerability assessment will determine exactly which technical weaknesses must be remediated first to reduce the organization's overall cyber risk.
