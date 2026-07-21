# 2. CIS Controls Audit – MedDefense Health Systems

## Control 1 – Inventory and Control of Enterprise Assets

**Score:** Partial

**Evidence:** An enterprise asset inventory was created during Project 1x00, but it did not exist previously and unknown devices were still identified during the assessment.

---

## Control 2 – Inventory and Control of Software Assets

**Score:** Partial

**Evidence:** The vulnerability assessment identified outdated and unsupported software, demonstrating incomplete software inventory and lifecycle management.

---

## Control 3 – Data Protection

**Score:** Partial

**Evidence:** Data classification was established during Project 1x00, but weak TLS configurations and insecure medical device communications indicate incomplete protection.

---

## Control 4 – Secure Configuration of Enterprise Assets and Software

**Score:** Partial

**Evidence:** The scan identified weak TLS settings, default credentials, SSH password authentication and insecure configurations across multiple systems.

---

## Control 5 – Account Management

**Score:** Partial

**Evidence:** Administrative accounts exist, but default credentials on medical devices and inconsistent authentication practices indicate incomplete account management.

---

## Control 6 – Access Control Management

**Score:** Partial

**Evidence:** SSH password authentication remains enabled and MFA was not consistently implemented for administrative or remote access.

---

## Control 7 – Continuous Vulnerability Management

**Score:** Partial

**Evidence:** OpenVAS scanning and vulnerability assessments have now been performed, but no mature vulnerability management process existed beforehand.

---

## Control 8 – Audit Log Management

**Score:** Not Implemented

**Evidence:** MedDefense has no centralized logging or SIEM platform, limiting log collection and analysis.

---

## Control 9 – Email and Web Browser Protections

**Score:** Partial

**Evidence:** No major browser weaknesses were identified, but there is no evidence of DNS filtering or formal email protection controls.

---

## Control 10 – Malware Defenses

**Score:** Partial

**Evidence:** A previous cryptocurrency miner infection demonstrates that endpoint malware protection and monitoring are insufficient.

---

## Control 11 – Data Recovery

**Score:** Partial

**Evidence:** Synology NAS backups exist, but backup testing, isolation and recovery validation have not been demonstrated.

---

## Control 12 – Network Infrastructure Management

**Score:** Partial

**Evidence:** The environment uses a flat network architecture with minimal segmentation, increasing lateral movement opportunities.

---

## Control 13 – Network Monitoring and Defense

**Score:** Not Implemented

**Evidence:** Marcus reported that MedDefense has virtually no monitoring capability, no IDS/IPS and no centralized security monitoring.

---

## Control 14 – Security Awareness and Skills Training

**Score:** Partial

**Evidence:** No formal security awareness program was identified for employees despite significant phishing and social engineering risks.

---

## Control 15 – Service Provider Management

**Score:** Partial

**Evidence:** Third-party vendors such as SecurePoint and medical device manufacturers are used, but no formal supplier security management process was identified.

---

## Control 16 – Application Software Security

**Score:** Not Implemented

**Evidence:** No secure software development lifecycle or application security program was identified for internally developed applications.

---

## Control 17 – Incident Response Management

**Score:** Partial

**Evidence:** Previous incidents were handled reactively, and no formally documented or tested Incident Response Plan was identified.

---

## Control 18 – Penetration Testing

**Score:** Not Implemented

**Evidence:** The assessment included vulnerability scanning only; no formal penetration testing program exists.

---

# Scorecard Summary

| Score | Count |
|--------|------:|
| Implemented | 0 |
| Partial | 14 |
| Not Implemented | 4 |
| Total | 18 |

---

# Top 5 Priority Controls

## 1. Control 13 – Network Monitoring and Defense

**Priority:** Highest

**Justification:** MedDefense currently lacks centralized monitoring, IDS/IPS and continuous detection, leaving attacks likely to remain undetected.

---

## 2. Control 7 – Continuous Vulnerability Management

**Priority:** High

**Justification:** Establishing a formal vulnerability management process ensures that newly discovered vulnerabilities are identified, prioritized and remediated continuously.

---

## 3. Control 12 – Network Infrastructure Management

**Priority:** High

**Justification:** Network segmentation would significantly reduce lateral movement and limit the impact of attacks across critical healthcare systems.

---

## 4. Control 4 – Secure Configuration of Enterprise Assets and Software

**Priority:** High

**Justification:** Correcting insecure configurations, removing default credentials and hardening systems would eliminate many of the weaknesses identified during the vulnerability assessment.

---

## 5. Control 17 – Incident Response Management

**Priority:** High

**Justification:** A documented and tested Incident Response Plan would allow MedDefense to detect, contain and recover from incidents more efficiently while reducing operational and regulatory impact.

---

# Overall Assessment

MedDefense demonstrates the basic foundations of a cybersecurity program but remains at an early stage of CIS Controls implementation. Most controls are only partially implemented, while critical capabilities such as centralized monitoring, penetration testing and secure application development are absent. The immediate objective should be to fully implement **IG1 (Essential Cyber Hygiene)** and progressively adopt selected **IG2** safeguards during the next six months, aligning technical improvements with the organization's risk profile and regulatory obligations.
