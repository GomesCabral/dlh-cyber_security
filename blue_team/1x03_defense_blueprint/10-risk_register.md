# 10. Risk Register

## MedDefense Health Systems Risk Register

| Risk ID | Risk Description | Risk Category | Threat Source | Vulnerability | Affected Asset(s) | Likelihood (1-5) | Impact (1-5) | Inherent Risk Score | ALE | Risk Owner | Treatment Decision | Treatment Justification | Planned Control(s) | Residual Risk | KRI | Review Date |
|---------|------------------|---------------|---------------|---------------|-------------------|:---------------:|:------------:|:-------------------:|-------------:|----------------|----------------|----------------------|----------------------|--------------|---------------------------|--------------|
| **RISK-001** | Ransomware compromises the Billing Server through unpatched software. | Operational | Ransomware Group (BlackReef) | Findings 002, 006 | billing-srv-01 | 4 | 5 | 20 | $300,000 | IT Director (Sarah Park) | Mitigate | Highest operational and financial risk. | Network Segmentation, Immutable Backups, MFA, SIEM | Medium | Number of unpatched critical vulnerabilities >5 | Quarterly |
| **RISK-002** | Patient records are stolen from the EHR environment. | Compliance | External Cybercriminal | Findings 017, 031 | ehr-srv-01, ehr-db-01 | 4 | 5 | 20 | $1,200,000 | Deputy CISO (James Chen) | Mitigate | Regulatory penalties and patient privacy obligations require mitigation. | MFA, SIEM, Network Segmentation | Medium | Failed authentication attempts, abnormal database queries | Monthly |
| **RISK-003** | VPN compromise provides attackers with full internal network access. | Strategic | External Attacker | OSINT FortiGate CVE | FortiGate VPN | 4 | 5 | 20 | $450,000 | IT Director | Mitigate | VPN is the primary external attack path. | MFA, Firewall Updates, Continuous Patch Management | Low | VPN login failures, unusual VPN sessions | Monthly |
| **RISK-004** | Flat network enables lateral movement after initial compromise. | Operational | Ransomware Operators | Gap GAP-003 | Entire Internal Network | 5 | 5 | 25 | $500,000 | IT Director | Mitigate | Network segmentation significantly reduces enterprise-wide risk. | VLAN Segmentation, Internal Firewalls | Medium | East-west traffic anomalies | Quarterly |
| **RISK-005** | Medical IoT devices are compromised, affecting patient safety. | Operational | Opportunistic Attacker | Findings 010, 016, 024 | BD Alaris Pumps, Philips IntelliVue | 2 | 5 | 10 | $90,000 | Clinical Engineering Manager | Mitigate | Patient safety outweighs implementation cost. | Medical Device Isolation, Monitoring | Low | Unauthorized access to medical device VLAN | Quarterly |
| **RISK-006** | Windows XP MRI workstation is exploited due to end-of-life status. | Operational | External Attacker | Findings 021, 022 | MRI Workstation | 3 | 4 | 12 | $150,000 | Clinical Engineering Manager | Mitigate | Replacement is not immediately possible; compensating controls required. | Isolation VLAN, Restricted Access, Monitoring | Medium | New connections to MRI workstation | Quarterly |
| **RISK-007** | Insider accidentally leaks patient information. | Compliance | Negligent Insider | Shared Accounts / Weak Controls | Clinical Workstations | 3 | 4 | 12 | $240,000 | HR Director | Mitigate | Security awareness and least privilege reduce likelihood. | Security Awareness Training, MFA, Access Reviews | Medium | Large file transfers, USB usage | Quarterly |
| **RISK-008** | Backup systems become encrypted during ransomware attack. | Operational | Ransomware Group | Backup Architecture Gap | Synology NAS | 3 | 5 | 15 | $280,000 | Infrastructure Manager | Mitigate | Immutable backups dramatically reduce recovery costs. | Offsite Immutable Backups | Low | Backup failures or integrity alerts | Monthly |
| **RISK-009** | Regulatory non-compliance results in GDPR or HIPAA penalties. | Compliance | Regulatory Authorities | Multiple Findings | Patient Data Environment | 3 | 5 | 15 | $200,000 | Deputy CISO | Mitigate | Compliance obligations require continuous improvement. | Vulnerability Management Program, Audit Program | Low | Failed compliance audit findings | Semi-Annual |
| **RISK-010** | Security incidents remain undetected because of insufficient monitoring. | Operational | Advanced Persistent Threat (APT) | Gap: No Central Monitoring | Enterprise Infrastructure | 4 | 4 | 16 | $180,000 | Security Analyst | Mitigate | Earlier detection reduces incident cost and dwell time. | Enterprise SIEM (Wazuh), Log Management | Medium | Mean Time to Detect (MTTD) increases | Monthly |

---

# Likelihood Scale

| Score | Definition |
|------:|------------|
| **1** | Rare (less than once every 10 years) |
| **2** | Unlikely (once every 5–10 years) |
| **3** | Possible (once every 2–5 years) |
| **4** | Likely (annually or every 1–2 years) |
| **5** | Almost Certain (multiple times per year) |

---

# Impact Scale

| Score | Definition |
|------:|------------|
| **1** | Negligible impact |
| **2** | Minor operational disruption |
| **3** | Moderate business impact |
| **4** | Major financial or operational impact |
| **5** | Catastrophic impact involving patient safety, regulatory action or prolonged business interruption |

---

# Treatment Decision Summary

| Decision | Count |
|-----------|------:|
| Mitigate | 10 |
| Transfer | 0 |
| Accept | 0 |
| Avoid | 0 |

---

# Risk Register Governance Note

The **Deputy CISO (James Chen)** is responsible for maintaining the MedDefense Risk Register, with operational support from the **Security Analyst**. Risk owners are responsible for updating the status of their assigned risks whenever new vulnerabilities, incidents or control changes occur.

The Risk Register is reviewed **monthly** during cybersecurity governance meetings and formally presented to executive leadership every quarter. Additional out-of-cycle reviews are triggered whenever a new critical vulnerability (CVSS ≥ 9.0), a CISA KEV advisory, a significant security incident, a major infrastructure change or a regulatory requirement affects MedDefense's risk posture.

If a **Key Risk Indicator (KRI)** exceeds its predefined threshold, the risk owner must immediately notify the Deputy CISO. The risk is reassessed, mitigation priorities are updated, and, if necessary, an emergency remediation plan is initiated and escalated to executive management and the Board.
