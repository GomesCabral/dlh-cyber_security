# Gap-Threat Correlation

## GAP-001

**Gap ID:** GAP-001

**Gap Description:** Legacy MRI workstation running unsupported Windows XP without effective network isolation.

**Original Risk Level:** Critical

**Threat Actors:** Ransomware Groups, Unskilled/Opportunistic Attackers, Supply Chain Attackers

**Kill Chains:** Kill Chain #2 – VPN Exploit to Active Directory; Kill Chain #4 – Supply Chain Compromise

**Scenarios:** Scenario 1 – BlackReef Ransomware Attack; Scenario 3 – Supply Chain Compromise

**Updated Risk Level:** Critical – Same

**Justification:** The MRI remains an exploitable legacy system connected to the flat network. Threat analysis confirms that ransomware affiliates, opportunistic attackers and compromised vendors could use it as a foothold or lateral movement target, while an outage could directly affect patient care.

---

## GAP-002

**Gap ID:** GAP-002

**Gap Description:** Unattended EHR sessions expose patient records to unauthorized users.

**Original Risk Level:** Critical

**Threat Actors:** Insider (Malicious), Insider (Negligent), Social Engineering Attackers

**Kill Chains:** Kill Chain #3 – Shared Credentials Used for Data Theft; Kill Chain #5 – Insider Data Exfiltration

**Scenarios:** Scenario 2 – Malicious Insider Data Theft

**Updated Risk Level:** Critical – Same

**Justification:** The EHR contains Restricted patient information and supports clinical decisions. The insider analysis showed that legitimate access can become unauthorized use when sessions remain open and activity is not monitored.

---

## GAP-003

**Gap ID:** GAP-003

**Gap Description:** billing-srv-01 runs unsupported Ubuntu 18.04 and vulnerable software.

**Original Risk Level:** Critical

**Threat Actors:** Ransomware Groups, Unskilled/Opportunistic Attackers

**Kill Chains:** Kill Chain #1 – Phishing Leading to Ransomware; Kill Chain #2 – VPN Exploit to Active Directory

**Scenarios:** Scenario 1 – BlackReef Ransomware Attack

**Updated Risk Level:** Critical – Same

**Justification:** The previous ransomware and cryptocurrency-mining incidents prove that this is an actively exploitable system. BlackReef-style affiliates and automated scanners specifically target known vulnerabilities in exposed or unsupported software.

---

## GAP-004

**Gap ID:** GAP-004

**Gap Description:** Flat network architecture permits unrestricted communication between workstations, servers and medical devices.

**Original Risk Level:** Critical

**Threat Actors:** Ransomware Groups, Nation-State Actors, Opportunistic Attackers, Malicious Insiders, Supply Chain Attackers

**Kill Chains:** Kill Chain #1, Kill Chain #2, Kill Chain #4 and Kill Chain #5

**Scenarios:** Scenario 1 – BlackReef Ransomware Attack; Scenario 3 – Supply Chain Compromise

**Updated Risk Level:** Critical – Same

**Justification:** This gap appears in more attack paths than any other infrastructure weakness. Once an attacker gains any foothold, the flat network allows access to Active Directory, the EHR database, backup infrastructure, PACS and medical devices.

---

## GAP-005

**Gap ID:** GAP-005

**Gap Description:** Shared credentials and weak account accountability exist in Radiology and other workflows.

**Original Risk Level:** Medium

**Threat Actors:** Insider (Malicious), Insider (Negligent), Opportunistic Attackers

**Kill Chains:** Kill Chain #3 – Shared Credentials Used for Data Theft; Kill Chain #5 – Insider Data Exfiltration

**Scenarios:** Scenario 2 – Malicious Insider Data Theft

**Updated Risk Level:** High – Upgraded

**Justification:** Threat analysis showed that shared accounts do more than reduce audit quality. They allow unauthorized patient-data access, prevent attribution and make insider misuse difficult to detect, particularly in PACS and EHR workflows.

---

## GAP-006

**Gap ID:** GAP-006

**Gap Description:** Public-facing services may contain unpatched web, VPN or TLS weaknesses.

**Original Risk Level:** High

**Threat Actors:** Ransomware Groups, Hacktivists, Opportunistic Attackers

**Kill Chains:** Kill Chain #1 – Phishing Leading to Ransomware; Kill Chain #2 – VPN Exploit to Active Directory

**Scenarios:** Scenario 1 – BlackReef Ransomware Attack

**Updated Risk Level:** Critical – Upgraded

**Justification:** Healthcare intelligence shows that exploitation of public-facing applications is the most common ransomware entry vector. MedDefense relies on a FortiGate VPN, a patient portal and public web services, making this gap a likely initial-access path rather than only a general technical weakness.

---

## GAP-007

**Gap ID:** GAP-007

**Gap Description:** No centralized logging, intrusion detection or automated security alerting exists.

**Original Risk Level:** Critical

**Threat Actors:** All Threat Actor Categories

**Kill Chains:** Kill Chain #1, Kill Chain #2, Kill Chain #3, Kill Chain #4 and Kill Chain #5

**Scenarios:** Scenario 1, Scenario 2 and Scenario 3

**Updated Risk Level:** Critical – Same

**Justification:** Every major attack path benefits from the absence of detection. Ransomware affiliates can perform reconnaissance and lateral movement, insiders can export records and supply chain attackers can abuse vendor access without generating timely alerts.

---

## GAP-008

**Gap ID:** GAP-008

**Gap Description:** Backup infrastructure is reachable from production and recovery procedures are not fully tested.

**Original Risk Level:** High

**Threat Actors:** Ransomware Groups, Malicious Insiders, Supply Chain Attackers

**Kill Chains:** Kill Chain #1 – Phishing Leading to Ransomware; Kill Chain #2 – VPN Exploit to Active Directory; Kill Chain #4 – Supply Chain Compromise

**Scenarios:** Scenario 1 – BlackReef Ransomware Attack; Scenario 3 – Supply Chain Compromise

**Updated Risk Level:** Critical – Upgraded

**Justification:** BlackReef specifically targets backups before encryption because recoverable victims are less likely to pay. The backup NAS is reachable from the same flat network, so compromise could remove MedDefense's principal recovery option and extend clinical downtime.

---

## GAP-009

**Gap ID:** GAP-009

**Gap Description:** Privileged and network management credentials are inadequately protected.

**Original Risk Level:** Critical

**Threat Actors:** Ransomware Groups, Malicious Insiders, Supply Chain Attackers

**Kill Chains:** Kill Chain #1, Kill Chain #2 and Kill Chain #4

**Scenarios:** Scenario 1 – BlackReef Ransomware Attack; Scenario 3 – Supply Chain Compromise

**Updated Risk Level:** Critical – Same

**Justification:** Credential dumping, pass-the-hash and vendor-account abuse are central steps in the modeled attack chains. Exposure of privileged credentials can lead directly to Domain Administrator access and organization-wide control.

---

## GAP-010

**Gap ID:** GAP-010

**Gap Description:** Undocumented systems and Shadow IT operate outside formal security management.

**Original Risk Level:** High

**Threat Actors:** Opportunistic Attackers, Insider (Negligent), Supply Chain Attackers

**Kill Chains:** Kill Chain #4 – Supply Chain Compromise; Kill Chain #5 – Insider Data Exfiltration

**Scenarios:** Scenario 2 – Malicious Insider Data Theft; Scenario 3 – Supply Chain Compromise

**Updated Risk Level:** High – Same

**Justification:** The Raspberry Pi, personal NAS and unidentified Linux systems create unmonitored entry points and data stores. They may not be the primary target, but attackers can use them for persistence, lateral movement or data theft.

---

## GAP-011

**Gap ID:** GAP-011

**Gap Description:** No automated account lifecycle management and limited multi-factor authentication.

**Original Risk Level:** Critical

**Threat Actors:** Ransomware Groups, Malicious Insiders, Social Engineering Attackers, Supply Chain Attackers

**Kill Chains:** Kill Chain #1, Kill Chain #2, Kill Chain #4 and Kill Chain #5

**Scenarios:** Scenario 1, Scenario 2 and Scenario 3

**Updated Risk Level:** Critical – Same

**Justification:** Valid accounts are a preferred attack method for ransomware affiliates, insiders and vendor-based attackers. Ghost accounts, stolen passwords and accounts without multi-factor authentication can bypass perimeter controls and provide trusted access.

---

## GAP-012

**Gap ID:** GAP-012

**Gap Description:** Default credentials remain on medical device management interfaces.

**Original Risk Level:** Critical

**Threat Actors:** Opportunistic Attackers, Ransomware Groups, Malicious Insiders

**Kill Chains:** Kill Chain #2 – VPN Exploit to Active Directory; Kill Chain #4 – Supply Chain Compromise

**Scenarios:** Scenario 1 – BlackReef Ransomware Attack; Scenario 3 – Supply Chain Compromise

**Updated Risk Level:** Critical – Same

**Justification:** Default credentials provide immediate administrative access without requiring a software exploit. Because medical devices are reachable through the flat network, compromise could expose patient information, alter device settings or affect device availability.

---

## GAP-013

**Gap ID:** GAP-013

**Gap Description:** No Data Loss Prevention controls or restrictions on USB storage and cloud uploads.

**Original Risk Level:** High

**Threat Actors:** Malicious Insiders, Negligent Insiders, Ransomware Groups

**Kill Chains:** Kill Chain #3 – Shared Credentials Used for Data Theft; Kill Chain #5 – Insider Data Exfiltration

**Scenarios:** Scenario 1 – BlackReef Ransomware Attack; Scenario 2 – Malicious Insider Data Theft

**Updated Risk Level:** Critical – Upgraded

**Justification:** The insider and ransomware scenarios both include large-scale data collection and exfiltration. Without DLP, MedDefense cannot detect or block patient records being copied to USB devices, personal cloud storage or attacker-controlled services.

---

## GAP-014

**Gap ID:** GAP-014

**Gap Description:** Third-party remote access is not sufficiently restricted or monitored.

**Original Risk Level:** High

**Threat Actors:** Supply Chain Attackers, Ransomware Groups, Nation-State Actors

**Kill Chains:** Kill Chain #4 – Supply Chain Compromise

**Scenarios:** Scenario 3 – Supply Chain Compromise

**Updated Risk Level:** Critical – Upgraded

**Justification:** MedTech Solutions has direct maintenance access to the EHR, while other vendors manage endpoints, medical devices and network infrastructure. A compromised vendor account could bypass normal perimeter defenses and provide direct access to Critical systems.

---

## GAP-015

**Gap ID:** GAP-015

**Gap Description:** USB storage is unrestricted on employee workstations.

**Original Risk Level:** High

**Threat Actors:** Malicious Insiders, Negligent Insiders

**Kill Chains:** Kill Chain #5 – Insider Data Exfiltration

**Scenarios:** Scenario 2 – Malicious Insider Data Theft

**Updated Risk Level:** High – Same

**Justification:** The modeled insider scenario demonstrates a direct and realistic path from legitimate EHR access to patient-data theft using removable media. The impact is serious, although the vector depends on an insider already having authorized access.

---

## GAP-016

**Gap ID:** GAP-016

**Gap Description:** No formal change management process exists for system and network modifications.

**Original Risk Level:** Medium

**Threat Actors:** Insider (Negligent), Supply Chain Attackers

**Kill Chains:** Kill Chain #1 – Phishing Leading to Ransomware; Kill Chain #4 – Supply Chain Compromise

**Scenarios:** Scenario 3 – Supply Chain Compromise

**Updated Risk Level:** High – Upgraded

**Justification:** Threat analysis showed that unreviewed changes can create persistent attack paths, weaken firewall rules or expose credentials. The previous backup cron failure demonstrates that uncontrolled changes can also damage recovery capability without malicious activity.

---

# Re-prioritized Gap List

## Critical

1. **GAP-007 – No Centralized Security Monitoring**
2. **GAP-004 – Flat Network Architecture**
3. **GAP-011 – No Automated Account Lifecycle Management / Limited MFA**
4. **GAP-008 – Backup Isolation and Recovery Weaknesses** – **Upgraded**
5. **GAP-006 – Public-Facing Service Vulnerabilities** – **Upgraded**
6. **GAP-009 – Weak Privileged Credential Protection**
7. **GAP-014 – Inadequate Third-Party Access Controls** – **Upgraded**
8. **GAP-013 – No Data Loss Prevention** – **Upgraded**
9. **GAP-003 – Unsupported Billing Server**
10. **GAP-001 – Legacy MRI Workstation**
11. **GAP-002 – Unattended EHR Sessions**
12. **GAP-012 – Default Medical Device Credentials**

## High

13. **GAP-005 – Shared Credentials and Weak Accountability** – **Upgraded**
14. **GAP-010 – Shadow IT and Undocumented Systems**
15. **GAP-015 – Unrestricted USB Storage**
16. **GAP-016 – No Formal Change Management** – **Upgraded**

## Medium

No remaining gaps are rated Medium after threat-informed reassessment.

## Low

No remaining gaps are rated Low after threat-informed reassessment.

---

# The Critical Three

## 1. GAP-007 – No Centralized Security Monitoring

This gap appears in all five kill chains and all three threat scenarios. Closing it would improve detection of phishing payloads, credential theft, lateral movement, insider exports, vendor-account abuse and ransomware preparation.

## 2. GAP-004 – Flat Network Architecture

This gap appears in four kill chains and two major scenarios. Network segmentation would interrupt attacker movement from compromised workstations or vendor connections to Active Directory, EHR, backups and medical devices.

## 3. GAP-011 – Weak Identity Lifecycle and Multi-Factor Authentication

This gap appears in four kill chains and all three scenarios. Automated offboarding and multi-factor authentication would reduce stolen-account abuse, ghost accounts, ransomware access and third-party credential compromise.

---

# The Surprise

**GAP-016 – No Formal Change Management** was originally rated Medium because it appeared to be primarily an operational-process weakness. Threat analysis showed that uncontrolled changes can expose services, weaken firewall rules, introduce plaintext credentials and damage backups, making the gap relevant to both ransomware and supply chain scenarios. It should therefore be upgraded to **High**, because effective change control reduces both accidental failures and attacker-created persistence paths.
