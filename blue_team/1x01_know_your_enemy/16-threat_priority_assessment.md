# Threat Priority Assessment

---

## Rank 1

**Threat:** Ransomware attack against the EHR infrastructure

**Actor Type:** Organized Crime (BlackReef RaaS)

**Primary Vector:** Spear Phishing / VPN Exploit

**Primary Target:** EHR System, Active Directory and Backup Infrastructure

**Likelihood:** Critical – Healthcare is the most targeted sector for ransomware, and MedDefense matches the profile of a mid-sized hospital with several known security gaps.

**Impact:** Critical – Loss of the EHR would interrupt patient care, expose protected health information and cause major financial and regulatory consequences.

**Overall Priority:** Critical

**Key Gap:** GAP-004 – Flat Network Architecture

**Recommended Action:** Implement network segmentation between workstations, servers and medical devices. *(Long-term)*

---

## Rank 2

**Threat:** Credential compromise leading to domain-wide access

**Actor Type:** Organized Crime / Opportunistic Attacker

**Primary Vector:** Phishing or Stolen Credentials

**Primary Target:** Active Directory

**Likelihood:** High – MedDefense has no MFA and limited centralized monitoring, making credential theft highly effective.

**Impact:** Critical – Compromise of Active Directory gives attackers control over nearly every system.

**Overall Priority:** Critical

**Key Gap:** GAP-011 – No MFA and Weak Account Lifecycle Management

**Recommended Action:** Deploy MFA for VPN, administrators and clinical systems. *(Short-term)*

---

## Rank 3

**Threat:** Insider theft of patient information

**Actor Type:** Malicious Insider

**Primary Vector:** Abuse of Legitimate Access

**Primary Target:** EHR Database and Billing System

**Likelihood:** High – Clinical staff require broad access to patient data, while DLP and monitoring are absent.

**Impact:** High – Large-scale disclosure of protected health information would trigger HIPAA investigations, legal action and reputational damage.

**Overall Priority:** High

**Key Gap:** GAP-013 – No Data Loss Prevention

**Recommended Action:** Implement DLP and monitor abnormal data exports. *(Short-term)*

---

## Rank 4

**Threat:** Supply Chain Compromise through Trusted Vendors

**Actor Type:** External Attacker using Third-Party Access

**Primary Vector:** Vendor Remote Access

**Primary Target:** EHR Servers and Critical Infrastructure

**Likelihood:** High – Vendors maintain privileged access to critical systems, and their activity is not sufficiently monitored.

**Impact:** High – A compromised vendor account could bypass perimeter security and provide direct access to sensitive systems.

**Overall Priority:** High

**Key Gap:** GAP-014 – Weak Third-Party Access Controls

**Recommended Action:** Restrict vendor access using least privilege, MFA and session monitoring. *(Short-term)*

---

## Rank 5

**Threat:** Compromise of Legacy Medical Devices

**Actor Type:** Opportunistic Attacker or Ransomware Group

**Primary Vector:** Exploitation of Unsupported Systems

**Primary Target:** MRI Workstation and Medical IoT Devices

**Likelihood:** Medium – Windows XP and outdated medical devices remain connected to the production network.

**Impact:** Critical – Device compromise could affect patient care and allow lateral movement into the hospital network.

**Overall Priority:** High

**Key Gap:** GAP-001 – Legacy MRI Workstation

**Recommended Action:** Isolate legacy medical devices on dedicated VLANs protected by firewall rules. *(Long-term)*

---

# Strategic Recommendation

If MedDefense can only fund two security initiatives during the next quarter, the first priority should be implementing **network segmentation**, because it would stop attackers from moving freely between workstations, servers and medical devices. The second priority should be deploying **multi-factor authentication with centralized security monitoring (SIEM)**, which would significantly reduce credential-based attacks and improve the ability to detect ransomware, insider threats and suspicious vendor activity before major damage occurs. Together, these initiatives address the highest-risk attack paths identified throughout the assessment.
