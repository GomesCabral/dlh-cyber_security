# Technical Vector Assessment

---

## Vector Category: Vulnerable Software

**MedDefense Evidence:** Apache 2.4.29 on billing-srv-01 and Ubuntu 18.04 LTS (End-of-Life).

**Affected Asset(s):** billing-srv-01, web-srv-01.

**Actor Most Likely to Exploit:** Ransomware Groups (Organized Crime) and Unskilled/Opportunistic Attackers.

**Exploitation Scenario:** An attacker exploits a known vulnerability in Apache or the unsupported operating system to gain initial access. The compromised server can then be used to deploy malware or move laterally across the internal network.

**Current Protection:** Firewall rules and endpoint protection.

**Gap Reference:** GAP-003 – Unsupported Billing Server.

---

## Vector Category: Unsupported Systems

**MedDefense Evidence:** Windows XP Embedded on the MRI workstation and Windows Server 2012 R2 on print-srv-01.

**Affected Asset(s):** WS-RAD-01 (MRI), print-srv-01.

**Actor Most Likely to Exploit:** Ransomware Groups and Opportunistic Attackers.

**Exploitation Scenario:** Attackers exploit publicly known vulnerabilities that are no longer patched. Once compromised, these systems provide a foothold inside the hospital network.

**Current Protection:** Compensating controls proposed for the MRI workstation and firewall protection.

**Gap Reference:** GAP-001 – Legacy MRI Workstation, GAP-003 – Unsupported Systems.

---

## Vector Category: Open Service Ports

**MedDefense Evidence:** MySQL (3306) on billing-srv-01, PostgreSQL (5432) on ehr-db-01, RDP (3389) on workstations and HTTP/HTTPS interfaces on medical IoT devices.

**Affected Asset(s):** billing-srv-01, ehr-db-01, Windows workstations, medical devices.

**Actor Most Likely to Exploit:** Ransomware Groups.

**Exploitation Scenario:** Once inside the network, attackers connect directly to exposed services to steal data, execute remote administration or move laterally to critical systems.

**Current Protection:** Firewall rules.

**Gap Reference:** GAP-004 – Flat Network Architecture.

---

## Vector Category: Default Credentials

**MedDefense Evidence:** Shared PACS account (raduser/radiology1) and default credentials on medical IoT devices.

**Affected Asset(s):** PACS workstation and BD Alaris medical devices.

**Actor Most Likely to Exploit:** Insider Threats and Opportunistic Attackers.

**Exploitation Scenario:** An attacker uses shared or default credentials to gain unauthorized access without exploiting software vulnerabilities. This allows unauthorized access to sensitive medical systems.

**Current Protection:** Password Policy.

**Gap Reference:** GAP-005 – Weak Credential Management.

---

## Vector Category: Unsecure Networks

**MedDefense Evidence:** Flat network with no internal segmentation, consumer router at Westside Clinic and uncertain wireless isolation.

**Affected Asset(s):** Entire MedDefense network.

**Actor Most Likely to Exploit:** Ransomware Groups.

**Exploitation Scenario:** After compromising one device, attackers move freely across servers, workstations and medical devices because there are no internal security boundaries.

**Current Protection:** Perimeter firewall.

**Gap Reference:** GAP-004 – Flat Network Architecture.

---

## Vector Category: Removable Devices / Unmanaged Endpoints

**MedDefense Evidence:** No USB restriction policy, Shadow IT devices and personal NAS connected to the network.

**Affected Asset(s):** Employee workstations, personal NAS, unmanaged devices.

**Actor Most Likely to Exploit:** Insider Threats (Negligent or Malicious).

**Exploitation Scenario:** Sensitive information can be copied to USB devices or unmanaged systems without detection. Malware may also be introduced through removable media or unauthorized devices.

**Current Protection:** Security awareness training.

**Gap Reference:** GAP-013 – No Data Loss Prevention and GAP-005 – Shadow IT.
