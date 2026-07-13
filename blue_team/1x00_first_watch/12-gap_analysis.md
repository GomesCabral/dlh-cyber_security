# Prioritized Gap Analysis

## GAP-001

**Gap ID:** GAP-001

**Title:** Legacy MRI workstation running unsupported Windows XP

**Affected Asset(s):** MRI Control Workstation (Critical)

**Data at Risk:** Medical imaging data (Restricted)

**Current Control Status:** Firewall protection and authentication exist, but no network segmentation or endpoint protection.

**What is Missing:** Technical Compensating and Technical Detective controls.

**Risk Level:** Critical

**Risk Justification:** The workstation runs an unsupported operating system connected to the production network. It supports patient diagnosis and has no effective detective controls.

**Potential Impact:** A compromise could interrupt MRI services, expose imaging data and provide an entry point for lateral movement across the hospital network.

---

## GAP-002

**Gap ID:** GAP-002

**Title:** Unattended EHR sessions expose patient records

**Affected Asset(s):** EHR System (Critical)

**Data at Risk:** Patient medical records (Restricted)

**Current Control Status:** Authentication and password policies exist.

**What is Missing:** Technical Preventive controls such as automatic session locking.

**Risk Level:** Critical

**Risk Justification:** Protected health information remains accessible on unattended workstations.

**Potential Impact:** Unauthorized users could access or modify patient records, creating regulatory violations and patient safety risks.

---

## GAP-003

**Gap ID:** GAP-003

**Title:** Billing server remains on unsupported operating system

**Affected Asset(s):** billing-srv-01 (High)

**Data at Risk:** Billing and insurance information (Restricted)

**Current Control Status:** Firewall, backups and authentication are implemented.

**What is Missing:** Technical Preventive controls through supported operating system updates.

**Risk Level:** Critical

**Risk Justification:** The server has already experienced ransomware and cryptomining incidents while running an unsupported platform.

**Potential Impact:** Financial services may become unavailable and sensitive billing information could be compromised.

---

## GAP-004

**Gap ID:** GAP-004

**Title:** Medical devices share the same network as user workstations

**Affected Asset(s):** Medical IoT Devices (Critical)

**Data at Risk:** Patient monitoring information (Restricted)

**Current Control Status:** Basic firewall protection only.

**What is Missing:** Technical Compensating controls through network segmentation.

**Risk Level:** Critical

**Risk Justification:** Flat network architecture allows lateral movement between user workstations and patient-care devices.

**Potential Impact:** Compromise of medical devices could directly affect patient care.

---

## GAP-005

**Gap ID:** GAP-005

**Title:** Personal NAS storing organizational data

**Affected Asset(s):** Shadow NAS (High)

**Data at Risk:** Research and patient-related information (Restricted)

**Current Control Status:** No official security controls.

**What is Missing:** Administrative governance, Technical monitoring and Corrective backup controls.

**Risk Level:** Critical

**Risk Justification:** Sensitive data is stored outside organizational control.

**Potential Impact:** Data theft, ransomware or complete loss of research information.

---

## GAP-006

**Gap ID:** GAP-006

**Title:** Personal Google Drive used for business data

**Affected Asset(s):** Marketing Cloud Storage (High)

**Data at Risk:** Internal communications (Confidential)

**Current Control Status:** Outside corporate security controls.

**What is Missing:** Administrative governance and centralized identity management.

**Risk Level:** High

**Risk Justification:** Business information is controlled through a personal account.

**Potential Impact:** Unauthorized disclosure or permanent loss of organizational files.

---

## GAP-007

**Gap ID:** GAP-007

**Title:** No centralized security monitoring

**Affected Asset(s):** Entire Infrastructure (Critical)

**Data at Risk:** Restricted and Confidential organizational data.

**Current Control Status:** Local logs only.

**What is Missing:** Technical Detective controls (SIEM).

**Risk Level:** Critical

**Risk Justification:** Security incidents may remain undetected for extended periods.

**Potential Impact:** Attackers could maintain persistence and compromise multiple systems before detection.

---

## GAP-008

**Gap ID:** GAP-008

**Title:** Disaster recovery procedures are not tested

**Affected Asset(s):** Backup Infrastructure (Critical)

**Data at Risk:** All production data (Restricted)

**Current Control Status:** Daily backups exist.

**What is Missing:** Administrative Corrective controls.

**Risk Level:** High

**Risk Justification:** Recovery capability has never been validated.

**Potential Impact:** Backup restoration may fail during a real ransomware or disaster event.

---

## GAP-009

**Gap ID:** GAP-009

**Title:** Network management credentials exposed

**Affected Asset(s):** Network Infrastructure (Critical)

**Data at Risk:** Network administration credentials (Restricted)

**Current Control Status:** Physical access controls are inadequate.

**What is Missing:** Administrative and Physical Preventive controls.

**Risk Level:** Critical

**Risk Justification:** Anyone entering the network closet can obtain privileged credentials.

**Potential Impact:** Unauthorized network configuration changes or complete network compromise.

---

## GAP-010

**Gap ID:** GAP-010

**Title:** Undocumented Linux systems operating on the network

**Affected Asset(s):** UNKNOWN-01 and Westside Linux Device (High)

**Data at Risk:** Unknown (Potentially Confidential)

**Current Control Status:** No documented ownership or monitoring.

**What is Missing:** Asset management, Technical Detective controls and Administrative governance.

**Risk Level:** High

**Risk Justification:** Unmanaged systems create unknown attack surfaces.

**Potential Impact:** Attackers could use these systems as persistence mechanisms or pivot points.

---

# Gap Distribution Summary

| Risk Level | Number of Gaps |
|------------|----------------|
| Critical | 6 |
| High | 4 |
| Medium | 0 |
| Low | 0 |

## Asset Categories with the Most Gaps

- Medical IoT and Clinical Systems
- Core Server Infrastructure
- Network Infrastructure
- Shadow IT Assets

## Control Category / Function Most Affected

The majority of identified gaps involve missing or inadequate **Technical Detective** and **Technical Compensating** controls. While MedDefense has implemented several preventive controls, its ability to detect attacks, isolate compromised systems and respond effectively remains insufficient.
