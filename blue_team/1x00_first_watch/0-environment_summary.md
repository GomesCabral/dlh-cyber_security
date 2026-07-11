# MedDefense Health Systems — Structured Environment Summary

## Scope and Source Limitations

This summary is based only on the MedDefense onboarding packet supplied to the new Security Analyst. The packet contains an HR onboarding excerpt, a partial ServiceDesk asset export, informal security notes, a service-contract summary, an incomplete network diagram, and an organization chart.

The source documentation is incomplete, partly outdated, and not independently verified. Items described as unknown, unverified, approximate, suspected, or incomplete are preserved as such below. No missing technical details have been invented.

---

## 1. Organization Overview

### 1.1 Sites

| Site | Location type | Primary function | Approximate headcount | Relevant physical/IT details |
|---|---|---|---:|---|
| **MedDefense Central Hospital** | Downtown acute-care hospital | Emergency and inpatient clinical care; surgery; diagnostic and support services; administration | **1,400** clinical and support staff | 350 beds; six floors plus basement; mechanical equipment and server room are in the basement; underground staff garage and surface visitor parking |
| **Westside Clinic** | Suburban outpatient facility, approximately 12 minutes from Central | Primary care, X-ray, ultrasound, blood work, minor procedures, and physical therapy | **180** | Two-story medical office complex; parking shared with an adjacent retail plaza; shares some IT services with Central; has a local server closet |
| **Corporate HQ** | Administrative office in Greenfield Business Park, approximately 15 minutes from Central | Finance, HR, Legal, Marketing, Executive Leadership, and IT | **220** | Leased space on the third floor of a five-story commercial building; IT department is located here; no on-premises servers are documented |

The packet states that MedDefense employs approximately **2,000 people organization-wide**. The listed site headcounts total approximately 1,800, leaving an unexplained difference of about 200 employees. This may reflect rounding, omitted personnel, contractors, or stale data, but the packet does not explain it.

### 1.2 Departments Relevant to Security

**Clinical and operational departments at Central:**

- Emergency
- Surgery
- Cardiology
- Radiology
- Oncology
- Pediatrics
- Maternity
- Pharmacy
- Laboratory
- Administration

**Clinical services at Westside:**

- Primary care
- Diagnostic imaging: X-ray and ultrasound; no MRI
- Blood work
- Minor procedures
- Physical therapy

**Corporate departments at HQ:**

- Finance
- Human Resources
- Legal
- Marketing
- Executive Leadership
- Information Technology

### 1.3 Security and IT Reporting Structure

- **CEO:** Dr. Patricia Morales
- **CFO:** Robert Kim
- **COO:** Angela Torres
  - Clinical Directors report under the COO.
- **General Counsel:** David Park
- **CISO:** Vacant
- **Deputy CISO / Acting security lead:** James Chen
  - In practice, James reports directly to the CEO.
  - James has authority over security policy.
  - James does **not** have authority over IT operations.
  - The new Security Analyst reports to James.
- **IT Director:** Sarah Park
  - Sarah and James are organizational peers.
  - Sarah controls IT operations.
  - The packet states that this division of authority creates friction.

### 1.4 IT Staffing

The IT department has **12 staff members**:

- 1 IT Director
- 3 System Administrators
- 2 Network Technicians
- 1 Database Administrator
- 2 Helpdesk Analysts, including Mike Torres as lead
- 2 Desktop Support Technicians
- 1 IT Intern position, currently vacant

The security function consists of James Chen and the new Security Analyst. Marcus Webb, the previous analyst, left three months before the new analyst's start date.

---

## 2. IT Infrastructure Identified

### 2.1 Servers — MedDefense Central

| Name | Type / operating system | Function | Location | Technical details and current status |
|---|---|---|---|---|
| `ehr-srv-01` | Ubuntu 20.04 LTS server | Electronic Health Record application server | Central server environment | Marcus migrated this host to SSH key authentication; it is the intended application client for `ehr-db-01` |
| `ehr-db-01` | Ubuntu 20.04 LTS server; PostgreSQL | EHR database | Central server environment | PostgreSQL is reportedly reachable from the entire `10.10.0.0/16` network; Marcus states it should be restricted to `ehr-srv-01` |
| `pacs-srv-01` | Windows Server 2016 | PACS medical imaging server | Central server environment | Used by Radiology; a shared PACS workstation account is documented |
| `billing-srv-01` | Ubuntu 18.04 LTS server | Billing and claims processing | Central server environment | Repeated performance problems; IT reportedly restarts it rather than resolving the cause; a prior ransomware incident affected this server |
| `ad-dc-01` | Windows Server 2019 | Primary Active Directory domain controller | Central server environment | Central identity service; the badge/access system is connected to AD for some doors |
| `ad-dc-02` | Windows Server 2019 | Secondary Active Directory domain controller | Central server environment | Redundant domain controller |
| `file-srv-01` | Windows Server 2016 | Department file shares | Central server environment | Shared drive `S:\Security\Notes` is documented, implying departmental/shared storage on the environment |
| `print-srv-01` | Windows Server 2012 R2 | Print server | Central server environment | Marked **unverified**; not physically confirmed in over a year; operating system reached end of support in October 2023 according to Marcus's notes |
| `backup-srv-01` | Ubuntu 22.04 LTS; Veeam agent | Backup server | Central server room | Nightly backups are written to a local NAS in the same room, rack, and network |
| `web-srv-01` | Ubuntu 20.04 LTS | Public website and patient portal | Central DMZ, according to the draft diagram | Connected to a DMZ off the FortiGate in the simplified network diagram |

### 2.2 Servers — Westside Clinic

| Name | Type / operating system | Function | Location | Technical details and current status |
|---|---|---|---|---|
| `ws-srv-01` | Windows Server 2016 | Local file services and scheduling | Westside server closet | Confirmed in the partial asset list |
| **Possible unidentified server** | Unknown | Unknown | Westside server closet | Mentioned to Marcus by Mike Torres but never confirmed |

### 2.3 Servers — Corporate HQ

No on-premises servers are documented at Corporate HQ. HQ personnel use cloud services and connect to Central infrastructure through a site-to-site VPN.

### 2.4 Network Infrastructure

| Device / service | Location | Function | Known details |
|---|---|---|---|
| Fortinet FortiGate 100F | Central | Internet perimeter firewall; VPN termination; DMZ connection | Supported under a Fortinet service contract; appears to be the primary perimeter control |
| Cisco core switch | Central | Core network switching | Model unknown |
| Cisco access switches | Central | Floor-level access switching | Approximately two per floor; exact count and models are not documented |
| Ubiquiti UniFi access points | Central | Wireless access | Approximately 12 units |
| Guest Wi-Fi SSID | Central | Visitor wireless access | Separate SSID exists, but actual isolation from the internal network has not been verified |
| Central network | Central | Shared network for endpoints, servers, and medical devices | Documented as a flat `10.10.0.0/16` broadcast domain with no VLANs |
| Unmanaged switch | Westside | Local wired connectivity | Brand and model unknown |
| Consumer-grade Netgear Nighthawk router | Westside | Internet access and site-to-site VPN to Central | No dedicated firewall is documented; traffic reportedly connects directly to the ISP through this router |
| Wireless infrastructure | Westside | Wireless access | Vendor, model, configuration, and security status unknown |
| Building-managed network | HQ | Internet and building network services | Managed by the landlord; MedDefense has its own VLAN |
| Site-to-site VPN | HQ to Central | Remote site connectivity | Present; configuration appears acceptable to Marcus, but ACLs were not audited |
| IPSec VPN | Westside to Central | Remote site connectivity | Runs through the consumer router |
| DMZ | Central | Hosts externally exposed services | `web-srv-01` is shown in the DMZ; full DMZ design and rule set are not documented |
| Network ACLs | HQ/Central VPN and possibly elsewhere | Traffic control | Not audited; exact rules unknown |

### 2.5 Endpoints

| Category | Approximate quantity | Location / users | Known details |
|---|---:|---|---|
| Windows 10 workstations | 320 | Central | Count comes from an Active Directory report that was eight months old |
| Thin clients | 60 | Central clinical areas | Exact models, operating systems, ownership, and management status unknown |
| Windows 10 workstations | 45 | Westside | Approximate count |
| Windows 10/11 workstations | 120 | HQ | Approximate count |
| Remote-capable laptops | 30 | HQ | Exact operating systems, ownership, encryption, and remote-access controls unknown |
| iPads | 25 | Used by physicians during rounds | Device-management status is explicitly unclear |
| PACS workstation(s) | Quantity unknown | Radiology | At least one workstation uses a shared login; hardware and OS details are not provided |
| Printers and other peripherals | Implied, quantity unknown | Organization-wide | A print server exists, but printer inventory is absent |

Marcus states that nobody has a complete endpoint count and that the available figures are based on an eight-month-old AD report.

### 2.6 Medical and Operational Technology Devices

| Device / system | Approximate quantity | Location | Function / details |
|---|---:|---|---|
| Philips IntelliVue connected patient monitors | 80 | Central | Patient monitoring; connected to the same flat network as other systems |
| BD Alaris infusion pumps | 120 | Central | Network-connected for dosage updates; reachable from the shared network according to Marcus |
| Siemens MAGNETOM MRI scanner | 1 | Central Radiology | Runs Windows XP; separate referenced file is not included in the packet |
| GE Revolution CT scanner | 1 | Central | Operating system unknown |
| IP-based nurse call system | At least 1 system | Central, exact coverage unknown | Integrated with the telephone system |
| HID Global badge/access system | At least 1 system | Central and possibly other sites; exact scope unknown | Connected to Active Directory for some doors |
| X-ray equipment | Quantity/model unknown | Westside | Diagnostic imaging service implies supporting equipment, but no asset details are supplied |
| Ultrasound equipment | Quantity/model unknown | Westside | Diagnostic imaging service implies supporting equipment, but no asset details are supplied |
| Laboratory and pharmacy systems/devices | Implied, not inventoried | Central and possibly Westside | The organization operates Laboratory and Pharmacy departments, but no supporting assets are listed |

The last three categories are **implied by documented business services**, not confirmed inventory records.

### 2.7 Security, Backup, Cloud, and Support Services

| Service / vendor | Function | Scope / location | Known details |
|---|---|---|---|
| Sophos Endpoint Protection | Endpoint malware protection | Organization-wide scope is implied by contract, but actual deployment is unknown | Annual contract exists; Marcus did not verify currency or coverage across all endpoints |
| Veeam | Backup software | Central backup environment | Nightly backup to local NAS; no approved off-site/cloud copy documented |
| Local NAS | Backup storage | Central server room | Same room, rack, and network as production/backup server |
| Microsoft 365 E3 | Cloud productivity and collaboration | Organization-wide | Main known cloud platform; other departmental cloud use is suspected but not inventoried |
| MedTech Solutions | EHR maintenance | EHR environment | Includes software updates, not hardware; four-hour response for critical issues and 24-hour response for standard issues |
| Greenfield Building Management | HQ network and internet | HQ | Service included in lease |
| ClearView Security | Physical guard service | Central main entrance | One guard, Monday-Friday, 07:00-19:00; no night/weekend coverage; no guard at Westside or HQ |
| Ubiquiti UniFi controller | Wireless management | Central | Free controller license; configuration and management host are not documented |
| UPS | Short-duration power protection | Central | Approximately 20 minutes of capacity; model, load, maintenance, and generator integration are unknown |

### 2.8 Documented Authentication and Access Controls

- Password policy:
  - Minimum length: eight characters
  - Complexity enabled
  - Password rotation every 90 days
- Multi-factor authentication:
  - Not implemented generally
  - Only James's personal account is documented as using MFA
- Shared account:
  - Radiology uses a shared PACS workstation login
  - The packet contains the credential in plaintext; it should be treated as exposed and changed
- Linux SSH:
  - Password authentication remains enabled on all Linux servers except `ehr-srv-01`, which Marcus began migrating to key-only authentication
- Physical access:
  - Server-room access uses the same generic badge issued broadly to personnel
  - Westside's server closet reportedly does not lock
- Cameras:
  - Present in the Central parking garage and Emergency Room entrance
  - No cameras documented near the server-room corridor or IT infrastructure

---

## 3. Data and Services

### 3.1 Data Types Handled

| Data type | Evidence in the packet | Primary users / stakeholders |
|---|---|---|
| Electronic patient health records | EHR application and PostgreSQL database | Physicians, nurses, clinical staff, health-information and administrative personnel |
| Medical images and imaging records | PACS server, MRI, CT, X-ray, ultrasound | Radiology staff, physicians, clinical teams |
| Patient monitoring data | Connected patient monitors | Nurses, physicians, clinical operations |
| Infusion and dosage-update data | Network-connected infusion pumps | Clinical staff, pharmacy, biomedical/IT support |
| Patient portal data | Public website and patient portal on `web-srv-01` | Patients and authorized staff |
| Billing and insurance-claim data | `billing-srv-01` | Billing, Finance, administrative staff, insurers/claims partners |
| Appointment and scheduling data | Westside local scheduling service | Westside clinical and administrative staff |
| Departmental files | `file-srv-01` and shared-drive references | Clinical, administrative, IT, and security staff |
| Identity and authentication data | Active Directory domain controllers | All workforce users and systems joined to the domain |
| Employee and HR data | HR department and Microsoft 365 use | HR, management, employees |
| Financial, legal, marketing, and executive records | Corporate departments and Microsoft 365 | Finance, Legal, Marketing, executives |
| Physical-access records | HID badge/access system connected partly to AD | Security, facilities, IT, management |
| Audit, event, and security logs | Implied by servers, firewall, AD, endpoint protection, and applications | IT and Security; actual collection/retention is unknown |
| Backup copies of organizational data | Veeam backup server and local NAS | IT, Security, business/system owners during restoration |

Some categories above are inferred from the named systems and departments. The packet does not provide a formal data inventory, classification scheme, data-flow map, or record-retention schedule.

### 3.2 Critical IT-Dependent Services

| Service | Supporting infrastructure | Main users | Criticality rationale based on packet |
|---|---|---|---|
| Electronic Health Record access | `ehr-srv-01`, `ehr-db-01`, AD, network infrastructure | Clinical staff across applicable sites | Supports access to patient records and clinical operations |
| Medical imaging and image retrieval | `pacs-srv-01`, MRI, CT, Westside imaging equipment, network | Radiology and treating clinicians | Supports diagnosis and treatment |
| Patient monitoring | Philips IntelliVue monitors and network | Nurses and physicians | Supports real-time clinical observation |
| Infusion management and dosage updates | BD Alaris pumps and network | Nursing, pharmacy, clinical teams | Directly supports medication delivery workflows |
| Billing and claims processing | `billing-srv-01` | Billing, Finance, administration | Supports revenue cycle and insurance claims |
| Identity and access management | `ad-dc-01`, `ad-dc-02` | Entire workforce and connected systems | Required for authentication and some physical-access integration |
| File sharing | `file-srv-01`; `ws-srv-01` at Westside | Departments across the organization | Supports operational document access |
| Westside scheduling | `ws-srv-01` | Westside staff and patients indirectly | Supports outpatient operations |
| Public website and patient portal | `web-srv-01`, DMZ, Internet connectivity | Patients, public users, authorized staff | Supports public information and patient-facing digital services |
| Internal and external communications/productivity | Microsoft 365 E3, HQ and site connectivity | Organization-wide | Supports email, collaboration, and administrative work |
| Printing | `print-srv-01` and unknown printer fleet | Clinical and administrative users | Supports paper-dependent workflows; exact criticality is not documented |
| Backup and restoration | `backup-srv-01`, Veeam, local NAS | IT and all service owners | Required to recover systems and data |
| Site connectivity | FortiGate, Westside and HQ VPNs, switches, routers | Westside and HQ personnel | Enables access to Central-hosted services |
| Nurse call communications | IP nurse call system and telephone integration | Patients and clinical staff | Supports patient-to-staff communications |
| Physical access control | HID Global system and AD integration | Workforce, facilities, security | Controls access to at least some doors |
| Endpoint protection | Sophos | Organization-wide endpoint users | Helps prevent and detect endpoint threats; actual coverage unknown |

### 3.3 Documented Service Resilience and Dependencies

- Central appears to be the primary infrastructure hub.
- Westside depends on Central for some IT services over an IPSec VPN running through a consumer router.
- HQ depends on cloud services and a site-to-site VPN to Central.
- The EHR application depends on the EHR PostgreSQL database.
- Active Directory supports workforce authentication and some physical-access functions.
- The patient portal and public website depend on `web-srv-01`, the DMZ, the FortiGate, and Internet connectivity.
- Backups depend on a local Veeam server and local NAS located in the same physical and network environment.
- Central's documented UPS supports approximately 20 minutes; no documented business continuity or disaster recovery procedure exists for a longer outage.
- MedTech Solutions provides EHR software support but does not cover EHR hardware.

---

## 4. Known Unknowns

### 4.1 Asset Inventory Gaps

1. **No authoritative asset inventory exists.** The ServiceDesk export is explicitly partial, records were entered inconsistently, and endpoint counts are based on an eight-month-old AD report.
2. **The physical existence and status of `print-srv-01` are unverified.** It has not been physically confirmed in over a year.
3. **A possible second Westside server is unconfirmed.** Its name, owner, function, operating system, data, and network exposure are unknown.
4. **The total endpoint count is unknown.** No complete inventory of desktops, laptops, thin clients, tablets, PACS workstations, printers, or other connected devices is available.
5. **iPad management is unknown.** Enrollment, MDM, encryption, application control, remote wipe, patching, and ownership are not documented.
6. **Medical-device inventory is incomplete.** Serial numbers, firmware, software versions, IP addresses, support status, maintenance ownership, and vendor remote-access paths are missing. The MRI references a separate file that is not included, and the CT operating system is unknown.
7. **Network-device inventory is incomplete.** Central switch models and exact quantities, Westside switch details, Westside Wi-Fi, and landlord-managed HQ controls are not documented.
8. **No inventory of printers, telephony components, nurse-call components, UPS units, NAS hardware, cameras, badge readers, or facilities/IoT systems is provided.**
9. **No software inventory exists.** Installed applications, versions, licensing, unauthorized software, and server packages are unknown.
10. **No complete cloud-service inventory exists.** Microsoft 365 is known; additional departmental services are suspected but unidentified.

### 4.2 Network Architecture Gaps

11. **The network diagram is explicitly incomplete and simplified.** The real topology is described as more complex.
12. **The exact Central topology is unknown.** The diagram shows floors 1-4 although Central has six floors plus a basement; floors 5 and 6 are absent.
13. **The packet states that Central is flat and has no VLANs, but the DMZ is shown separately.** The routing and filtering relationship is not documented.
14. **Guest Wi-Fi isolation is unverified.** A separate SSID does not prove isolation.
15. **VPN controls are not documented.** HQ ACLs were not audited; Westside VPN settings, authentication, logging, and permitted routes are unknown.
16. **Internet redundancy and site-connectivity resilience are unknown.** Providers, circuits, failover, and capacity are absent.
17. **No IP address management, DNS, DHCP, network access control, or wireless-security configuration is documented.**
18. **No network-monitoring architecture is documented.** IDS/IPS, NetFlow, centralized logging, SIEM, and alerting are unknown.

### 4.3 Security-Control Gaps

19. **Endpoint-protection coverage is unknown.** A Sophos contract exists, but deployment and health have not been verified.
20. **Patch and vulnerability-management status is unknown.** No formal server assessment has been completed, and other asset classes are not documented.
21. **MFA scope is effectively unknown beyond James's account.** No evidence covers Microsoft 365, VPN, privileged accounts, EHR, the patient portal, or administration tools.
22. **Privileged-access management is not documented.** Administrator accounts, service accounts, local admin rights, emergency access, and credential vaulting are unknown.
23. **Shared-account use may extend beyond Radiology.** No organization-wide review has occurred.
24. **Password-policy enforcement scope is unknown.** It may apply only to AD; application, device, cloud, and local-account coverage is not documented.
25. **SSH configuration is only partly documented.** Key ownership, rotation, storage, sudo controls, and other Linux-server configurations are unknown.
26. **Logging and audit capability are unknown.** Sources, retention, review, synchronization, alerting, and centralized collection are absent.
27. **Email-security controls are unknown.** Anti-phishing, SPF/DKIM/DMARC, attachment filtering, user reporting, and mailbox auditing are not described.
28. **Data-protection controls are unknown.** Encryption, removable-media controls, DLP, database encryption, laptop encryption, and secure disposal are not documented.
29. **Backup effectiveness is unverified.** Job success, scope, encryption, immutability, retention, restore testing, credentials, and recovery objectives are unknown.
30. **Security-awareness training is not mentioned.** Frequency, phishing exercises, role-based training, and metrics are unknown.
31. **Third-party and supply-chain access is unknown.** Vendor remote access, support accounts, security requirements, and contract controls are not described.

### 4.4 Data, Application, and Service Gaps

32. **No formal data inventory or classification exists in the packet.** Owners, sensitivity, retention, legal requirements, and disposal are unknown.
33. **No data-flow diagrams are provided.** Flows among EHR, PACS, portal, billing, devices, Microsoft 365, vendors, and partners are unknown.
34. **The EHR environment is incompletely documented.** Product/version, users, interfaces, availability design, authentication, logging, and recovery are absent.
35. **The patient-portal architecture is unknown.** Ownership, authentication, encryption, external dependencies, testing, and data scope are not documented.
36. **PACS details are incomplete.** Workstation count, connected modalities, storage, retention, remote access, interfaces, and audit controls are unknown.
37. **`billing-srv-01` performance problems are unresolved.** Root cause, utilization, dependencies, compromise indicators, and current status are unknown.
38. **The prior ransomware incident is incompletely documented.** Date details, initial access, affected systems, data exposure, containment, eradication, recovery, and notifications are unknown.
39. **Business-service criticality has not been formally assessed.** No BIA, RTOs, RPOs, or dependency map exists.
40. **Clinical downtime procedures are unknown or absent.** No documented procedure covers outages beyond approximately 20 minutes of UPS capacity.

### 4.5 Physical and Environmental Gaps

41. **Server-room access authorization is unclear.** A broadly issued badge reportedly permits access; no access list or review process is documented.
42. **Westside server-closet controls are inadequate and incomplete.** The closet reportedly does not lock; environmental controls are unknown.
43. **Camera coverage is incomplete.** No coverage is documented near the Central server-room corridor; retention and monitoring are unknown.
44. **Environmental resilience is unknown.** Generator capacity, UPS maintenance, fire suppression, water detection, HVAC redundancy, and disaster exposure are not documented.
45. **Physical-security coverage is limited.** Central has one weekday daytime guard; there is no documented night/weekend guard or guard at Westside/HQ.

### 4.6 Governance, Compliance, and Process Gaps

46. **HIPAA Security Rule compliance has never been formally assessed.** Legal claims compliance without evidence in the packet.
47. **No formal incident response plan exists.** Roles, escalation, communications, evidence handling, notification, playbooks, and exercises are absent.
48. **No documented Business Continuity Plan or Disaster Recovery Plan exists.**
49. **No formal after-action report for the ransomware incident is documented.**
50. **Security governance authority is unclear and contested.** James controls policy, Sarah controls operations, and no formal risk-acceptance process is described.
51. **The CISO role is vacant.** Executive accountability, risk ownership, budget authority, and long-term sponsorship are unclear.
52. **No formal risk register or security roadmap is provided.** Items described as planned lack dates, owners, budgets, milestones, and accepted-risk records.
53. **Security staffing and coverage are limited.** Responsibilities, on-call coverage, separation of duties, and escalation support are not defined.
54. **Policies and standards are largely absent.** No supplied policies cover acceptable use, access, changes, assets, vulnerabilities, backups, encryption, vendors, or secure configuration.
55. **Change and configuration management are unknown.** Baselines, approvals, emergency changes, configuration backups, and drift monitoring are not described.
56. **Ownership is unclear for many systems.** Technical, business, data, and risk owners are not assigned.

### 4.7 Documentation Contradictions or Ambiguities

57. **Organization-wide headcount does not reconcile with site totals.** Site estimates total approximately 1,800, while the organization-wide figure is approximately 2,000.
58. **Central building and diagram floor counts do not align.** HR describes six floors plus basement; the diagram shows floors 1-4 and servers.
59. **The asset list is partial and quantities are approximate.** Listed figures cannot be treated as authoritative totals.
60. **HQ has no on-premises servers but depends on landlord-managed networking and Central connectivity.** Responsibility boundaries are undocumented.
61. **The badge/access system connects to AD for “some doors.”** Covered doors, excluded doors, and architecture are unknown.

---

## Initial Validation Priorities

Although remediation prioritization belongs in the broader security posture assessment, these validation activities are required to understand the environment:

1. Physically validate servers, network devices, medical devices, and backup equipment at all sites.
2. Export current endpoint, user, group, software, and OS data from AD, Microsoft 365, Sophos, network tools, and ServiceDesk.
3. Discover the real topology and verify segmentation, routing, firewall rules, VPN ACLs, and guest Wi-Fi isolation.
4. Investigate `billing-srv-01` immediately and preserve evidence before routine restart or modification.
5. Confirm backup scope, job health, restore capability, credentials, and any offline, immutable, or off-site copies.
6. Identify externally exposed services and vendor remote-access paths.
7. Build an inventory of applications, cloud services, data stores, owners, and data flows.
8. Validate medical-device operating systems, firmware, connectivity, vendor support, and compensating controls.
9. Review privileged, shared, dormant, and service accounts and confirm MFA coverage.
10. Collect policies, contracts, risk acceptances, incident records, audit evidence, and continuity documentation.

---

## Summary

MedDefense operates a centralized healthcare technology environment supporting three sites and approximately 2,000 employees. Central hosts the known core systems, including EHR, PACS, billing, Active Directory, file, backup, web, and patient-portal services. Westside depends partly on Central while maintaining local file and scheduling infrastructure. HQ relies on cloud services and VPN connectivity to Central.

The packet identifies numerous technologies and dependencies, but it does not constitute a reliable asset inventory or current architecture record. The most important onboarding conclusion is therefore not only that several security weaknesses are visible, but also that MedDefense lacks the verified asset, network, data, ownership, and control information required to measure its security posture confidently.
