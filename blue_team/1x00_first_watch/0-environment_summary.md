# Environment Summary

## 1. Organization Overview

### Sites

| Site | Location Type | Primary Function | Approximate Headcount |
|------|---------------|------------------|----------------------:|
| MedDefense Central Hospital | Downtown acute-care hospital | Main hospital providing emergency, surgery, cardiology, radiology, oncology, pediatrics, maternity, pharmacy, laboratory and administration | ~1,400 |
| Westside Clinic | Suburban outpatient facility | Primary care, diagnostic imaging (X-ray and ultrasound), blood work, minor procedures and physical therapy | ~180 |
| Corporate HQ | Administrative office | Finance, Human Resources, Legal, Marketing, Executive Leadership and Information Technology | ~220 |

**Organization-wide employees:** Approximately **2,000**.

### Departments

#### MedDefense Central Hospital

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

#### Westside Clinic

- Primary Care
- Diagnostic Imaging
- Blood Work
- Minor Procedures
- Physical Therapy

#### Corporate HQ

- Finance
- Human Resources
- Legal
- Marketing
- Executive Leadership
- Information Technology

### Reporting Structure

- CEO: Dr. Patricia Morales
- CFO: Robert Kim
- COO: Angela Torres
- General Counsel: David Park
- CISO: Vacant
- Deputy CISO (Acting): James Chen
- IT Director: Sarah Park

The Security Analyst reports to James Chen.

James Chen is responsible for security policy.

Sarah Park manages IT operations.

James Chen and Sarah Park are peers, which creates separation between security governance and IT operations.

## 2. IT Infrastructure Identified

### Servers

| Asset | Type | Function | Location | Technical Details |
|-------|------|----------|----------|-------------------|
| ehr-srv-01 | Application Server | Electronic Health Record (EHR) application | MedDefense Central Hospital | Ubuntu 20.04 LTS |
| ehr-db-01 | Database Server | PostgreSQL database for the EHR system | MedDefense Central Hospital | Ubuntu 20.04 LTS |
| pacs-srv-01 | Imaging Server | PACS medical imaging server | MedDefense Central Hospital | Windows Server 2016 |
| billing-srv-01 | Application Server | Billing and claims processing | MedDefense Central Hospital | Ubuntu 18.04 LTS |
| ad-dc-01 | Domain Controller | Primary Active Directory Domain Controller | MedDefense Central Hospital | Windows Server 2019 |
| ad-dc-02 | Domain Controller | Secondary Active Directory Domain Controller | MedDefense Central Hospital | Windows Server 2019 |
| file-srv-01 | File Server | Department file shares | MedDefense Central Hospital | Windows Server 2016 |
| print-srv-01 | Print Server | Print services | MedDefense Central Hospital | Windows Server 2012 R2, marked as **Unverified** |
| backup-srv-01 | Backup Server | Backup services | MedDefense Central Hospital | Ubuntu 22.04 LTS, Veeam agent |
| web-srv-01 | Web Server | Public website and patient portal | MedDefense Central Hospital (DMZ) | Ubuntu 20.04 LTS |
| ws-srv-01 | File/Scheduling Server | Local file server and scheduling | Westside Clinic | Windows Server 2016 |
| Unknown Server | Server | Unknown | Westside Clinic | Mentioned by staff but not confirmed |

### Network Infrastructure

| Asset | Type | Function | Location | Technical Details |
|-------|------|----------|----------|-------------------|
| Fortinet FortiGate 100F | Firewall | Perimeter firewall | MedDefense Central Hospital | Internet gateway |
| Cisco Core Switch | Core Switch | Core network switching | MedDefense Central Hospital | Model unknown |
| Cisco Access Switches | Access Switches | Floor network connectivity | MedDefense Central Hospital | Two per floor |
| Ubiquiti UniFi Access Points | Wireless Access Points | Wireless connectivity | MedDefense Central Hospital | Approximately 12 units |
| Guest Wi-Fi | Wireless Network | Visitor wireless access | MedDefense Central Hospital | Separate SSID |
| Netgear Nighthawk | Router | Internet connectivity and IPSec VPN | Westside Clinic | Consumer-grade router |
| Unmanaged Switch | Switch | Local wired connectivity | Westside Clinic | Brand unknown |
| Site-to-Site VPN | VPN | Connectivity between HQ and Central | HQ / Central | VPN connection |
| IPSec VPN | VPN | Connectivity between Westside and Central | Westside / Central | Runs through Netgear router |
| DMZ | Network Segment | Hosts public-facing services | MedDefense Central Hospital | Hosts web-srv-01 |

### Endpoints

| Category | Location | Quantity | Notes |
|----------|----------|---------:|------|
| Windows 10 Workstations | Central Hospital | ~320 | Clinical and administrative users |
| Thin Clients | Central Hospital | ~60 | Clinical areas |
| Windows 10 Workstations | Westside Clinic | ~45 | Staff workstations |
| Windows 10/11 Workstations | Corporate HQ | ~120 | Administrative users |
| Laptops | Corporate HQ | ~30 | Remote-capable |
| iPads | Organization-wide | ~25 | Used by physicians during rounds |

### Medical Devices

| Device | Function | Location | Technical Details |
|--------|----------|----------|-------------------|
| Philips IntelliVue Patient Monitors | Patient monitoring | MedDefense Central Hospital | Approximately 80 units |
| BD Alaris Infusion Pumps | Medication delivery | MedDefense Central Hospital | Approximately 120 units |
| Siemens MAGNETOM MRI | Magnetic Resonance Imaging | Radiology, Central Hospital | Runs Windows XP |
| GE Revolution CT Scanner | Computed Tomography | MedDefense Central Hospital | Operating system unknown |
| IP Nurse Call System | Patient communication | MedDefense Central Hospital | Integrated with phone system |
| HID Global Access Control System | Physical access control | MedDefense Central Hospital | Connected to Active Directory for some doors |

### Supporting IT Services

| Service | Function | Scope |
|---------|----------|------|
| Microsoft 365 E3 | Email and productivity services | Organization-wide |
| Sophos Endpoint Protection | Endpoint security | Organization-wide |
| Veeam | Backup software | Central Hospital |
| MedTech Solutions | EHR maintenance | Organization-wide |
| Greenfield Building Management | HQ network and Internet | Corporate HQ |
| ClearView Security | Physical security services | Central Hospital |

## 3. Data and Services

### Data Handled

| Data Type | Description | Primary Users |
|-----------|-------------|---------------|
| Electronic Health Records (EHR) | Patient medical records stored in the EHR system | Physicians, nurses, clinical staff |
| Medical Images | Diagnostic images managed by the PACS system | Radiologists, physicians, clinical staff |
| Laboratory Data | Blood work and laboratory test results | Laboratory staff, physicians |
| Pharmacy Data | Medication and pharmacy information | Pharmacy staff, physicians |
| Billing and Claims Data | Patient billing and insurance claims | Billing department, Finance |
| Patient Portal Data | Information accessed through the patient portal | Patients, clinical staff |
| Employee Information | Human Resources records | HR staff, management |
| Financial Records | Financial and accounting information | Finance department |
| Legal Documents | Legal and compliance documentation | Legal department |
| Active Directory Data | User accounts, authentication and directory services | All employees |
| Department File Shares | Shared organizational documents | All departments |
| Backup Data | Backup copies of organizational systems and data | IT department |

### Critical Services

| Service | Supporting Infrastructure | Primary Users |
|---------|---------------------------|---------------|
| Electronic Health Record (EHR) | ehr-srv-01, ehr-db-01 | Clinical staff |
| PACS Imaging | pacs-srv-01 | Radiologists, physicians |
| Patient Portal | web-srv-01 | Patients, clinical staff |
| Billing and Claims Processing | billing-srv-01 | Billing department, Finance |
| Active Directory | ad-dc-01, ad-dc-02 | All employees |
| Department File Sharing | file-srv-01 | All departments |
| Westside Scheduling | ws-srv-01 | Westside clinical and administrative staff |
| Microsoft 365 | Cloud services | All employees |
| Backup Services | backup-srv-01, Veeam | IT department |
| VPN Connectivity | Site-to-Site VPN, IPSec VPN | Westside Clinic and Corporate HQ staff |
| Nurse Call System | IP Nurse Call System | Clinical staff |
| Badge Access Control | HID Global Access System | Employees and Facilities staff |

## 4. Known Unknowns

### Asset Inventory

- The asset inventory is incomplete and was exported from the ticketing system.
- The exact number of endpoints is unknown.
- The exact number of printers is unknown.
- The complete medical device inventory is not available.
- `print-srv-01` has not been physically verified for more than one year.
- A possible second server at Westside Clinic has been mentioned but has not been confirmed.

### Network Infrastructure

- The network diagram is incomplete.
- The real network topology has not been fully documented.
- The Cisco Core Switch model is unknown.
- The Westside Clinic switch model is unknown.
- The wireless infrastructure at Westside Clinic is undocumented.
- Guest Wi-Fi network isolation has not been verified.
- VPN Access Control Lists (ACLs) have never been audited.
- Firewall rules are not documented.
- The complete DMZ configuration is unknown.

### Systems and Software

- The operating system of the GE Revolution CT scanner is unknown.
- Additional documentation for the Siemens MAGNETOM MRI is missing.
- The management status of the organizational iPads is unknown.
- A complete software inventory is not available.
- A complete cloud services inventory is not available beyond Microsoft 365.

### Security Controls

- Sophos deployment status across all endpoints has not been verified.
- No formal vulnerability assessment has been completed.
- The current logging and monitoring configuration is unknown.
- Backup restore testing has not been documented.
- Multi-factor authentication is only confirmed for one user.

### Governance and Compliance

- No Incident Response Plan has been documented.
- No Business Continuity Plan has been documented.
- No Disaster Recovery Plan has been documented.
- HIPAA Security Rule compliance has never been formally assessed.
- The CISO position is currently vacant.

### Contradictory or Inconsistent Information

- The organization is described as having approximately 2,000 employees, while the documented site headcounts total approximately 1,800.
- The HR documentation describes the Central Hospital as having six floors plus a basement, while the available network diagram only shows four floors.
- The asset inventory and network documentation are incomplete.

