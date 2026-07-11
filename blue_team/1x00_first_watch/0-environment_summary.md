# Environment Summary

## 1. Organization Overview

### Sites

| Site | Location Type | Function | Approximate Headcount |
|------|---------------|----------|----------------------|
| MedDefense Central Hospital | Downtown acute-care hospital | Main hospital providing emergency, surgery, cardiology, radiology, oncology, pediatrics, maternity, pharmacy, laboratory and administration | ~1,400 |
| Westside Clinic | Suburban outpatient clinic | Primary care, X-ray, ultrasound, blood work, minor procedures and physical therapy | ~180 |
| Corporate HQ | Administrative office | Finance, HR, Legal, Marketing, Executive Leadership and IT | ~220 |

Total organization headcount: **approximately 2,000 employees.**

### Departments Relevant to Security

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

James Chen is responsible for security policy but does not manage IT operations.

Sarah Park manages the IT department.

IT Department:

- 3 System Administrators
- 2 Network Technicians
- 1 Database Administrator
- 2 Helpdesk Analysts
- 2 Desktop Support Technicians
- 1 IT Intern (vacant)

---

# 2. IT Infrastructure Identified

## Central Hospital Servers

| Server | Operating System | Function |
|---------|-----------------|----------|
| ehr-srv-01 | Ubuntu 20.04 LTS | EHR Application Server |
| ehr-db-01 | Ubuntu 20.04 LTS | PostgreSQL EHR Database |
| pacs-srv-01 | Windows Server 2016 | PACS Imaging Server |
| billing-srv-01 | Ubuntu 18.04 LTS | Billing and Claims Processing |
| ad-dc-01 | Windows Server 2019 | Primary Domain Controller |
| ad-dc-02 | Windows Server 2019 | Secondary Domain Controller |
| file-srv-01 | Windows Server 2016 | File Server |
| print-srv-01 | Windows Server 2012 R2 | Print Server (Unverified) |
| backup-srv-01 | Ubuntu 22.04 LTS | Backup Server (Veeam) |
| web-srv-01 | Ubuntu 20.04 LTS | Public Website and Patient Portal |

## Westside Clinic

- ws-srv-01 (Windows Server 2016)
- Possible second unknown server (not confirmed)

## Corporate HQ

- No on-premises servers
- Uses cloud services
- Connected to Central via Site-to-Site VPN

## Network Infrastructure

- Fortinet FortiGate 100F Firewall
- Cisco Core Switch
- Cisco Access Switches
- Ubiquiti UniFi Access Points (12)
- Guest Wi-Fi
- Site-to-Site VPN
- IPSec VPN
- DMZ
- Netgear Nighthawk consumer router (Westside)
- Unmanaged switch (Westside)

## Endpoints

Central:

- ~320 Windows 10 workstations
- ~60 Thin Clients

Westside:

- ~45 Windows 10 workstations

Corporate HQ:

- ~120 Windows 10/11 workstations
- ~30 laptops

Mobile Devices:

- ~25 iPads

## Medical Devices

- Philips IntelliVue patient monitors (~80)
- BD Alaris infusion pumps (~120)
- Siemens MAGNETOM MRI
- GE Revolution CT Scanner
- IP Nurse Call System
- HID Global Badge/Access System

---

# 3. Data and Services

## Data

MedDefense handles:

- Electronic Health Records (EHR)
- Patient medical records
- Medical images
- Laboratory information
- Pharmacy information
- Billing and insurance claims
- Employee records
- Financial data
- Legal documents
- Active Directory user accounts
- Authentication information
- Backup data
- Patient portal information

## Critical Services

- Electronic Health Record (EHR)
- PostgreSQL EHR Database
- PACS Imaging System
- Billing and Claims Processing
- Patient Portal
- Public Website
- Active Directory
- File Sharing
- Scheduling System
- Microsoft 365
- VPN Connectivity
- Backup Services
- Nurse Call System
- Badge/Access Control

## Users

Clinical Staff:

- Doctors
- Nurses
- Radiology
- Laboratory
- Pharmacy

Administrative Staff:

- Finance
- HR
- Legal
- Marketing
- Executive Management

IT Staff:

- System Administrators
- Network Technicians
- Database Administrator
- Helpdesk
- Desktop Support
- Security Team

Patients:

- Patient Portal users

---

# 4. Known Unknowns

## Asset Inventory

- Asset inventory is incomplete.
- print-srv-01 has not been physically verified.
- Possible second server at Westside has not been confirmed.
- Total endpoint inventory is unknown.
- Printer inventory is unknown.
- Medical device inventory is incomplete.

## Network

- Cisco Core Switch model is unknown.
- Westside switch brand is unknown.
- Westside Wi-Fi equipment is unknown.
- Guest Wi-Fi isolation has not been verified.
- HQ VPN ACLs have not been audited.
- Firewall rules are undocumented.
- DMZ configuration is incomplete.
- Network topology is incomplete.

## Systems

- CT Scanner operating system is unknown.
- MRI supporting documentation is missing.
- iPad management status is unknown.
- Cloud service inventory is incomplete.
- Software inventory is incomplete.

## Security

- No formal vulnerability assessment.
- Sophos deployment status is unknown.
- MFA is implemented only for James Chen.
- Shared accounts may exist beyond Radiology.
- Logging and monitoring configuration is unknown.
- Backup restore testing is unknown.

## Governance

- No Incident Response Plan.
- No Business Continuity Plan.
- No Disaster Recovery Plan.
- HIPAA Security Rule has never been formally assessed.
- CISO position is vacant.

## Contradictions

- Organization headcount is approximately 2,000 employees, but site totals add up to approximately 1,800.
- Building description states six floors plus basement, while the network diagram shows only four floors.
- The ServiceDesk asset list is explicitly described as incomplete and partially outdated.
