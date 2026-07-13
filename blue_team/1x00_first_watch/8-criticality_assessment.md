# Asset Criticality Assessment

## Asset Criticality Matrix

| Asset Category | Confidentiality | Integrity | Availability | Overall Criticality | Justification |
|---|---|---|---|---|---|
| EHR System | Critical | Critical | Critical | Critical | The EHR application and database support access to patient histories, diagnoses, allergies, medications and treatment information across MedDefense. Unauthorized disclosure would expose protected health information and create regulatory and legal consequences; unauthorized modification could cause clinicians to make decisions using incorrect records; an outage would force staff to use paper processes, as occurred during the documented nine-hour EHR outage. |
| PACS and Imaging Infrastructure | Critical | Critical | Critical | Critical | The PACS server, MRI control workstation and related imaging systems support diagnosis and treatment decisions. Disclosure would expose identifiable medical images, modification could cause images to be assigned to the wrong patient or interpreted incorrectly, and loss of availability would interrupt Radiology operations, including approximately 45 MRI studies per day. |
| Medical IoT and Patient-Care Devices | High | Critical | Critical | Critical | The category includes approximately 80 patient monitors, 120 network-connected infusion pumps and the nurse call system. Altered readings, dosage settings or device configurations could directly endanger patients, while device outages could prevent monitoring, medication delivery or patient-to-staff communication during clinical care. |
| Identity and Access Management | Critical | Critical | Critical | Critical | The two Active Directory domain controllers authenticate approximately 2,000 employees and support access to clinical, administrative and infrastructure systems. Compromise could expose account and authentication information, allow unauthorized privilege changes and prevent staff from accessing systems across all three MedDefense sites. |
| Network Core and Site Connectivity | High | Critical | Critical | Critical | The FortiGate firewall, Cisco switching infrastructure, wireless access points and site VPNs connect Central Hospital, Westside Clinic and Corporate HQ. Unauthorized configuration changes could redirect or expose traffic, and failure of the core network or VPN services could isolate departments or entire sites from EHR, file, identity and other centrally hosted services. |
| Billing Infrastructure | High | High | High | High | The billing server processes insurance claims and supports the organization's revenue cycle. Its previous ransomware incident prevented claims processing for four days, demonstrating that loss of availability causes significant financial and operational disruption; compromise could also expose or alter patient billing and insurance information. |
| Backup and Recovery Infrastructure | High | Critical | High | Critical | The Veeam server and NAS contain recovery copies of the EHR, billing, Active Directory, file and web systems. Unauthorized access could expose sensitive organizational data, while deletion, encryption or alteration of backups could make recovery impossible after ransomware or system failure; the current copies are stored in the same room and network as production systems. |
| Clinical Endpoints | Critical | Critical | High | Critical | Clinical workstations, thin clients and physician iPads provide access to EHR, imaging and other patient-care services. An unattended or compromised endpoint could expose patient records or allow unauthorized changes to clinical information; widespread endpoint disruption would slow care delivery and force manual workarounds. |
| Administrative Endpoints and Services | High | High | Medium | High | Corporate and administrative endpoints process HR, Finance, Legal, executive and Microsoft 365 information. Compromise could expose employee, financial or legal data and support phishing or lateral movement, but localized outages would generally be recoverable without immediately halting direct patient care. |
| Physical Access and Security Systems | High | High | High | High | Badge readers, visitor controls, guards and cameras protect server rooms, administrative areas and other restricted spaces. Failure or manipulation could allow unauthorized persons to reach infrastructure, steal information, install malicious devices or interrupt systems; the current limited camera and guard coverage increases the consequence of control failure. |

## Top 5 Most Critical Assets

### 1. EHR Application and Database (`ehr-srv-01` and `ehr-db-01`)

The EHR environment is the most critical asset because it supports clinical decision-making across MedDefense. Physicians and nurses depend on it for patient histories, allergies, medications and treatment information. Loss of integrity could lead to incorrect treatment, loss of confidentiality would expose protected health information, and loss of availability would force hospital-wide manual procedures, as demonstrated by the previous nine-hour outage.

### 2. Active Directory Domain Controllers (`ad-dc-01` and `ad-dc-02`)

Active Directory is the central identity service for approximately 2,000 employees and multiple connected systems. A compromise could allow an attacker to create privileged accounts, reset passwords, impersonate staff and gain access to clinical and administrative services. An outage could prevent users from authenticating and produce organization-wide disruption across Central Hospital, Westside Clinic and Corporate HQ.

### 3. Medical IoT and Patient-Care Devices

The connected patient monitors, infusion pumps and nurse call systems directly support patient treatment and observation. Incorrect readings, unauthorized dosage changes or unavailable devices could create immediate patient-safety consequences. Their exposure is increased because they are reachable from the same flat network as workstations and servers.

### 4. PACS and Medical Imaging Environment

The PACS server and imaging systems are essential to diagnosis and treatment. MedDefense processes approximately 45 MRI studies each day, so prolonged downtime would delay patient care and create scheduling backlogs. Compromise of image integrity could cause clinicians to rely on altered, incomplete or incorrectly associated diagnostic information.

### 5. Network Core and FortiGate Firewall

The core network and FortiGate provide connectivity between users, servers, medical devices and all three sites. A failure or unauthorized configuration change could interrupt access to EHR, PACS, Active Directory, billing and other central services at the same time. Because the environment lacks effective segmentation, compromise of the network core could also enable broad lateral movement across clinical, administrative and medical-device systems.
