# 14. Segmentation Architecture – MedDefense Health Systems

## Part 1 – Network Zone Definition

To eliminate the flat network identified during Projects 1x00, 1x01 and 1x02, MedDefense will implement VLAN-based network segmentation with firewall enforcement between all security zones. Each zone follows the principle of least privilege, allowing only the communications required for business operations.

| Zone | VLAN | IP Range | Systems Included | Allowed Outbound Connections | Allowed Inbound Connections |
|------|------|----------------|-------------------------------|--------------------------------------|--------------------------------------|
| **Server Zone** | VLAN 10 | 10.10.10.0/24 | EHR Server, Billing Server, Active Directory, File Server, Database Servers | DNS, NTP, Backup Repository | HTTPS from Clinical Workstations, LDAP/Kerberos from Management, Backup traffic |
| **Clinical Workstation Zone** | VLAN 20 | 10.10.20.0/24 | Nurse Stations, Physician PCs, Reception Computers | HTTPS to EHR, DNS, Email | Security updates from Management, Domain Services |
| **Medical Device Zone** | VLAN 30 | 10.10.30.0/24 | MRI, PACS, Infusion Pumps, Patient Monitors, Imaging Equipment | PACS Server, NTP | Management traffic only from IT Management Zone |
| **Management Zone** | VLAN 40 | 10.10.40.0/24 | IT Administrator PCs, Wazuh Server, Patch Management Server, Monitoring Systems | Administrative access to all managed systems | VPN access for authorized administrators only |
| **Guest / IoT Zone** | VLAN 50 | 10.10.50.0/24 | Guest Wi-Fi, Smart TVs, Printers, Cafeteria Devices, BYOD Devices | Internet only | None |
| **DMZ / Perimeter Zone** | VLAN 60 | 10.10.60.0/24 | VPN Gateway, Public Web Portal, Reverse Proxy | Internet | HTTPS from Internet only |

---

## Part 2 – Firewall Rules

| Rule | Source | Destination | Port / Protocol | Action | Purpose |
|------|-------------|----------------|----------------|---------|---------|
| 1 | Clinical Workstations | EHR Server | TCP 443 | ALLOW | Allow secure access to patient records. |
| 2 | Clinical Workstations | Billing Server | TCP 443 | ALLOW | Allow billing application access. |
| 3 | Management Zone | All Internal Zones | SSH, RDP, WinRM | ALLOW | Permit authorized administration only. |
| 4 | Medical Devices | PACS Server | DICOM (104), HTTPS | ALLOW | Medical imaging communications. |
| 5 | Server Zone | Backup Repository | Backup Ports | ALLOW | Backup and recovery operations. |
| 6 | Guest / IoT Zone | Internet | HTTP/HTTPS | ALLOW | Internet access only. |
| 7 | Guest / IoT Zone | Internal Network | ANY | **DENY** | Prevent visitors and IoT devices from reaching internal systems. |
| 8 | Medical Device Zone | Clinical Workstations | ANY | **DENY** | Prevent compromised medical devices from attacking workstations. |
| 9 | Clinical Workstations | Active Directory | ANY except LDAP/Kerberos/DNS | **DENY** | Block unnecessary lateral movement toward identity infrastructure. |
| 10 | Internet | Internal Network | ANY | **DENY** | Prevent direct Internet access to internal assets. Only the DMZ is exposed. |

### Deny Rule Explanations

**Rule 7 – Guest/IoT → Internal Network (DENY)**

Prevents visitors or compromised IoT devices from accessing clinical systems, servers or medical devices.

**Rule 8 – Medical Devices → Clinical Workstations (DENY)**

Prevents compromised medical equipment from spreading malware to user endpoints.

**Rule 9 – Clinical Workstations → Active Directory (DENY except required services)**

Stops attackers who compromise a workstation from directly targeting Domain Controllers and performing credential theft or privilege escalation.

**Rule 10 – Internet → Internal Network (DENY)**

Ensures Internet users cannot directly reach internal servers. External access is restricted to the VPN Gateway and public-facing services in the DMZ.

---

# Part 3 – Kill Chain Impact

## Kill Chain #1 – BlackReef Ransomware Attack

### Step 1 – Initial Access

The attacker compromises VPN credentials or exploits a FortiGate vulnerability.

**Impact of Segmentation**

The VPN terminates inside the DMZ and authenticated users are granted access only to authorized VLANs rather than the entire network.

**Result**

The attacker no longer gains unrestricted internal access.

---

### Step 2 – Credential Theft

The attacker attempts to access Active Directory to obtain privileged credentials.

**Impact of Segmentation**

Firewall Rule 9 restricts workstation access to Active Directory, allowing only required authentication protocols.

**Result**

Credential dumping and privilege escalation become significantly more difficult.

---

### Step 3 – Lateral Movement

The attacker attempts to spread ransomware across servers, workstations and medical devices.

**Impact of Segmentation**

Each VLAN is isolated.

Medical devices cannot communicate with workstations.

Guest devices cannot reach internal systems.

Administrative access is restricted to the Management Zone.

**Result**

The ransomware cannot freely propagate across the environment.

---

### Step 4 – Encryption of Critical Servers

The attacker attempts to encrypt EHR, Billing and File Servers.

**Impact of Segmentation**

Only authorized application traffic is permitted.

Administrative access requires privileged accounts from the Management Zone.

Immutable backups remain isolated.

**Result**

Even if one server is compromised, encryption of the entire infrastructure becomes much more difficult.

---

### Step 5 – Business Disruption

The attacker attempts to impact patient care by compromising medical devices.

**Impact of Segmentation**

Medical devices are isolated in their own VLAN and cannot be reached from compromised user workstations.

**Result**

Clinical operations continue even if user endpoints are compromised.

---

# Overall Kill Chain Impact

| Kill Chain | Segmentation Impact |
|------------|--------------------|
| Kill Chain #1 – Ransomware | Strongly Disrupted |
| Kill Chain #2 – VPN Compromise | Strongly Disrupted |
| Kill Chain #3 – Insider Data Theft | Partially Disrupted |
| Kill Chain #4 – Medical Device Attack | Strongly Disrupted |
| Kill Chain #5 – Lateral Movement after Phishing | Strongly Disrupted |

---

## Estimated Effectiveness

Implementing this segmentation architecture is expected to disrupt approximately **80%** of MedDefense's highest-priority attack paths identified during Project **1x01**.

The greatest security improvements include:

- Elimination of unrestricted lateral movement.
- Isolation of critical healthcare systems.
- Protection of Active Directory.
- Separation of medical devices from user workstations.
- Containment of ransomware outbreaks.
- Reduced attack surface for Internet-facing systems.
- Improved compliance with **NIST CSF (PR.AC, PR.PS)** and **CIS Controls 12 (Network Infrastructure Management)**.
