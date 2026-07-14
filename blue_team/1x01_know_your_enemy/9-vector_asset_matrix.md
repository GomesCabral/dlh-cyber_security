# Vector-to-Asset Matrix

| Attack Vector | EHR System | EHR Database | Billing Server | Backup Infrastructure | Patient Portal | Medical IoT | Active Directory |
|---------------|------------|--------------|----------------|----------------------|----------------|-------------|------------------|
| **Phishing / Spear Phishing** | Phishing → clinician credentials → EHR access. | Phishing → stolen credentials → flat network → PostgreSQL → patient data. | Phishing → compromised user → lateral movement → billing-srv-01. | Phishing → compromised admin account → backup access. | Phishing → stolen credentials → portal administration. | Phishing → compromised workstation → access to medical device network. | Phishing → privileged credentials → Active Directory compromise. |
| **VPN Exploit** | VPN exploit → internal network → EHR server. | VPN exploit → flat network → PostgreSQL database. | VPN exploit → billing server exploitation. | VPN exploit → access to NAS backups. | VPN exploit → internal web services. | VPN exploit → unrestricted access to medical devices. | VPN exploit → Domain Controller access. |
| **Default / Shared Credentials** | Shared credentials → unauthorized EHR access. | Shared account → database access through compromised systems. | Shared credentials → server administration. | Shared admin credentials → backup management. | | Default credentials → medical device management interface. | Shared admin credentials → privileged access. |
| **Vulnerable Software Exploit** | Exploit vulnerable application → EHR compromise. | Exploit internal server → database access. | Apache 2.4.29 exploit → billing-srv-01 compromise. | Exploit NAS vulnerability → backup compromise. | Web application vulnerability → patient portal compromise. | Exploit outdated firmware → medical device access. | Exploit vulnerable server → privilege escalation. |
| **Supply Chain Compromise** | Compromised MedTech Solutions → EHR access. | Vendor compromise → patient database exposure. | Vendor remote maintenance → billing server compromise. | Compromised backup software → backup access. | Vendor update compromise → portal compromise. | Siemens maintenance compromise → MRI workstation. | Vendor privileged access → Domain Controller. |
| **Insider (Malicious)** | Employee abuses EHR access. | Authorized user exports patient records. | Administrator abuses billing access. | Insider deletes backups. | Employee modifies portal content. | Insider changes device configuration. | Admin abuses privileged accounts. |
| **Insider (Negligent)** | Unattended EHR session abused. | Shared workstation exposes patient data. | Misconfiguration exposes billing server. | Backup process incorrectly configured. | Weak passwords expose portal. | Default credentials remain unchanged. | Failure to disable former employee accounts. |
| **Physical Access** | Unauthorized workstation access → EHR. | Physical server access → database compromise. | Physical access to billing server. | Physical access to NAS. | Server room access → web server. | Physical access to medical devices. | Physical access to Domain Controllers. |

---

# Most Connected Assets

### 1. EHR Database
The EHR Database is reachable through nearly every attack vector because it stores critical patient information and is accessible across the flat network.

### 2. Active Directory
Active Directory provides administrative control over the environment, making it a primary target for attackers seeking privilege escalation.

### 3. EHR System
The EHR System is essential for clinical operations and contains restricted patient information, making it attractive to both external and insider threats.

---

# Most Versatile Vectors

### 1. Phishing / Spear Phishing
Phishing can compromise user credentials that provide access to almost every critical system in MedDefense.

### 2. VPN Exploit
A compromised VPN provides direct access to the internal flat network, enabling rapid lateral movement.

### 3. Insider (Malicious)
Malicious insiders already possess legitimate access, allowing them to reach multiple critical assets without exploiting technical vulnerabilities.
