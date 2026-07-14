# ATT&CK Mapping

## Scenario Alpha – Operation Flatline

### Step 1
**Description:** Attacker purchases a list of healthcare organizations with FortiGate VPN appliances.

- **Tactic:** Resource Development
- **Technique:** Acquire Infrastructure (T1583)
- **MedDefense Factor:** MedDefense exposes a FortiGate VPN to the Internet.

---

### Step 2
**Description:** Spear phishing email sent to Sarah Park with a malicious document.

- **Tactic:** Initial Access
- **Technique:** Phishing: Spearphishing Attachment (T1566.001)
- **MedDefense Factor:** No MFA and limited security awareness training.

---

### Step 3
**Description:** Reverse shell connects to the attacker and a scheduled task creates persistence.

- **Tactic:** Persistence
- **Technique:** Scheduled Task/Job (T1053.005)
- **MedDefense Factor:** Endpoints allow scheduled tasks and there is no centralized monitoring.

---

### Step 4
**Description:** Network discovery identifies Active Directory, EHR and servers.

- **Tactic:** Discovery
- **Technique:** Network Service Scanning (T1046)
- **MedDefense Factor:** Flat network with no internal segmentation.

---

### Step 5
**Description:** Mimikatz dumps cached credentials.

- **Tactic:** Credential Access
- **Technique:** OS Credential Dumping (T1003)
- **MedDefense Factor:** Privileged credentials were cached on Sarah's workstation.

---

### Step 6
**Description:** Pass-the-Hash attack against Active Directory.

- **Tactic:** Lateral Movement
- **Technique:** Pass the Hash (T1550.002)
- **MedDefense Factor:** Flat network and lack of privileged access protection.

---

### Step 7
**Description:** Patient database is exported and uploaded to cloud storage.

- **Tactic:** Exfiltration
- **Technique:** Exfiltration Over Web Service (T1567)
- **MedDefense Factor:** No DLP and no SIEM to detect large exports.

---

### Step 8
**Description:** Backups are deleted from NAS and Volume Shadow Copies removed.

- **Tactic:** Impact
- **Technique:** Inhibit System Recovery (T1490)
- **MedDefense Factor:** NAS is on the same network and backups are not isolated.

---

### Step 9
**Description:** Ransomware deployed through Group Policy to all Windows systems.

- **Tactic:** Impact
- **Technique:** Data Encrypted for Impact (T1486)
- **MedDefense Factor:** Domain Admin compromise and flat network.

---

# Scenario Beta – The Quiet Departure

### Step 1
**Description:** Employee decides to steal patient data before leaving.

- **Tactic:** Reconnaissance
- **Technique:** Gather Victim Identity Information (T1589)
- **MedDefense Factor:** Employee already has legitimate access.

---

### Step 2
**Description:** Employee identifies accessible patient data.

- **Tactic:** Discovery
- **Technique:** File and Directory Discovery (T1083)
- **MedDefense Factor:** Excessive read permissions and no access restrictions.

---

### Step 3
**Description:** Patient records exported from the EHR.

- **Tactic:** Collection
- **Technique:** Data from Information Repositories (T1213)
- **MedDefense Factor:** No monitoring of large exports and no DLP.

---

### Step 4
**Description:** Files copied to a USB drive.

- **Tactic:** Collection
- **Technique:** Data from Local System (T1005)
- **Alternative:** Peripheral Device Discovery (T1120)
- **MedDefense Factor:** USB devices are unrestricted.

---

### Step 5
**Description:** CSV files deleted to hide activity.

- **Tactic:** Defense Evasion
- **Technique:** File Deletion (T1070.004)
- **MedDefense Factor:** Audit logs are never reviewed proactively.

---

### Step 6
**Description:** Database credentials copied from a configuration file.

- **Tactic:** Credential Access
- **Technique:** Credentials from Password Stores (T1555)
- **MedDefense Factor:** Credentials stored in plaintext.

---

### Step 7
**Description:** VPN account remains active after termination.

- **Tactic:** Persistence
- **Technique:** Valid Accounts (T1078)
- **MedDefense Factor:** No automated account deactivation.

---

### Step 8
**Description:** Former employee connects through VPN and extracts more records.

- **Tactic:** Exfiltration
- **Technique:** Exfiltration Over C2 Channel (T1041)
- **Alternative:** Exfiltration Over Web Service (T1567)
- **MedDefense Factor:** Active VPN account, no MFA and no monitoring.

---

# ATT&CK Coverage Assessment

Both scenarios include the **Discovery**, **Credential Access**, **Persistence**, **Collection**, **Exfiltration** and **Impact** tactics. This shows that MedDefense's biggest weakness is not only preventing attacks, but detecting attackers after they gain initial access. The organization urgently needs centralized logging, SIEM, MFA, network segmentation and monitoring to detect credential theft, lateral movement and data exfiltration before attackers reach critical systems.
