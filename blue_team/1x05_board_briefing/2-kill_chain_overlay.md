# 2. The Kill Chain Overlay

## Goal

Overlay MedDefense Kill Chain #1 from Project 1x01 against the observed Crimson Tide seven-phase attack chain, identify where the two models converge or diverge, and determine where the controls planned in the 1x03 Security Strategy would intercept the attack.

---

# Part 1 - The Overlay

## MedDefense Kill Chain #1

The ransomware kill chain developed in 1x01 follows this sequence:

```text
1. Initial Access
2. Execution
3. Credential Access
4. Discovery
5. Lateral Movement
6. Privilege Escalation
7. Backup Compromise
8. Data Exfiltration
9. Ransomware Deployment
10. Operational Impact
```

## Crimson Tide Attack Chain

The observed Crimson Tide attack chain follows this sequence:

```text
1. Initial Access
2. Internal Reconnaissance
3. Lateral Movement
4. Data Exfiltration
5. Backup Destruction
6. Ransomware Deployment
7. Extortion
```

---

## Step-by-Step Overlay

| MedDefense Kill Chain #1 Step | Crimson Tide Phase | Match? | Where the Prediction Was Accurate | What Crimson Tide Added or Changed |
|---|---|---:|---|---|
| 1. Initial Access | Phase 1 — Initial Access | **Yes** | The model correctly predicted that ransomware begins with an external foothold. | The original model focused mainly on phishing or stolen credentials, while Crimson Tide used unauthenticated exploitation of the FortiGate SSL-VPN through CVE-2023-27997. |
| 2. Execution | Phase 1 — Initial Access | **Partial** | The model correctly predicted attacker-controlled code execution early in the chain. | Crimson Tide executes code directly on the perimeter firewall instead of first executing malware on a workstation. |
| 3. Credential Access | Phase 2 — Internal Reconnaissance | **Yes** | The model correctly predicted credential theft before broad lateral movement. | Crimson Tide specifically captures VPN credentials from FortiGate memory and later uses Mimikatz and Kerberoasting. The original model did not explicitly predict credential recovery from a network appliance. |
| 4. Discovery | Phase 2 — Internal Reconnaissance | **Yes** | The model predicted internal scanning and identification of servers, domain controllers, databases, backups, and medical systems. | Crimson Tide uses the FortiGate routing table and built-in FortiOS CLI, allowing faster and more authoritative network mapping than normal endpoint scanning. |
| 5. Lateral Movement | Phase 3 — Lateral Movement | **Yes** | The model accurately predicted RDP, SMB, SSH, remote administration, and movement through a flat network. | Crimson Tide specifically combines RDP, SSH, WMI, Kerberoasting, and cached credential theft. |
| 6. Privilege Escalation | Phase 3 — Lateral Movement | **Partial** | The model correctly predicted that the attacker would seek administrative control and access to Domain Controllers. | Crimson Tide often obtains already privileged VPN or service-account credentials, so traditional local privilege escalation may be less important than privilege abuse and Kerberoasting. |
| 7. Backup Compromise | Phase 5 — Backup Destruction | **Yes** | The model accurately predicted that ransomware operators would attack backups before encryption. | Crimson Tide verifies plaintext backup value, deletes Volume Shadow Copies, and destroys backup software catalogues in addition to attacking NAS/SAN storage. |
| 8. Data Exfiltration | Phase 4 — Data Exfiltration | **Yes** | The model correctly predicted collection and theft of EHR, billing, employee, and imaging data before ransomware deployment. | Crimson Tide uses Rclone and attacker-controlled cloud storage, with a measured volume of 15–65 GB per incident. The original model may not have specified a legitimate cloud-transfer tool. |
| 9. Ransomware Deployment | Phase 6 — Ransomware Deployment | **Yes** | The model accurately predicted enterprise-wide ransomware deployment after privilege and backup compromise. | Crimson Tide uses a compromised Domain Controller and GPO for Windows deployment and separately targets Linux servers over SSH. |
| 10. Operational Impact | Phase 6 and Phase 7 — Ransomware Deployment and Extortion | **Yes** | The model predicted disruption of EHR, billing, imaging, workstations, and clinical operations. | Crimson Tide adds double extortion, direct executive contact, public data-leak threats, a 96-hour payment deadline, ambulance diversion, and prolonged paper-based operations. |

---

## Where the Model Was Accurate

The 1x01 ransomware model accurately predicted the core operational structure of the real attack:

1. obtain an initial foothold;
2. execute attacker-controlled actions;
3. steal credentials;
4. discover the environment;
5. move laterally;
6. gain administrative control;
7. destroy recovery capability;
8. steal high-value data;
9. deploy ransomware;
10. create enterprise and clinical impact.

The strongest predictions were:

- the importance of the flat network;
- credential theft before lateral movement;
- access to Domain Controllers;
- deliberate backup compromise;
- exfiltration before encryption;
- enterprise-wide ransomware impact;
- disruption of clinical systems through unavailable backend services.

---

## Where the Model Diverged

The original kill chain did not fully anticipate the following Crimson Tide techniques:

### 1. Firewall Exploitation as the Initial Foothold

The model assumed a more traditional endpoint entry method such as phishing or stolen credentials. Crimson Tide instead compromises the FortiGate itself before authentication.

### 2. Credential Recovery from a VPN Appliance

The attacker captures VPN authentication material directly from FortiGate memory. This is different from stealing browser, workstation, or Active Directory credentials first.

### 3. Routing-Table-Based Discovery

The compromised firewall already knows the internal routes. This gives the attacker an accurate network map without depending entirely on noisy network scans.

### 4. Privilege Abuse Instead of Only Privilege Escalation

Crimson Tide often begins lateral movement with VPN service accounts or domain accounts that already have excessive privileges. The attack may therefore skip a traditional exploit-based privilege escalation step.

### 5. Rclone and Legitimate Cloud Storage

The attack uses a legitimate data-transfer utility and a legitimate cloud service, which may bypass controls focused only on known malicious tools and destinations.

### 6. GPO-Based Enterprise Deployment

The original model predicted ransomware deployment, but Crimson Tide's use of Group Policy provides a particularly efficient trusted distribution mechanism.

### 7. Direct Executive and Public Extortion

The original model focused on operational impact. Crimson Tide adds direct contact with the CEO and CFO, Tor leak-site publication, telephone calls, and a time-limited double-extortion process.

---

## Overlay Conclusion

The 1x01 kill chain was highly accurate at the strategic level. It predicted all major attacker objectives and most operational stages.

The main differences were not failures of the model's overall logic. They were differences in:

- the exact initial-access technology;
- the source of stolen credentials;
- the discovery method;
- the balance between privilege escalation and privilege abuse;
- the exfiltration tool;
- the ransomware distribution method;
- the pressure tactics used after deployment.

The original threat modelling therefore predicted the attack well, but Crimson Tide demonstrates why kill chains must be continuously updated with current threat intelligence.

---

# Part 2 - Control Interception Map

## Status Definitions

- **Deployed:** The control is currently operating in production.
- **Funded / Not Deployed:** The control was approved in the 1x03 budget but has not yet been implemented.
- **Not Funded:** The control was deferred or excluded from the current budget.

The 1x03 funded controls were:

- MFA Deployment;
- Enterprise SIEM using Wazuh;
- Offsite Immutable Backups;
- Network Segmentation;
- Dedicated Firewall for Westside Clinic.

The following were deferred or not funded:

- Enterprise EDR upgrade;
- dedicated medical-device network isolation;
- 24/7 Managed SOC.

---

## Phase-by-Phase Interception

| Phase | Planned Control from 1x03 | Status | Would It Stop This Phase? |
|---|---|---|---|
| **1 — Initial Access** | Critical patch and vulnerability management for internet-facing systems | Existing process, but ineffective in this case | **Yes**, if CVE-2023-27997 had been patched before exploitation |
| **1 — Initial Access** | MFA on VPN and remote access | **Funded / Not Deployed** | **No** for CVE-2023-27997 because it is pre-authentication; **Yes** against later use of stolen VPN credentials |
| **1 — Initial Access** | Enterprise SIEM and FortiGate log ingestion | **Funded / Not Deployed** | **No**, but it could detect exploitation attempts or suspicious appliance activity |
| **2 — Internal Reconnaissance** | Network segmentation | **Funded / Not Deployed** | **Partially**; the attacker could still inspect routes, but access between zones would be restricted |
| **2 — Internal Reconnaissance** | Enterprise SIEM | **Funded / Not Deployed** | **Partially**; unusual CLI commands, VPN sessions, and internal authentication anomalies could be detected |
| **2 — Internal Reconnaissance** | MFA | **Funded / Not Deployed** | **Partially**; stolen passwords alone would be less useful, although active session tokens or privileged appliance control could still create risk |
| **3 — Lateral Movement** | Network segmentation | **Funded / Not Deployed** | **Yes** for most direct movement paths; workstation, server, backup, medical, and management zones would be separated |
| **3 — Lateral Movement** | MFA for administrative accounts | **Funded / Not Deployed** | **Partially**; it would reduce credential reuse but would not stop every Kerberos, service-account, or token-based attack |
| **3 — Lateral Movement** | Disable RC4 and DES; use AES-only Kerberos | Planned hardening, not confirmed funded or deployed | **Partially**; it would greatly reduce Kerberoasting efficiency but would not eliminate lateral movement using valid credentials |
| **3 — Lateral Movement** | EDR upgrade | **Not Funded** | **Partially**; it could detect Mimikatz, suspicious RDP/WMI, credential dumping, and remote execution |
| **3 — Lateral Movement** | Privileged-access and service-account review | Planned, not fully deployed | **Partially**; it would reduce the reach of stolen accounts |
| **4 — Data Exfiltration** | Database encryption at rest | Designed in 1x04, not deployed | **Partially**; raw copied files would be protected, but authorised applications or stolen keys could still expose data |
| **4 — Data Exfiltration** | Enterprise SIEM and large-transfer alerting | **Funded / Not Deployed** | **Partially**; it could detect Rclone, Mega access, and transfers larger than 5 GB |
| **4 — Data Exfiltration** | Network segmentation | **Funded / Not Deployed** | **Partially**; it would restrict direct access to databases and PACS storage |
| **4 — Data Exfiltration** | DLP and egress filtering | Not confirmed funded | **Partially**; it could block unauthorised cloud storage and high-volume transfers |
| **5 — Backup Destruction** | Offsite immutable backups | **Funded / Not Deployed** | **Yes** for preserving a recoverable copy, although local backups might still be destroyed |
| **5 — Backup Destruction** | Backup Zone through network segmentation | **Funded / Not Deployed** | **Yes** for most production-to-backup attack paths |
| **5 — Backup Destruction** | Separate backup credentials and MFA | Planned, not fully deployed | **Partially**; it would reduce credential reuse and unauthorised administration |
| **5 — Backup Destruction** | Backup encryption | Designed in 1x04, not deployed | **No** for deletion; it protects confidentiality, not availability |
| **6 — Ransomware Deployment** | Network segmentation | **Funded / Not Deployed** | **Partially/Yes**; it would prevent or greatly reduce enterprise-wide spread across zones |
| **6 — Ransomware Deployment** | Enterprise SIEM with GPO monitoring | **Funded / Not Deployed** | **Partially**; it could detect new GPO creation but may not stop it automatically |
| **6 — Ransomware Deployment** | EDR upgrade | **Not Funded** | **Partially/Yes**; behavioural prevention could block the payload on many endpoints |
| **6 — Ransomware Deployment** | Application allowlisting | Not confirmed funded | **Partially/Yes**; it could prevent unknown ransomware binaries from executing |
| **6 — Ransomware Deployment** | Least privilege and restricted Domain Admin use | Planned, not fully deployed | **Partially**; it would make GPO compromise more difficult |
| **7 — Extortion** | Offsite immutable backups | **Funded / Not Deployed** | **Partially**; it would reduce dependence on the attacker's decryption key |
| **7 — Extortion** | Database and backup encryption | Designed, not deployed | **Partially**; it could reduce the value of copied raw files if keys remained protected |
| **7 — Extortion** | Incident response and crisis communication plan | Planned, not fully tested | **No** prevention, but it would improve legal, clinical, executive, and public response |
| **7 — Extortion** | 24/7 Managed SOC | **Not Funded** | **No** at this late phase; earlier detection might have prevented arrival at extortion |

---

## Primary Interception Points

The strongest planned interception points are:

### Phase 1 — Patch Management

Patching or disabling the vulnerable SSL-VPN would prevent the observed initial-access method entirely.

### Phase 3 — Network Segmentation

Segmentation is the most important architectural break point. It would prevent direct movement from the perimeter or a compromised workstation to every server, database, backup device, and medical system.

### Phase 5 — Isolated Immutable Backups

Even if production systems were compromised, an attacker would be unable to destroy every recovery copy.

### Phase 6 — EDR and Restricted GPO Administration

EDR, application control, and protected Domain Controller administration would reduce or prevent mass ransomware execution.

### Phase 4 — Encryption and Egress Monitoring

Encryption at rest would protect copied raw files, while SIEM and DLP controls would identify or block unusual data transfers.

---

# Part 3 - The Gap Between Plan and Reality

If MedDefense had fully implemented the complete 1x03 Security Strategy, the most defensible assessment is that **four of the seven Crimson Tide phases would have been blocked or prevented from completing successfully**, while **three phases could still occur in some form**. Initial access would be blocked if the vulnerability-management process patched the FortiGate, lateral movement would be largely broken by segmentation and stronger identity controls, backup destruction would fail against isolated immutable copies, and enterprise-wide ransomware deployment would be prevented or heavily contained by segmentation, EDR, application control, and restricted administrative privileges. Internal reconnaissance might still occur after a successful foothold, attempted data exfiltration might still occur through an authorised or compromised application path, and extortion could still be attempted if any data were stolen. This demonstrates that full strategy implementation would reduce the probability and blast radius of the attack dramatically, but would not reduce residual risk to zero. Security controls must be layered because patching can fail, credentials can still be stolen, trusted applications can be abused, and no prevention architecture can guarantee that every intrusion or extortion attempt will be stopped.

---

# Residual Risk Summary

| Outcome After Full Strategy Implementation | Estimated Result |
|---|---:|
| Phases blocked or prevented from completing | **4/7** |
| Phases that could still occur partially | **3/7** |
| Enterprise-wide ransomware event | **Unlikely** |
| Localised compromise | **Still possible** |
| Data exfiltration through a trusted path | **Still possible** |
| Complete backup loss | **Unlikely** |
| Zero residual risk | **Not achievable** |

---

# Final Conclusion

The Crimson Tide campaign validates the strategic accuracy of MedDefense's 1x01 threat modelling. The original ransomware kill chain anticipated nearly every important attacker objective.

The principal failure is not the quality of the plan. It is the implementation gap between approved controls and production reality.

MedDefense had already identified the controls most capable of disrupting this attack:

- patching;
- MFA;
- segmentation;
- SIEM;
- immutable backups;
- EDR;
- least privilege;
- encryption at rest.

However, several of the highest-value controls are funded but not deployed, while others remain unfunded. The attack therefore shows that a documented security strategy does not reduce risk until the controls are implemented, validated, monitored, and maintained.


