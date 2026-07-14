# Threat Scenarios

---

# Scenario 1 – BlackReef Ransomware Attack

**Threat Actor:** Organized Crime (BlackReef RaaS)

**Motivation:** Financial Gain

**Initial Vector:** Spear Phishing Email

**Attack Surface Exploited:** Human + External

## Attack Sequence

**Step 1:** Spear phishing email sent to the IT Director. *(ATT&CK: Initial Access)*

**Step 2:** Malware installs a backdoor on the workstation. *(ATT&CK: Persistence)*

**Step 3:** Credentials are stolen with Mimikatz and the attacker gains Domain Admin privileges. *(ATT&CK: Credential Access / Privilege Escalation)*

**Step 4:** The attacker moves through the flat network, reaches the EHR, billing server and backup server, and exfiltrates patient data. *(ATT&CK: Lateral Movement / Collection / Exfiltration)*

**Step 5:** Backups are deleted and ransomware encrypts all Windows systems. *(ATT&CK: Impact)*

## STRIDE Categories Triggered

- Spoofing
- Information Disclosure
- Denial of Service
- Elevation of Privilege

## MedDefense Assets Impacted

- Active Directory
- EHR System
- Billing Server
- Backup Server
- NAS-01
- Clinical Workstations

## Business Impact

- Clinical operations interrupted.
- Patient records encrypted and stolen.
- Ambulances diverted.
- HIPAA investigation.
- Financial losses exceeding several million dollars.

## Gaps Exploited

- **GAP-004:** Flat Network enables lateral movement.
- **GAP-007:** No centralized monitoring delays detection.
- **GAP-011:** No MFA allows credential abuse.
- **GAP-002:** Backups are not isolated.

## Detection Opportunities

- Detect phishing email with email security.
- Detect credential dumping using EDR.
- Detect unusual lateral movement using SIEM.
- Detect large data transfers using DLP.

---

# Scenario 2 – Malicious Insider Data Theft

**Threat Actor:** Malicious Insider

**Motivation:** Financial Gain

**Initial Vector:** Legitimate User Access

**Attack Surface Exploited:** Human + Internal

## Attack Sequence

**Step 1:** Billing employee decides to steal patient records before leaving the company. *(ATT&CK: Reconnaissance)*

**Step 2:** The employee exports large amounts of patient data from the EHR. *(ATT&CK: Collection)*

**Step 3:** Data is copied to a personal USB drive. *(ATT&CK: Collection)*

**Step 4:** Local files are deleted to hide activity. *(ATT&CK: Defense Evasion)*

**Step 5:** After leaving the company, the employee connects through the still-active VPN account and downloads additional billing records. *(ATT&CK: Persistence / Exfiltration)*

## STRIDE Categories Triggered

- Repudiation
- Information Disclosure
- Elevation of Privilege

## MedDefense Assets Impacted

- EHR System
- Billing Server
- Active Directory

## Business Impact

- Exposure of restricted patient information.
- Regulatory penalties.
- Identity theft risk.
- Reputational damage.

## Gaps Exploited

- **GAP-011:** No automated account deactivation.
- **GAP-013:** No Data Loss Prevention.
- **GAP-007:** Logs are not reviewed.
- **GAP-005:** Weak access management.

## Detection Opportunities

- Detect abnormal record exports.
- Alert on USB storage usage.
- Alert on VPN access after employee termination.
- Monitor unusual login hours.

---

# Scenario 3 – Supply Chain Compromise

**Threat Actor:** External Attacker through Third-Party Vendor

**Motivation:** Financial Gain

**Initial Vector:** Compromised Vendor Remote Access

**Attack Surface Exploited:** External + Third Party

## Attack Sequence

**Step 1:** Attackers compromise the MedTech Solutions maintenance environment. *(ATT&CK: Initial Access)*

**Step 2:** They authenticate using the vendor's legitimate maintenance account. *(ATT&CK: Valid Accounts)*

**Step 3:** The attackers access the EHR maintenance server and install malware. *(ATT&CK: Execution / Persistence)*

**Step 4:** They move through the flat network to the database and backup servers. *(ATT&CK: Lateral Movement)*

**Step 5:** Patient data is stolen and ransomware is deployed. *(ATT&CK: Exfiltration / Impact)*

## STRIDE Categories Triggered

- Spoofing
- Tampering
- Information Disclosure
- Denial of Service
- Elevation of Privilege

## MedDefense Assets Impacted

- EHR Server
- EHR Database
- Active Directory
- Backup Infrastructure
- Clinical Workstations

## Business Impact

- EHR unavailable.
- Patient records exposed.
- Hospital services disrupted.
- Regulatory investigation.
- Significant financial loss.

## Gaps Exploited

- **GAP-004:** Flat network.
- **GAP-007:** No SIEM or IDS.
- **GAP-011:** Weak privileged access controls.
- **GAP-014:** Limited third-party access monitoring.

## Detection Opportunities

- Monitor vendor remote sessions.
- Detect unusual administrative activity.
- Detect lateral movement between servers.
- Alert on abnormal database exports.
