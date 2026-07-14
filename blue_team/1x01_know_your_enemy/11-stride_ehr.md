# STRIDE Analysis – MedDefense EHR System

---

## Category: S (Spoofing)

**Threat ID:** EHR-S1

**Description:** An attacker steals a clinician's credentials through phishing and logs into the EHR as a legitimate user.

**Attack Vector:** Phishing / Stolen Credentials.

**Impact:** Unauthorized access to patient medical records.

**Existing Control:** C-007 Password Policy.

**Gap:** GAP-011 – No MFA.

---

**Threat ID:** EHR-S2

**Description:** A former employee continues using an account that was never disabled.

**Attack Vector:** Ghost Account.

**Impact:** Unauthorized access to clinical information.

**Existing Control:** C-007 Password Policy.

**Gap:** GAP-011 – No Automated Account Lifecycle Management.

---

## Category: T (Tampering)

**Threat ID:** EHR-T1

**Description:** An attacker modifies patient diagnoses or medication records.

**Attack Vector:** Compromised user credentials.

**Impact:** Incorrect clinical treatment and patient safety risk.

**Existing Control:** Access Control Policy.

**Gap:** GAP-007 – Limited Monitoring.

---

**Threat ID:** EHR-T2

**Description:** Malware alters application files on ehr-srv-01.

**Attack Vector:** Vulnerable Software Exploit.

**Impact:** EHR service becomes unreliable.

**Existing Control:** Endpoint Protection.

**Gap:** GAP-003 – Unsupported Systems.

---

## Category: R (Repudiation)

**Threat ID:** EHR-R1

**Description:** A user denies accessing patient records because audit logs are not actively reviewed.

**Attack Vector:** Legitimate Credentials.

**Impact:** Difficult forensic investigation.

**Existing Control:** Local System Logs.

**Gap:** GAP-007 – No Centralized Logging.

---

**Threat ID:** EHR-R2

**Description:** Shared accounts prevent identifying who performed an action.

**Attack Vector:** Shared Credentials.

**Impact:** Loss of accountability.

**Existing Control:** Password Policy.

**Gap:** GAP-005 – Shared Credentials.

---

## Category: I (Information Disclosure)

**Threat ID:** EHR-I1

**Description:** Patient records are stolen after compromising the database.

**Attack Vector:** PostgreSQL exposed on the flat network.

**Impact:** Large-scale PHI breach.

**Existing Control:** Firewall.

**Gap:** GAP-004 – Flat Network.

---

**Threat ID:** EHR-I2

**Description:** An insider exports patient records without detection.

**Attack Vector:** Insider Threat.

**Impact:** HIPAA violation and reputational damage.

**Existing Control:** Access Control Policy.

**Gap:** GAP-013 – No Data Loss Prevention.

---

## Category: D (Denial of Service)

**Threat ID:** EHR-D1

**Description:** Ransomware encrypts the EHR servers.

**Attack Vector:** Phishing followed by lateral movement.

**Impact:** Clinical operations stop.

**Existing Control:** Daily Backups.

**Gap:** GAP-004 – Flat Network.

---

**Threat ID:** EHR-D2

**Description:** Database services are disrupted through network attacks.

**Attack Vector:** Internal Network Access.

**Impact:** Physicians cannot access patient records.

**Existing Control:** Firewall.

**Gap:** GAP-007 – No Intrusion Detection.

---

## Category: E (Elevation of Privilege)

**Threat ID:** EHR-E1

**Description:** An attacker escalates privileges from a workstation to Domain Administrator.

**Attack Vector:** Credential Theft.

**Impact:** Full control of the EHR environment.

**Existing Control:** Password Policy.

**Gap:** GAP-011 – No MFA.

---

**Threat ID:** EHR-E2

**Description:** Exploiting an unpatched server vulnerability provides administrative access to the EHR application.

**Attack Vector:** Vulnerable Software Exploit.

**Impact:** Complete compromise of patient records.

**Existing Control:** Firewall.

**Gap:** GAP-003 – Unsupported Systems.

---

# STRIDE Summary for EHR

The greatest risk for the MedDefense EHR system is **Information Disclosure** because the EHR stores restricted patient medical records and is accessible across a flat network. A successful compromise could expose sensitive health information for thousands of patients, resulting in regulatory penalties, financial losses and damage to patient trust. The lack of network segmentation, centralized monitoring and Data Loss Prevention significantly increases this risk.
