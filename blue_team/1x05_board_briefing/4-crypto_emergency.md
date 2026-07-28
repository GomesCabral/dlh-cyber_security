# 4. The Crypto Emergency

## Goal

Identify the cryptographic weaknesses exploited by the Crimson Tide ransomware campaign and prioritise the cryptographic remediations previously developed during Project 1x04.

---

# Part 1 - Crypto Attack Surface Mapping

| Phase | Crypto Weakness (1x04) | What Crimson Tide Exploits | Recommended Crypto Fix | Emergency Timeline |
|---|---|---|---|---|
| **Phase 3 – Lateral Movement** | RC4 and DES still enabled for Kerberos; weak key management (T14) | RC4 Kerberoasting allows attackers to crack service tickets offline and obtain privileged credentials. | Disable RC4 and DES, enable AES-only Kerberos, rotate service account passwords, review privileged accounts. | **36–72 hours** (maintenance window required). |
| **Phase 4 – Data Exfiltration** | Patient database (`ehr-db-01`) has **no encryption at rest** (T13, T15). | After obtaining filesystem or Domain Admin access, attackers copy raw PostgreSQL files because they are stored in plaintext. | Encrypt the database at rest using AES-256 with database or volume encryption and protect the encryption key using the T14 key-management design. | **Begin within 72 hours**; full deployment requires planning. |
| **Phase 5 – Backup Destruction** | NAS-01 backups are unencrypted and stored on the production network (T12, T15). | Attackers can verify backup contents, steal sensitive information and destroy backups before deploying ransomware. | Encrypt NAS-01 using LUKS, isolate backups, implement immutable off-site encrypted copies, store keys **NOT on the NAS**. | **Isolation tonight (0–12h)**; encryption and migration **36–72h**. |
| **Phase 6 – Ransomware Deployment** | Weak certificate, identity and key-management practices increase administrative compromise (T10, T14). | Stolen privileged credentials allow trusted deployment mechanisms such as GPO. | Strengthen key management, rotate privileged credentials, protect private keys with TPM/HSM where appropriate, enforce MFA. | **12–72 hours**. |
| **Phase 7 – Extortion** | Sensitive information exists in plaintext after exfiltration because encryption at rest is absent (T15). | Attackers threaten to publish readable patient and financial records. | Encrypt regulated data at rest, classify sensitive information, protect keys separately and minimise plaintext copies. | **Begin immediately; complete as Phase 1 project.** |

---

# Part 2 - Updated Encryption Priority List

| Updated Priority | Cryptographic Action | Previous Position | Reason for Change |
|---|---|---:|---|
| **1** | Encrypt NAS-01 backups and isolate them from the production network. | 2 | The advisory shows backup destruction occurred in every observed incident. Preserving recovery capability becomes the highest priority. |
| **2** | Encrypt the PostgreSQL patient database (`ehr-db-01`) at rest. | 1 | Patient data was successfully stolen because databases were stored in plaintext. Encryption directly reduces confidentiality impact. |
| **3** | Implement enterprise key management (TPM/HSM/KMS) from T14. | 4 | Encryption is only effective if encryption keys are stored separately and protected correctly. |
| **4** | Harden TLS and certificate lifecycle management. | 3 | Important for protecting communications, but less urgent than protecting stored patient data and backups against the current campaign. |
| **5** | Continue organisation-wide data classification and cryptographic governance. | 5 | Long-term governance remains essential but has less immediate impact on the active Crimson Tide campaign. |

### Why the Priorities Changed

The advisory demonstrates that Crimson Tide gains the greatest benefit from **unencrypted databases** and **unencrypted backups**. These weaknesses therefore become the first remediation priorities because they directly reduce the attacker's ability to steal readable patient information and permanently destroy recovery data.

---

# Part 3 - The "What If" Calculation

## Scenario

Assume:

- `ehr-db-01` uses AES-256 encryption at rest.
- The attacker has obtained Domain Administrator privileges.
- The database encryption key is stored on the **same server**.

## What Changes?

Encryption at rest would **prevent attackers from simply copying raw PostgreSQL files from disk** and reading them offline without the key. The copied files would remain encrypted.

However, because the attacker already has Domain Administrator privileges and the encryption key is stored on the same server, the attacker could potentially recover the key from memory, configuration files, the operating system key store, or the running database service.

Once the encryption key is recovered, the attacker can decrypt the database or simply access the running database through authorised software.

## Would the Data Still Be Exfiltrable?

**Yes, but under stricter conditions.**

The attacker would first need to compromise the key-management process instead of merely copying database files. Encryption therefore increases attacker effort, creates additional detection opportunities and protects against offline theft of storage media, but it does **not** fully protect a system that has already been completely compromised.

## Best Practice

To maximise protection:

- encrypt the database with AES-256;
- store encryption keys **NOT on the database server**;
- protect keys using an HSM, TPM or enterprise KMS;
- enforce least privilege and MFA for administrators;
- monitor key usage and rotation;
- isolate database servers from general administrative networks.

With proper key separation, even a stolen database file cannot be decrypted without access to the external key-management system.

---

# Final Conclusion

The Crimson Tide advisory validates the conclusions reached during Project 1x04. The most critical weaknesses are **unencrypted patient databases**, **unencrypted backups**, and **poor key management**. Accelerating these cryptographic controls within the first 72 hours significantly reduces the confidentiality impact of ransomware, limits the value of stolen data and improves MedDefense's ability to recover from an attack without paying a ransom.

