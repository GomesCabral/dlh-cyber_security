# 0. The Crypto Inventory

## MedDefense Health Systems Data Protection Map

### Purpose

This document maps every major category of data within MedDefense Health Systems against its current cryptographic protection state. It identifies where encryption is adequate, weak, or absent across the three primary data states:

- At Rest
- In Transit
- In Use

This inventory provides the baseline for the cryptographic improvements implemented throughout Project 1x04.

---

## Protection Status Definitions

| Status | Definition |
|---------|------------|
| **Adequate** | Modern cryptographic protection is implemented and correctly configured. |
| **Weak** | Cryptography exists but uses outdated algorithms, optional encryption, or insecure configurations. |
| **Absent** | No meaningful cryptographic protection exists. |

---

# Data Protection Matrix

| Data Category | At Rest | In Transit | In Use |
|---------------|---------|------------|--------|
| **Patient Medical Records (PostgreSQL EHR)** | **Protection:** None.<br><br>**Evidence:** PostgreSQL stores all data on an unencrypted ext4 filesystem. Root access or physical disk theft exposes all patient records in plaintext.<br><br>**Reference:** Crypto Audit Notes – Patient Data.<br><br>**Status:** **Absent** | **Protection:** PostgreSQL SSL enabled but not enforced. Patient Portal supports TLS 1.0 and TLS 1.2.<br><br>**Evidence:** `pg_hba.conf` allows both SSL and non-SSL connections. Finding 005 confirmed TLS 1.0 remains enabled and HSTS is not configured.<br><br>**Status:** **Weak** | **Protection:** None.<br><br>**Evidence:** Patient records are decrypted in application memory and displayed on unlocked nurse workstations. Group Policy screensaver timeout is set to "Never".<br><br>**Status:** **Absent** |
| **Financial / Billing Data (MySQL)** | **Protection:** None.<br><br>**Evidence:** Billing database resides on an unencrypted ext4 filesystem. During the crypto-miner investigation, investigators confirmed database files could be read directly from disk without MySQL credentials.<br><br>**Reference:** 1x00 Incident Review and Crypto Audit Notes.<br><br>**Status:** **Absent** | **Protection:** None.<br><br>**Evidence:** MySQL listens on 0.0.0.0 and does not require SSL. Billing application communicates using plaintext MySQL traffic across the flat network.<br><br>**Status:** **Absent** | **Protection:** None.<br><br>**Evidence:** Financial records are processed in plaintext memory. No application-level encryption or protected processing mechanisms exist.<br><br>**Status:** **Absent** |
| **Medical Images (PACS / DICOM)** | **Protection:** None.<br><br>**Evidence:** PACS stores DICOM files without encryption. Patient identifiers remain readable inside DICOM headers.<br><br>**Status:** **Absent** | **Protection:** None.<br><br>**Evidence:** MRI workstation, radiology workstations and PACS communicate using unencrypted DICOM over TCP ports 4242 and 11112. DICOM TLS is not enabled.<br><br>**Status:** **Absent** | **Protection:** None.<br><br>**Evidence:** Images and patient identifiers remain fully visible while processed by DICOM viewers. No protected viewing environment exists.<br><br>**Status:** **Absent** |
| **Credentials (Active Directory)** | **Protection:** NTHash (MD4). Kerberos supports AES but also RC4 and DES.<br><br>**Evidence:** Finding 018 confirmed RC4 and DES remain enabled for legacy compatibility.<br><br>**Status:** **Weak** | **Protection:** Mixed.<br><br>**Evidence:** Kerberos supports AES-256 but LDAP Signing is disabled (Finding 007). LDAP traffic may therefore be transmitted without integrity protection.<br><br>**Status:** **Weak** |
| **Credentials (Active Directory)** *(continuação)* | **Protection:** NTHash (MD4). Kerberos supports AES but also RC4 and DES.<br><br>**Evidence:** Finding 018 confirmed RC4 and DES remain enabled for legacy compatibility.<br><br>**Status:** **Weak** | **Protection:** Mixed.<br><br>**Evidence:** Kerberos supports AES-256 but LDAP Signing is disabled (Finding 007). LDAP traffic may therefore be transmitted without integrity protection.<br><br>**Status:** **Weak** | **Protection:** None.<br><br>**Evidence:** Credentials and Kerberos tickets are processed in memory during authentication. No credential isolation or protected-memory technology is documented.<br><br>**Status:** **Absent** |
| **Backup Data (NAS-01)** | **Protection:** None.<br><br>**Evidence:** Synology NAS stores backups on an unencrypted RAID-5 volume. Shared Folder Encryption (AES-256-CBC) exists but is not enabled.<br><br>**Status:** **Absent** | **Protection:** None documented.<br><br>**Evidence:** Database dumps are copied across the flat network without encrypted transport being documented.<br><br>**Status:** **Absent** | **Protection:** None.<br><br>**Evidence:** Backup data is readable whenever mounted or restored. Encryption keys are not independently managed.<br><br>**Status:** **Absent** |
| **Email (Microsoft 365)** | **Protection:** BitLocker encryption and Microsoft-managed mailbox encryption.<br><br>**Evidence:** Exchange Online encrypts mailbox storage using Microsoft-managed keys.<br><br>**Status:** **Adequate** | **Protection:** TLS 1.2.<br><br>**Evidence:** Microsoft enforces TLS 1.2 for Exchange Online connections.<br><br>**Status:** **Adequate** | **Protection:** No S/MIME or Microsoft Purview Message Encryption.<br><br>**Evidence:** Physicians sometimes exchange PHI through standard email without end-to-end encryption.<br><br>**Status:** **Weak** |
| **VPN Traffic (Site-to-Site IPsec)** | **Protection:** VPN configuration stored on FortiGate and Netgear router. Endpoint protection is uncertain.<br><br>**Evidence:** Consumer router firmware history is unknown and independent key management is not documented.<br><br>**Status:** **Weak** | **Protection:** IPsec with AES-256, SHA-256, IKEv2 and DH Group 14.<br><br>**Evidence:** Current FortiGate configuration uses modern algorithms. However, one VPN endpoint uses a consumer-grade Netgear router identified during Project 1x00.<br><br>**Status:** **Adequate** | **Protection:** Session keys exist in endpoint memory during active VPN sessions.<br><br>**Evidence:** A compromise of the FortiGate or the Netgear router could expose active VPN sessions regardless of AES-256 strength.<br><br>**Status:** **Weak** |

---

# Gap Summary

## Assessment Results

The inventory contains **21 individual protection assessments**.

```text
7 Data Categories × 3 Data States = 21 Assessment Cells
```

| Protection Status | Cells | Percentage |
|-------------------|------:|-----------:|
| Adequate | 3 | 14.3% |
| Weak | 6 | 28.6% |
| Absent | 12 | 57.1% |
| **Total** | **21** | **100%** |

---

## Overall Cryptographic Coverage

Only **Adequate** protection is considered fully compliant with MedDefense's target security strategy.

```text
Crypto Coverage = Adequate Cells ÷ Total Cells × 100

Crypto Coverage = 3 ÷ 21 × 100

Crypto Coverage = 14.3%
```

If Weak controls are counted as providing partial protection:

```text
Partial Coverage = (Adequate + Weak) ÷ Total Cells × 100

Partial Coverage = 9 ÷ 21 × 100

Partial Coverage = 42.9%
```

However, weak controls still expose MedDefense to significant risk because they rely on:

- Legacy cryptographic algorithms (DES, RC4)
- Optional encryption
- Weak TLS configuration
- Missing message-level encryption
- Poor key management
- Consumer networking equipment

---

# Priority Cryptographic Gaps

Based on the inventory, the following cryptographic weaknesses represent the highest priorities for remediation during Project **1x04 – Cryptographic Foundation**.

## Priority 1 – Encrypt the EHR Database at Rest

- **System:** `ehr-db-01`
- **Issue:** PostgreSQL stores approximately 50,000 patient records on an unencrypted ext4 filesystem.
- **Risk:** Physical theft or server compromise exposes every patient record in plaintext.
- **Reference:** Project 1x02 – Vulnerability Assessment; Project 1x03 – Risk Register.

---

## Priority 2 – Encrypt Billing Data

- **System:** `billing-srv-01`
- **Issue:** The MySQL database is neither encrypted at rest nor protected with SSL/TLS for client connections.
- **Risk:** Financial records, insurance information and patient identifiers can be stolen directly from disk or intercepted across the network.
- **Reference:** Crypto-miner forensic investigation from Project 1x00.

---

## Priority 3 – Protect Backup Data

- **System:** `NAS-01`
- **Issue:** Backup data is stored in plaintext with no independent key management.
- **Risk:** Ransomware compromising the NAS gains immediate access to every database backup.
- **Reference:** Kill Chain #1 and Risk Register (Project 1x03).

---

## Priority 4 – Encrypt Medical Imaging

- **Systems:** PACS Server, MRI Workstation and Radiology Workstations.
- **Issue:** DICOM traffic is transmitted without TLS and images are stored unencrypted.
- **Risk:** Patient identifiers and diagnostic images can be intercepted or copied without authentication.
- **Reference:** Vulnerability Assessment Finding – Cleartext DICOM Communications.

---

## Priority 5 – Modernize Active Directory Cryptography

- **Systems:** `ad-dc-01`, `ad-dc-02`
- **Issue:** Kerberos continues to support DES and RC4, while LDAP Signing is disabled.
- **Risk:** Kerberoasting attacks, downgrade attacks and unsigned LDAP traffic increase the likelihood of credential compromise.
- **Reference:** Findings 007 and 018.

---

## Priority 6 – Modernize TLS on the Patient Portal

- **System:** `web-srv-01`
- **Issue:** TLS 1.0 remains enabled, HSTS is not configured, TLS 1.3 is unsupported, and certificate renewal is manual.
- **Risk:** Users remain exposed to downgrade attacks and service interruption due to certificate expiration.
- **Reference:** Findings 005 and 013.

---

## Priority 7 – Improve Data Protection While in Use

- **Systems:** Clinical Workstations and Business Workstations.
- **Issue:** Sensitive information is displayed on workstations that never lock automatically.
- **Risk:** Unauthorized users may access patient information through unattended sessions.
- **Reference:** Security Posture Assessment (Project 1x00).

---

# Overall Assessment

The cryptographic posture of MedDefense Health Systems is **poor**.

Only Microsoft 365 and the existing IPSec VPN tunnels provide cryptographic protections that can currently be considered **Adequate**. Every business-critical system managed directly by MedDefense—including the Electronic Health Record (EHR), Billing System, PACS environment, Active Directory, Backup Infrastructure and Patient Portal—contains significant cryptographic weaknesses ranging from outdated algorithms to the complete absence of encryption.

The inventory shows that:

- Only **3 of 21** evaluated data-state combinations (**14.3%**) have adequate cryptographic protection.
- **6 of 21** (**28.6%**) provide only weak or partially configured protection.
- **12 of 21** (**57.1%**) have no effective cryptographic protection whatsoever.

These findings directly support the Security Strategy developed in Project **1x03** and justify the cryptographic roadmap beginning in Project **1x04**.

The highest implementation priorities are:

1. Encrypt PostgreSQL and MySQL databases at rest.
2. Enforce encrypted database communications.
3. Implement DICOM TLS for medical imaging.
4. Encrypt backup storage using secure external key management.
5. Disable DES and RC4 in Active Directory.
6. Require LDAP Signing and LDAPS.
7. Upgrade the Patient Portal to TLS 1.3 with HSTS and automated certificate renewal.
8. Introduce stronger protections for sensitive data while actively in use, including automatic workstation locking and improved session security.

Completing these improvements will significantly reduce the attack surface identified throughout Projects **1x00 (Security Posture Assessment)**, **1x01 (Threat Landscape)**, **1x02 (Vulnerability Assessment)** and **1x03 (Security Strategy)**, providing the cryptographic foundation required for the remaining phases of MedDefense's cybersecurity programme.
