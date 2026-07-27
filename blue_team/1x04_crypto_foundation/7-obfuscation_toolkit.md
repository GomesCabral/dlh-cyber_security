# 7. The Obfuscation Toolkit

## Goal

This document explains the differences between encryption, hashing, tokenization, data masking and steganography. It also designs a tokenization solution for MedDefense, demonstrates role-based data masking and evaluates steganography as both a legitimate protection mechanism and a potential insider threat.

---

# Part 1 - Technique Comparison

| Technique | What It Does | Can the Original Data Be Recovered? | Healthcare Use Case |
|------------|--------------|-------------------------------------|---------------------|
| **Encryption** | Converts readable data into ciphertext using a cryptographic algorithm and a key. | **Yes.** Only someone with the correct decryption key can recover the original data. | Encrypting PostgreSQL databases, VPN traffic, DICOM images and backups. |
| **Hashing** | Produces a fixed-length cryptographic digest that uniquely represents the input data. | **No.** Hashing is a one-way function and cannot be reversed. | Password storage, file integrity verification and digital signatures. |
| **Tokenization** | Replaces sensitive information with a meaningless token while storing the original value in a secure vault. | **Yes.** Only authorised systems with access to the token vault can retrieve the original data. | Replacing patient payment card numbers during billing transactions. |
| **Data Masking** | Hides part of the original value while preserving its format for authorised viewing. | **Yes.** Users with sufficient privileges can view the complete value. | Showing only the last four digits of an SSN or payment card number. |
| **Steganography** | Conceals data inside another file without changing the visible appearance of that file. | **Yes.** The hidden data can be extracted using the appropriate tool or algorithm. | Watermarking medical images or, maliciously, hiding stolen patient records inside DICOM files. |

---

# Part 2 - MedDefense Tokenization Design

## Data to be Tokenized

MedDefense should tokenize all patient payment card numbers used by the billing department.

Example:

```text
Original Card Number:
4532 8745 9911 2233

Stored Token:
CC-9F4A7B28E1
```

The billing application stores only the token. The actual card number is never stored in the production billing database.

---

## Token Format

Each token should:

- Contain no mathematical relationship to the original card number.
- Be randomly generated.
- Be unique.
- Preserve no sensitive information.

Example token format:

```text
CC-9F4A7B28E1
```

---

## Token Vault

The mapping between tokens and real payment card numbers should be stored inside a dedicated Token Vault.

The Token Vault should be protected using:

- AES-256 encryption at rest.
- TLS 1.3 for all communications.
- Multi-Factor Authentication (MFA).
- Role-Based Access Control (RBAC).
- Network segmentation.
- Audit logging.
- Daily encrypted backups.
- Hardware Security Module (HSM) for key protection when available.

Only the payment processing service should have permission to retrieve original card numbers.

---

## If the Token Vault Is Compromised

If an attacker compromises only the billing database, they obtain meaningless tokens.

If the attacker compromises the Token Vault, they could recover the original payment card numbers.

For this reason, the Token Vault must receive the strongest security controls in the environment.

---

## Tokenization vs Encryption

| Tokenization | Encryption |
|---------------|------------|
| Stores meaningless tokens instead of real data. | Stores encrypted versions of the original data. |
| Original data exists only inside the Token Vault. | Original data can always be recovered using the encryption key. |
| Reduces PCI-DSS compliance scope. | Does not reduce PCI scope because card data still exists. |
| Excellent for payment systems. | Better for general-purpose data protection. |

### Recommendation

Tokenization is the preferred solution for payment card processing because most internal systems never need access to the real card number.

---

# Part 3 - Data Masking Examples

| Data Field | Full Value | Nurse (Clinical) | Billing Clerk | Reception |
|------------|------------|------------------|---------------|-----------|
| SSN | 987-65-4321 | ***-**-4321 | 987-65-4321 | *********** |
| Patient Name | Maria Gonzalez | Maria Gonzalez | Maria Gonzalez | Maria Gonzalez |
| Diagnosis | Type 2 Diabetes | Type 2 Diabetes | ************** | ************** |

---

## Justification

### SSN

**Nurse**

Only the last four digits are required to confirm patient identity during treatment.

**Billing Clerk**

Billing personnel require the complete SSN for insurance and payment processing.

**Reception**

Reception staff do not require access to the patient's SSN to schedule appointments.

---

### Patient Name

**Nurse**

The complete patient name is necessary to provide safe clinical care.

**Billing Clerk**

The billing department must identify the patient correctly for invoices and insurance claims.

**Reception**

Reception staff require the patient's full name for appointment scheduling and check-in.

---

### Diagnosis

**Nurse**

The diagnosis is essential for patient treatment.

**Billing Clerk**

The billing department generally requires billing codes rather than detailed clinical diagnoses, so the diagnosis should remain masked whenever possible.

**Reception**

Reception staff have no clinical need to view patient diagnoses.

---

# Part 4 - Steganography as a Threat Vector

Steganography presents a significant data loss risk because sensitive information can be hidden inside legitimate files without changing their visible appearance. At MedDefense, a malicious insider could embed stolen patient records inside DICOM medical images before transferring those files to another hospital or cloud storage. Since DICOM images are routinely exchanged between facilities and are already very large binary files, the hidden data may not noticeably change the file size or trigger traditional Data Loss Prevention (DLP) controls. This makes steganographic exfiltration much more difficult to detect than transferring an obvious archive such as a ZIP file containing patient records. The Enterprise SIEM (Wazuh), combined with File Integrity Monitoring, network monitoring, anomaly detection and DLP controls proposed in the MedDefense Security Strategy, would help identify unusual DICOM transfers, unexpected file modifications and abnormal outbound data movement.

---

# MedDefense Recommendations

To improve the protection of sensitive healthcare information, MedDefense should:

1. Encrypt all databases using AES-256.
2. Replace payment card storage with tokenization.
3. Apply role-based data masking according to the principle of least privilege.
4. Continue using SHA-256 for integrity verification and password hashing algorithms such as Argon2 or PBKDF2.
5. Monitor DICOM traffic using Wazuh SIEM and anomaly detection to identify potential steganographic exfiltration.
6. Train employees to recognise data protection techniques and insider threat scenarios.

---

# Conclusion

Encryption, hashing, tokenization, data masking and steganography each solve different security problems. Encryption protects confidentiality, hashing protects integrity, tokenization reduces exposure of sensitive payment information, data masking limits information disclosure based on business need, and steganography demonstrates how attackers may hide sensitive information inside legitimate files. By implementing these techniques appropriately, MedDefense can significantly reduce the risk of unauthorised disclosure of patient information while improving compliance with HIPAA, PCI-DSS and healthcare security best practices.
