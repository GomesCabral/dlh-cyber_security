# 15. The Crypto Posture Audit

## Goal

This document provides a complete cryptographic posture assessment of the MedDefense environment. Every weakness identified in the original Data Protection Map (T0) has been reviewed and mapped to a specific remediation plan using the knowledge gained throughout the Crypto Foundation module.

The recommendations reference previous work completed in:

- T6 – Algorithm Landscape
- T10 – CSR Workshop
- T11 – TLS Audit
- T12 – Disk Encryption
- T13 – Encryption Levels
- T14 – Key Management

---

# CRYPTO-001

## Finding ID

CRYPTO-001

### Data Category

Patient Records (ehr-db-01)

### Data State

At Rest

### Current Protection

Database stores sensitive PHI without field-level encryption.

### Vulnerability Reference

Finding-008

### Risk Reference

RISK-001

### Algorithm Assessment

Current protection is insufficient.

Sensitive healthcare information should be protected using modern authenticated encryption.

### Recommended Protection

AES-256-GCM

### Encryption Level

Database Encryption + Record-Level Encryption

### Key Management

Database Encryption Keys (DEKs)

↓

Protected by a Key Encryption Key (KEK)

↓

Stored inside an HSM-backed KMS

↓

Annual KEK rotation

Quarterly DEK rotation

### Implementation Priority

Immediate

---

# CRYPTO-002

## Finding ID

CRYPTO-002

### Data Category

NAS-01 Backup Storage

### Data State

At Rest

### Current Protection

Plaintext backup storage.

### Vulnerability Reference

Finding-012

### Risk Reference

RISK-003

### Algorithm Assessment

No encryption currently protects backup media.

### Recommended Protection

LUKS2

AES-XTS-512

### Encryption Level

Volume Encryption

### Key Management

LUKS recovery keys stored **NOT on the NAS**.

Keys stored inside the enterprise KMS with an encrypted offline escrow copy.

### Implementation Priority

Immediate

---

# CRYPTO-003

## Finding ID

CRYPTO-003

### Data Category

Patient Portal

### Data State

In Transit

### Current Protection

TLS 1.0 enabled alongside TLS 1.2.

Certificate approaching expiration.

### Vulnerability Reference

Finding-005

Finding-013

### Risk Reference

RISK-005

### Algorithm Assessment

TLS 1.0 is deprecated.

The certificate lifecycle is not adequately managed.

### Recommended Protection

TLS 1.3

TLS 1.2

ECDHE

AES-256-GCM

HSTS

OCSP Stapling

### Encryption Level

Transport Encryption

### Key Management

ECC P-256 private key.

Stored in an HSM-backed KMS.

Certificate renewed before expiration.

### Implementation Priority

Immediate

---

# CRYPTO-004

## Finding ID

CRYPTO-004

### Data Category

Financial Records (billing-srv-01)

### Data State

At Rest

### Current Protection

Database encryption only.

No field-level encryption for payment information.

### Vulnerability Reference

Finding-014

### Risk Reference

RISK-007

### Algorithm Assessment

Financial data requires stronger protection for regulated information.

### Recommended Protection

AES-256-GCM

Tokenization for payment card data

### Encryption Level

Database Encryption

Record-Level Encryption

### Key Management

Encryption keys stored inside the central KMS.

Master keys protected by HSM.

### Implementation Priority

Phase 1

---

# CRYPTO-005

## Finding ID

CRYPTO-005

### Data Category

Medical Images (PACS)

### Data State

At Rest

### Current Protection

Storage encryption inconsistent.

### Vulnerability Reference

Finding-015

### Risk Reference

RISK-009

### Algorithm Assessment

Medical images contain protected health information.

Storage should be encrypted.

### Recommended Protection

AES-256-XTS

LUKS2

### Encryption Level

Volume Encryption

### Key Management

Managed through the enterprise KMS.

Recovery keys stored offline.

### Implementation Priority

Phase 1

---

# CRYPTO-006

## Finding ID

CRYPTO-006

### Data Category

Microsoft 365 Email

### Data State

At Rest

In Transit

### Current Protection

Standard Microsoft encryption.

No customer-managed keys.

### Vulnerability Reference

Finding-016

### Risk Reference

RISK-010

### Algorithm Assessment

Protection is acceptable but customer-managed keys improve control.

### Recommended Protection

Microsoft Purview Encryption

Customer Managed Keys

TLS 1.3

### Encryption Level

Application-Level Encryption

### Key Management

Customer Managed Keys (CMK)

Stored inside Azure Key Vault backed by HSM.

### Implementation Priority

Phase 2

---

# CRYPTO-007

## Finding ID

CRYPTO-007

### Data Category

Employee Laptops

### Data State

At Rest

### Current Protection

Disk encryption not consistently enforced.

### Vulnerability Reference

Finding-020

### Risk Reference

RISK-011

### Algorithm Assessment

Lost or stolen laptops could expose sensitive information.

### Recommended Protection

BitLocker (Windows)

LUKS2 (Linux)

AES-XTS-256

### Encryption Level

Full-Disk Encryption

### Key Management

Keys protected by TPM.

Recovery keys escrowed in the enterprise KMS.

### Implementation Priority

Phase 1

---

# CRYPTO-008

## Finding ID

CRYPTO-008

### Data Category

BD Alaris Pump Firmware

### Data State

At Rest

In Transit

### Current Protection

Firmware authenticity not verified.

### Vulnerability Reference

Finding-022

### Risk Reference

RISK-014

### Algorithm Assessment

Unsigned firmware increases the risk of malicious code execution.

### Recommended Protection

ECDSA P-256 Digital Signatures

SHA-256

Secure Boot

### Encryption Level

File-Level Encryption

Code Signing

### Key Management

Firmware signing keys protected inside an HSM.

### Implementation Priority

Immediate

---

# Posture Score

## Initial State

Approximately **40%** of MedDefense data flows had adequate cryptographic protection.

## After Remediation

Approximately **95%** of data flows now have a documented remediation strategy.

The remaining gaps relate primarily to future implementation projects rather than missing technical recommendations.

---

# Top 3 Crypto Risks

## 1. Patient Database Without Adequate Encryption

Impact:

Critical

Reason:

Exposure of protected health information (PHI) affecting approximately 50,000 patient records.

Priority:

Immediate

---

## 2. NAS-01 Plaintext Backup Storage

Impact:

Critical

Reason:

Physical theft or offline compromise exposes complete backup sets.

Priority:

Immediate

---

## 3. TLS 1.0 Still Enabled

Impact:

High

Reason:

Legacy protocol support enables downgrade attacks and weakens transport security.

Priority:

Immediate

---

# Overall Assessment

The MedDefense cryptographic posture has significantly improved throughout the Crypto Foundation project.

The proposed architecture now includes:

- AES-256-GCM for sensitive databases
- LUKS2 for backup storage
- TLS 1.2/TLS 1.3 only
- ECC P-256 certificates
- HSM-backed Key Management System
- TPM protection for endpoint encryption
- Tokenization for payment information
- Digital signatures for firmware integrity
- Centralized key rotation and lifecycle management

If all recommendations are implemented, MedDefense will have a modern cryptographic architecture aligned with current industry best practices and suitable for protecting regulated healthcare information.
