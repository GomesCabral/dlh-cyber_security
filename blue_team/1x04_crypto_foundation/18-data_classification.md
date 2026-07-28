# 18. The Data Classification Matrix

## Goal

This document defines the MedDefense Data Classification Policy. The purpose of the policy is to classify information according to its sensitivity so that appropriate security controls—including encryption, access control, monitoring, and key management—can be applied consistently across the organization.

The principle is simple:

> **The more sensitive the data, the stronger the protection required.**

---

# Part 1 – Data Type Inventory

The following table classifies MedDefense information into the major data categories used in healthcare and information security.

| Data | Regulated (HIPAA/PHI) | PII | Financial | Intellectual Property | Legal | Operational |
|------|------------------------|-----|-----------|----------------------|-------|-------------|
| Patient Medical Records | Yes | Yes | No | No | Yes | No |
| Patient Diagnoses | Yes | Yes | No | No | Yes | No |
| Medical Images (DICOM) | Yes | Yes | No | No | Yes | No |
| Prescriptions | Yes | Yes | No | No | Yes | No |
| Patient Portal Accounts | Yes | Yes | No | No | No | No |
| Employee Records | No | Yes | Yes | No | Yes | Yes |
| Payroll Data | No | Yes | Yes | No | Yes | No |
| Billing Database | No | Yes | Yes | No | Yes | No |
| Credit Card Information | No | Yes | Yes | No | Yes | No |
| Vendor Contracts | No | No | Yes | No | Yes | No |
| Legal Documents | No | Yes | No | No | Yes | No |
| Software Source Code | No | No | No | Yes | No | No |
| Medical Research Data | Possibly | Possibly | No | Yes | Yes | No |
| Encryption Keys | No | No | No | Yes | No | Yes |
| Certificates | No | No | No | Yes | No | Yes |
| Server Configurations | No | No | No | No | No | Yes |
| Backup Files | Yes | Yes | Yes | Yes | Yes | Yes |
| Hospital Website | No | No | No | No | No | Public |
| Visiting Hours | No | No | No | No | No | Public |
| Staff Directory | No | Yes | No | No | No | Yes |

---

# Part 2 – Classification Levels

## Public

### Examples

- Hospital website
- Visiting hours
- Contact information
- Public announcements

### Access

Available to everyone.

### Encryption at Rest

Not required.

### Encryption in Transit

HTTPS recommended.

### Impact if Exposed

No significant impact.

---

## Internal

### Examples

- Staff directory
- Internal procedures
- Meeting schedules
- Network documentation

### Access

Employees only.

### Encryption at Rest

Recommended (AES-256 where practical).

### Encryption in Transit

TLS 1.2 or TLS 1.3.

### Impact if Exposed

Operational disruption or minor reputational damage.

---

## Confidential

### Examples

- Financial reports
- Vendor contracts
- Payroll information
- Budget documents

### Access

Authorized departments only.

### Encryption at Rest

AES-256.

### Encryption in Transit

TLS 1.2 or TLS 1.3.

### Impact if Exposed

Financial loss, contractual issues, and regulatory consequences.

---

## Restricted

### Examples

- Patient records
- Medical images
- Prescriptions
- Credentials
- Private keys
- Encryption keys
- Authentication databases

### Access

Authorized personnel with a business need-to-know.

### Encryption at Rest

Mandatory AES-256.

### Encryption in Transit

Mandatory TLS 1.3 (TLS 1.2 minimum where TLS 1.3 is unavailable).

### Additional Controls

- MFA
- RBAC
- HSM or KMS for key storage
- Full audit logging
- Continuous monitoring

### Impact if Exposed

Critical.

Exposure may result in:

- HIPAA violations
- GDPR violations
- Identity theft
- Patient harm
- Financial penalties
- Loss of public trust

---

# Part 3 – Data Classification Decision Tree

```text
New Data
│
├── Is it publicly available?
│      │
│      ├── Yes → PUBLIC
│      │
│      └── No
│
├── Does it contain patient medical information (PHI)?
│      │
│      ├── Yes → RESTRICTED
│      │
│      └── No
│
├── Does it contain credentials, passwords, certificates, or encryption keys?
│      │
│      ├── Yes → RESTRICTED
│      │
│      └── No
│
├── Does it contain financial information?
│      │
│      ├── Yes → CONFIDENTIAL
│      │
│      └── No
│
├── Does it contain employee personal information (PII)?
│      │
│      ├── Yes → CONFIDENTIAL
│      │
│      └── No
│
├── Is it internal business or operational information?
│      │
│      ├── Yes → INTERNAL
│      │
│      └── No
│
└── Otherwise → PUBLIC
```

---

# Part 4 – Data Sovereignty and Geolocation

Data sovereignty is particularly important in healthcare because patient information is protected by laws such as HIPAA and GDPR. These regulations may restrict where personal and medical data can be stored or processed.

If MedDefense stores backups in an AWS region located in another country, the organization must ensure that all applicable legal and regulatory requirements are satisfied before transferring healthcare data across national borders.

Encryption significantly reduces the risk of unauthorized disclosure by protecting the confidentiality of the data. However, encryption **does not eliminate data sovereignty obligations**, since organizations must still comply with the laws governing where healthcare data is stored and processed.

---

# MedDefense Classification Matrix

| Classification | Example Data | Access | Encryption at Rest | Encryption in Transit |
|---------------|-------------|--------|--------------------|-----------------------|
| Public | Website, Visiting Hours | Everyone | Optional | HTTPS |
| Internal | Staff Directory, Procedures | Employees | Recommended | TLS 1.2+ |
| Confidential | Payroll, Financial Reports, Contracts | Authorized Departments | AES-256 | TLS 1.2/1.3 |
| Restricted | PHI, Credentials, Keys, Patient Records | Need-to-Know Only | AES-256 Mandatory | TLS 1.3 (TLS 1.2 minimum) |

---

# Security Controls by Classification

| Control | Public | Internal | Confidential | Restricted |
|----------|--------|----------|--------------|------------|
| Encryption at Rest | Optional | Recommended | Mandatory | Mandatory |
| Encryption in Transit | HTTPS | TLS 1.2+ | TLS 1.2/1.3 | TLS 1.3 |
| MFA | No | Optional | Recommended | Mandatory |
| Role-Based Access Control | No | Yes | Yes | Mandatory |
| Audit Logging | Optional | Yes | Yes | Mandatory |
| HSM/KMS Protected Keys | No | No | Recommended | Mandatory |
| Regular Security Monitoring | No | Recommended | Yes | Continuous |

---

# Conclusion

The MedDefense Data Classification Policy ensures that every type of information receives protection proportional to its sensitivity. Public information requires minimal controls, while Restricted data—including patient records, credentials, and encryption keys—requires the strongest protections, including AES-256 encryption, TLS 1.3, role-based access control, MFA, secure key management, and continuous monitoring.

By consistently applying this classification model, MedDefense can improve regulatory compliance, reduce security risks, and ensure that encryption and access controls are aligned with the value and sensitivity of the organization's information assets.
