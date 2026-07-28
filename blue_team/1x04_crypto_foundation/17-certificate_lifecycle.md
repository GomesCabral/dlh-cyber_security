# 17. Certificate Lifecycle Management

## Goal

This document defines the Certificate Lifecycle Management (CLM) program for MedDefense. The objective is to ensure that all certificates are inventoried, monitored, renewed before expiration, and managed according to a consistent security policy. This prevents service outages, reduces operational risk, and strengthens the organization's overall Public Key Infrastructure (PKI).

---

# Part 1 – Certificate Inventory

| Certificate | Purpose | Issuer | Estimated Expiration | Owner |
|-------------|---------|--------|----------------------|-------|
| Patient Portal (portal.meddefense.local) | HTTPS for patient portal | MedDefense Internal CA (or Public CA for production) | 1 year | IT Infrastructure Manager |
| EHR Internal Server | HTTPS for Electronic Health Records | MedDefense Internal CA | 1 year | Infrastructure Team |
| VPN Gateway | IPsec / SSL VPN Authentication | MedDefense Internal CA | 1 year | Network Administrator |
| Email Signing (S/MIME) | Digital signatures and email encryption | Commercial CA | 2 years | Messaging Administrator |
| Email Server TLS | SMTP/IMAP TLS | Commercial CA | 1 year | Messaging Administrator |
| Code Signing Certificate | Software and firmware signing | Commercial CA | 2–3 years | Development Team Lead |
| PACS Server Certificate | Secure DICOM TLS communications | MedDefense Internal CA | 1 year | Medical Systems Administrator |
| Database Server Certificate | TLS for PostgreSQL and MySQL | MedDefense Internal CA | 1 year | Database Administrator |
| Domain Controller LDAPS Certificate | Secure LDAP | MedDefense Internal CA | 1 year | Active Directory Administrator |
| Internal Web Applications | HTTPS | MedDefense Internal CA | 1 year | Application Administrator |

---

## Certificate Inventory Requirements

The inventory should record:

- Certificate name
- Common Name (CN)
- Subject Alternative Names (SAN)
- Issuer
- Serial Number
- Signature Algorithm
- Key Algorithm
- Key Size
- Expiration Date
- Responsible Owner
- Renewal Status
- Last Renewal Date

The inventory should be stored in the organization's Configuration Management Database (CMDB) or Asset Management System.

---

# Part 2 – Auto-Renewal Strategy

## Internal Services

Use the **MedDefense Internal Certificate Authority** for:

- Internal web applications
- Active Directory
- Database servers
- PACS
- VPN
- Internal APIs

Renewal should be automated using enterprise certificate auto-enrollment.

---

## Public Patient Portal

For the public-facing patient portal, **a commercial Certificate Authority is recommended**.

### Justification

Although Let's Encrypt provides free certificates with ACME automation, the MedDefense patient portal supports approximately **800 patients per day**. Any certificate expiration would prevent secure access to healthcare services and could disrupt patient care.

A commercial CA provides:

- Longer certificate validity (typically one year)
- Enterprise support
- Commercial warranty
- Better integration with enterprise certificate management
- Dedicated support during incidents

Automatic renewal should still be configured wherever possible.

---

# Part 3 – Monitoring and Alerting

## Monitoring System

Certificate expiration should be monitored by:

- Zabbix
- Nagios
- PRTG
- Microsoft System Center
- SIEM integration (Microsoft Sentinel or Splunk)

---

## Alert Thresholds

| Days Before Expiration | Severity | Notification |
|-------------------------|----------|--------------|
| 90 Days | Informational | Certificate Owner |
| 60 Days | Low | Certificate Owner + Infrastructure Team |
| 30 Days | Medium | Infrastructure Manager + Security Team |
| 14 Days | High | IT Manager + SOC Team |
| 7 Days | Critical | IT Manager + CISO + On-call Administrator |
| 3 Days | Emergency | Executive Management + IT Director |
| Expired | Critical Incident | Incident Response Team |

---

## Alert Delivery Methods

- Email
- Microsoft Teams
- SMS
- SIEM Dashboard
- Ticket automatically created in the ITSM platform

---

# Part 4 – Certificate Policy

## Policy Rule 1

All production systems must use certificates issued by the MedDefense Internal Certificate Authority or a trusted public Certificate Authority.

Self-signed certificates are prohibited in production.

---

## Policy Rule 2

Only RSA-2048, RSA-4096, ECC P-256, or ECC P-384 certificates are permitted.

MD5, SHA-1, DES, RC4, and weak cryptographic algorithms are prohibited.

---

## Policy Rule 3

Private keys must never be stored in plaintext.

Private keys must be protected using:

- HSM
- TPM
- Secure Key Management System (KMS)

Access must follow the Principle of Least Privilege.

---

## Policy Rule 4

Certificates must be renewed before expiration.

Automatic monitoring must generate alerts beginning 90 days before certificate expiration.

No production certificate may be allowed to expire.

---

## Policy Rule 5

Every certificate must have:

- An assigned owner
- A documented business purpose
- A renewal procedure
- A revocation procedure
- An inventory record

Certificates without an assigned owner must not be deployed.

---

# Certificate Lifecycle Process

```
Generate Key Pair
        │
        ▼
Generate CSR
        │
        ▼
Submit CSR to CA
        │
        ▼
Identity Validation
        │
        ▼
Certificate Issued
        │
        ▼
Install Certificate
        │
        ▼
Verify Installation
        │
        ▼
Monitor Expiration
        │
        ▼
Renew Before Expiration
        │
        ▼
Replace Certificate
        │
        ▼
Revoke Old Certificate
        │
        ▼
Archive Documentation
```

---

# Roles and Responsibilities

| Role | Responsibilities |
|------|------------------|
| Certificate Owner | Requests renewal and validates certificate usage |
| PKI Administrator | Issues, renews, revokes, and manages certificates |
| Infrastructure Team | Installs certificates on servers |
| Security Team | Audits certificate compliance and monitors expiration |
| SOC Analyst | Monitors alerts related to certificate expiration and suspicious certificate activity |
| CISO | Approves certificate policies and oversees PKI governance |

---

# Benefits of the Certificate Lifecycle Program

Implementing this lifecycle management program provides several benefits:

- Prevents unexpected certificate expiration.
- Reduces service outages.
- Improves patient portal availability.
- Ensures compliance with healthcare security requirements.
- Simplifies certificate inventory management.
- Enables automated monitoring and renewal.
- Improves incident response through clear ownership and documented procedures.
- Strengthens trust in the MedDefense Public Key Infrastructure (PKI).

---

# Conclusion

A formal Certificate Lifecycle Management program ensures that MedDefense maintains continuous trust in its digital services. By maintaining a complete certificate inventory, assigning ownership, monitoring expiration dates, enforcing certificate policies, and automating renewal wherever possible, MedDefense can prevent certificate-related outages and maintain secure communications across all healthcare systems.
