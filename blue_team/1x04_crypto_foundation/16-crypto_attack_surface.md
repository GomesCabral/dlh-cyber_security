# 16. The Cryptographic Attack Surface

## Goal

This document maps common cryptographic attacks to the current MedDefense environment. For each attack, the mechanism, affected systems, supporting evidence, current viability, and recommended mitigations are identified.

The assessment references findings from:

- T0 – Data Protection Map
- T6 – Algorithm Landscape
- T11 – TLS Audit
- T13 – Encryption Levels
- T14 – Key Management
- 1x02 – Vulnerability Assessment
- 1x03 – Risk Register

---

# Attack 1 – TLS Downgrade Attack

## Mechanism

A TLS downgrade attack occurs when an attacker interferes with the TLS negotiation process and forces the client and server to communicate using an older, weaker protocol version such as TLS 1.0. Once the weaker protocol is selected, known cryptographic attacks against legacy TLS implementations become possible.

---

## MedDefense Vulnerability

Patient Portal

`portal.meddefense.local`

---

## Evidence

Finding-005

Patient Portal supports TLS 1.0 together with TLS 1.2.

TLS Audit (T11).

---

## Viable Today

**YES**

Because TLS 1.0 is still enabled, an attacker positioned between the client and the portal could attempt a downgrade attack against clients that still support legacy TLS.

---

## Mitigation

- Disable TLS 1.0.
- Disable TLS 1.1.
- Support only TLS 1.2 and TLS 1.3.
- Enable TLS_FALLBACK_SCSV.
- Configure only modern cipher suites.
- Enable HSTS.

---

# Attack 2 – Collision Attack

## Mechanism

A collision attack attempts to generate two different inputs that produce the same cryptographic hash value. Broken hash functions such as MD5 and SHA-1 are susceptible to practical collision attacks, allowing forged files or certificates to appear legitimate.

---

## MedDefense Vulnerability

Legacy Kerberos environments or applications using MD5.

Digital signature validation.

Legacy certificate infrastructure.

---

## Evidence

Algorithm Landscape (T6)

MD5 classified as **Broken**.

SHA-1 classified as **Deprecated**.

---

## Viable Today

**NO (for correctly configured MedDefense)**

The recommended cryptographic architecture replaces MD5 and SHA-1 with SHA-256 or SHA-384.

If any legacy systems still use MD5, then the attack becomes viable.

---

## Mitigation

- Replace MD5.
- Replace SHA-1.
- Use SHA-256 or SHA-384.
- Replace legacy certificates.

---

# Attack 3 – Birthday Attack

## Mechanism

The Birthday Attack exploits the mathematics behind hash collisions. Instead of requiring 2ⁿ attempts, a collision can often be found in approximately 2ⁿᐟ² attempts because of the Birthday Paradox.

This significantly weakens small hash outputs such as MD5.

---

## MedDefense Vulnerability

Legacy systems using:

- MD5
- SHA-1

---

## Evidence

Algorithm Landscape (T6)

MD5 and SHA-1 are no longer recommended.

---

## Viable Today

**NO**

MedDefense's recommended design uses SHA-256 and SHA-512.

A theoretical Birthday Attack against SHA-256 remains computationally infeasible with current technology.

---

## Mitigation

- SHA-256
- SHA-384
- SHA-512
- SHA-3

Avoid MD5 and SHA-1 entirely.

---

# Attack 4 – Kerberoasting

## Mechanism

Kerberoasting is an Active Directory attack where an authenticated attacker requests Kerberos service tickets (TGS) for service accounts. The tickets are encrypted using the service account password hash and can then be cracked offline without further interaction with the domain controller.

Weak passwords and legacy RC4 or DES encryption make offline cracking significantly easier.

---

## MedDefense Vulnerability

Active Directory

Service Accounts

Legacy Kerberos Encryption

---

## Evidence

Algorithm Landscape (T6)

RC4 = Deprecated

DES = Broken

Risk Register (1x03)

Weak service account credentials.

---

## Viable Today

**POTENTIALLY YES**

If MedDefense still supports RC4 or DES for Kerberos authentication or uses weak service account passwords.

If Kerberos is configured for AES-256 only with strong managed passwords, the attack becomes significantly more difficult.

---

## Mitigation

- Disable RC4.
- Disable DES.
- Use AES-256 Kerberos encryption.
- Use gMSA (Group Managed Service Accounts).
- Enforce long random passwords.
- Monitor excessive TGS requests.

---

# Attack 5 – On-Path / Man-in-the-Middle (MITM)

## Mechanism

An attacker positioned between two communicating systems intercepts, reads, or modifies traffic before forwarding it to the intended destination.

Without encryption, the attacker can view sensitive information and alter data in transit.

---

## MedDefense Vulnerability

Potential vulnerable communications include:

- DICOM traffic between PACS servers.
- Database connections without TLS.
- Legacy HTTP management interfaces.
- Internal application traffic without encryption.

---

## Evidence

Data Protection Map (T0)

Several internal communications originally lacked encryption.

TLS Audit (T11)

Transport encryption improvements recommended.

---

## Viable Today

**YES (if plaintext protocols remain)**

If any DICOM, SQL, SMB, or HTTP communication occurs without TLS or IPsec, an attacker on the same network can intercept the traffic.

---

## Mitigation

- TLS 1.2+
- TLS 1.3
- Mutual TLS
- IPsec
- VPN encryption
- Network segmentation
- Certificate validation

---

# Attack 6 – Key Recovery from Memory

## Mechanism

If an attacker gains root or SYSTEM privileges, they may dump process memory and recover cryptographic keys that are currently loaded into RAM.

Since applications must decrypt data during normal operation, encryption keys often exist in memory while the application is running.

---

## MedDefense Vulnerability

billing-srv-01

ehr-db-01

Portal Web Server

Application Servers

---

## Evidence

Key Management Design (T14)

Without HSM-backed key protection, application servers temporarily store decrypted keys in RAM.

---

## Viable Today

**YES**

If an attacker gains full administrative privileges over the operating system, memory extraction tools may recover encryption keys.

Examples include:

- gcore
- gdb
- Volatility
- LiME
- /proc/<pid>/mem

---

## Mitigation

- Store master keys inside an HSM.
- Use an HSM-backed KMS.
- Minimize key lifetime in memory.
- Rotate keys regularly.
- Enable endpoint detection and response (EDR).
- Restrict root access.
- Apply operating system hardening.

---

# Overall Cryptographic Attack Surface Assessment

| Attack | Viable Today | Risk Level | Priority |
|----------|--------------|------------|----------|
| TLS Downgrade | Yes | High | Immediate |
| Collision Attack | No (modern algorithms) | Low | Phase 2 |
| Birthday Attack | No | Low | Phase 2 |
| Kerberoasting | Potentially | High | Phase 1 |
| MITM | Yes (if plaintext traffic exists) | Critical | Immediate |
| Key Recovery from Memory | Yes (root compromise required) | Critical | Immediate |

---

# Top Three Cryptographic Risks

## 1. Unencrypted Internal Communications

Risk:

Critical

Reason:

Allows Man-in-the-Middle attacks against sensitive healthcare communications.

Priority:

Immediate

---

## 2. TLS Downgrade

Risk:

High

Reason:

TLS 1.0 support enables downgrade attacks and weakens transport security.

Priority:

Immediate

---

## 3. Memory-Based Key Extraction

Risk:

High

Reason:

An attacker with root access could recover encryption keys from RAM if they are not protected by an HSM-backed KMS.

Priority:

Immediate

---

# Conclusion

The MedDefense environment has significantly reduced its cryptographic attack surface through the recommendations developed during this project. The remaining risks are primarily associated with legacy protocols, unencrypted internal communications, and key protection.

Implementing the recommended controls—including TLS 1.2/1.3 only, AES-256, SHA-256, HSM-backed key management, secure Kerberos configuration, encrypted internal communications, and proper certificate lifecycle management—would effectively mitigate the identified attacks and align MedDefense with current cybersecurity best practices.
