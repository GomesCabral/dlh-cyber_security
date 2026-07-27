# 6. The Algorithm Landscape

## Goal

This document provides a reference of the most common cryptographic algorithms used in modern information security. It classifies each algorithm by type, explains its purpose, identifies whether it is considered current, deprecated or broken, and maps its usage to the MedDefense environment. The objective is to understand not only which algorithms should be used, but also why older algorithms must be replaced.

---

# Symmetric Encryption Algorithms

| Algorithm | Type | Key Size | Primary Use Case | Status | Why Deprecated / Broken | MedDefense Usage |
|------------|------|----------|------------------|--------|-------------------------|------------------|
| AES-128 | Symmetric | 128-bit | File encryption, TLS, VPN, databases | Current | Secure and approved by NIST | Suitable for VPNs and internal encrypted storage |
| AES-192 | Symmetric | 192-bit | High-security data encryption | Current | Secure but less commonly used than AES-256 | Optional for highly sensitive systems |
| AES-256 | Symmetric | 256-bit | Full disk encryption, databases, VPN, backups | Current | Recommended for highly regulated environments | Recommended for PostgreSQL, MySQL, NAS backups and VPN |
| DES | Symmetric | 56-bit | Legacy encryption | Broken | Key size is too small and can be brute-forced in hours | Must be removed from Kerberos compatibility |
| 3DES | Symmetric | 168-bit (effective ~112-bit) | Legacy financial systems | Deprecated | Slow and vulnerable to SWEET32 attacks | Should not be deployed |
| ChaCha20-Poly1305 | Symmetric | 256-bit | TLS, VPN, mobile devices | Current | Very efficient in software, especially without AES hardware acceleration | Recommended for mobile applications and medical devices |
| RC4 | Symmetric | Variable (40-2048 bits) | Legacy stream cipher | Broken | Statistical biases allow recovery of plaintext | Currently enabled in Kerberos compatibility and must be disabled |
| Blowfish | Symmetric | 32-448 bits | Legacy encryption | Deprecated | Small 64-bit block size makes it unsuitable for modern applications | Not recommended |

---

# Asymmetric Cryptography Algorithms

| Algorithm | Type | Key Size | Primary Use Case | Status | Why Deprecated / Broken | MedDefense Usage |
|------------|------|----------|------------------|--------|-------------------------|------------------|
| RSA-2048 | Asymmetric | 2048-bit | Certificates, digital signatures, key exchange | Current | Widely accepted security level | Used for certificates and document signing |
| RSA-4096 | Asymmetric | 4096-bit | Long-term PKI | Current | Stronger but slower than RSA-2048 | Suitable for internal CA certificates |
| ECC P-256 | Asymmetric | 256-bit | TLS, VPN, certificates | Current | Equivalent security with much smaller keys | Recommended for TLS certificates and medical devices |
| ECC P-384 | Asymmetric | 384-bit | High-security PKI | Current | Higher security than P-256 | Suitable for highly sensitive systems |
| Diffie-Hellman (DH) | Asymmetric | 2048+ bits | Secure key exchange | Current | Secure when authenticated and using strong parameters | Used during VPN key exchange |
| ECDHE | Asymmetric | 256/384-bit | TLS key exchange with Forward Secrecy | Current | Preferred modern key exchange | Recommended for Patient Portal HTTPS |

---

# Hash Algorithms

| Algorithm | Type | Output Size | Primary Use Case | Status | Why Deprecated / Broken | MedDefense Usage |
|------------|------|-------------|------------------|--------|-------------------------|------------------|
| MD5 | Hash | 128-bit | Legacy integrity checking | Broken | Practical collision attacks exist | Must never be used for passwords or certificates |
| SHA-1 | Hash | 160-bit | Legacy certificates | Deprecated | Collision attacks demonstrated | Must be replaced in all certificates |
| SHA-256 | Hash | 256-bit | Integrity verification, signatures | Current | Industry standard | Used for digital signatures and integrity checking |
| SHA-512 | Hash | 512-bit | High-security integrity | Current | Stronger output than SHA-256 | Suitable for backup integrity verification |
| SHA-3 | Hash | 224-512 bits | Next-generation hashing | Current | Different construction from SHA-2 | Optional for future deployments |

---

# Key Derivation Functions (KDF)

| Algorithm | Type | Output Size | Primary Use Case | Status | Why Deprecated / Broken | MedDefense Usage |
|------------|------|-------------|------------------|--------|-------------------------|------------------|
| PBKDF2 | KDF | Variable | Password storage | Current | Uses configurable iteration count | Suitable for application password storage |
| bcrypt | KDF | Variable | Password hashing | Current | Adaptive work factor slows brute-force attacks | Suitable for web applications |
| Argon2 | KDF | Variable | Password hashing | Current (Recommended) | Memory-hard design resists GPU attacks | Recommended for new MedDefense applications |
| scrypt | KDF | Variable | Password hashing | Current | Memory-hard algorithm | Acceptable alternative when Argon2 is unavailable |

---

# MedDefense Crypto Gap Analysis

The cryptographic assessment identified several weaknesses where MedDefense continues to use outdated or insufficient cryptographic technologies.

| Current Implementation | Status | Recommended Replacement | Reason |
|------------------------|--------|-------------------------|--------|
| TLS 1.0 on Patient Portal | Deprecated | TLS 1.3 | Eliminates known attacks such as BEAST, POODLE and Lucky Thirteen while improving performance and security. |
| Kerberos DES | Broken | AES-256 Kerberos | DES provides only a 56-bit key and can be cracked quickly using modern hardware. |
| Kerberos RC4 | Broken | AES-256 Kerberos | RC4 contains statistical weaknesses that enable offline password attacks such as Kerberoasting. |
| LDAP without encryption | Weak | LDAPS (TLS 1.3) | Protects credentials and directory traffic from interception and modification. |
| PostgreSQL without encryption at rest | Absent | AES-256 Full Disk Encryption (LUKS) | Prevents disclosure of patient records if storage media are stolen or compromised. |
| MySQL without encryption at rest | Absent | AES-256 Full Disk Encryption (LUKS) | Protects billing information containing regulated personal and financial data. |
| Plaintext MySQL connections | Weak | MySQL TLS 1.3 | Prevents interception of billing data across the network. |
| Unencrypted DICOM traffic | Absent | DICOM TLS with AES-256 | Protects medical images and embedded patient identifiers while in transit. |
| NAS backups stored in plaintext | Absent | AES-256 encrypted backup storage with external key management | Protects backups against theft and ransomware while avoiding local key compromise. |
| Missing S/MIME or Microsoft Purview Message Encryption | Weak | S/MIME or Microsoft Purview Message Encryption | Prevents exposure of protected health information (PHI) transmitted by email. |

---

# Overall Assessment

The assessment shows that MedDefense already benefits from modern cryptography in a few areas, including Microsoft 365 encryption and IPSec VPN tunnels using AES-256, SHA-256 and IKEv2. However, several critical healthcare systems still rely on weak, deprecated or completely absent cryptographic protections.

The highest priorities are:

1. Disable DES and RC4 in Active Directory Kerberos.
2. Upgrade the Patient Portal to TLS 1.3.
3. Encrypt PostgreSQL, MySQL and NAS storage using AES-256.
4. Enable TLS for MySQL, PostgreSQL and DICOM communications.
5. Implement encrypted email for protected health information.
6. Replace legacy cryptographic configurations with modern NIST-approved algorithms.

After these improvements, MedDefense will significantly strengthen the confidentiality, integrity and authenticity of patient data while aligning its cryptographic controls with current healthcare security best practices and regulatory requirements such as HIPAA.
