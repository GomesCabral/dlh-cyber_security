# 2. The Asymmetric Engine

## Goal

This exercise demonstrates how asymmetric cryptography works by generating RSA and ECC key pairs, testing their capabilities and limitations, and understanding why modern protocols such as TLS combine asymmetric and symmetric cryptography.

---

# Part 1 – RSA Key Generation and Encryption

## Generate an RSA-2048 Private Key

### Command

```bash
openssl genrsa -out rsa_private.pem 2048
```

### Output

```text
Generating RSA private key, 2048 bit long modulus
........................................+++++
................................+++++
e is 65537 (0x010001)
```

### Explanation

This command generates a new 2048-bit RSA private key.

- `genrsa` generates an RSA private key.
- `-out rsa_private.pem` saves the private key in PEM format.
- `2048` specifies the key size.

The private key must remain confidential because it is used to decrypt information and create digital signatures.

---

## Protect the Private Key

```bash
chmod 600 rsa_private.pem
```

Verify permissions:

```bash
ls -l rsa_private.pem
```

Example output:

```text
-rw------- 1 gomes gomes 1704 Jul 27 12:10 rsa_private.pem
```

Only the owner should have read/write permissions.

---

## Generate the RSA Public Key

### Command

```bash
openssl rsa \
-in rsa_private.pem \
-pubout \
-out rsa_public.pem
```

### Output

```text
writing RSA key
```

### Explanation

The public key is extracted from the private key.

Unlike the private key, the public key can safely be distributed to anyone.

---

## Verify Both Keys

```bash
ls -lh rsa_private.pem rsa_public.pem
```

Example output

```text
-rw------- 1 gomes gomes 1.7K Jul 27 12:10 rsa_private.pem
-rw-r--r-- 1 gomes gomes 451  Jul 27 12:10 rsa_public.pem
```

The public key is significantly smaller because it only contains the public components of the RSA key pair.

---

## Display the RSA Key Information

Private key:

```bash
openssl rsa \
-in rsa_private.pem \
-text \
-noout
```

Public key:

```bash
openssl rsa \
-pubin \
-in rsa_public.pem \
-text \
-noout
```

These commands allow verification of:

- Modulus
- Public exponent
- Key size
- RSA parameters

Sensitive private-key values should never be shared publicly.

---

# Encrypt the Patient Record

Patient file:

```text
Patient: Jane Doe | DOB: 1985-03-14 | MRN: MED-50421 | Diagnosis: Atrial Fibrillation
```

Encrypt using RSA-OAEP:

```bash
openssl pkeyutl \
-encrypt \
-pubin \
-inkey rsa_public.pem \
-in patient.txt \
-out patient.rsa \
-pkeyopt rsa_padding_mode:oaep \
-pkeyopt rsa_oaep_md:sha256
```

### Explanation

This command encrypts the patient record using the RSA public key.

Options:

- `-encrypt` performs encryption.
- `-pubin` indicates the supplied key is public.
- `-inkey` specifies the public key.
- `-pkeyopt rsa_padding_mode:oaep` enables OAEP padding.
- `-pkeyopt rsa_oaep_md:sha256` uses SHA-256 for OAEP.

OAEP is recommended because it provides stronger security than the older PKCS#1 v1.5 padding.

---

## Verify the Ciphertext

```bash
ls -lh patient.rsa
```

Example output

```text
-rw-r--r-- 1 gomes gomes 256 Jul 27 12:12 patient.rsa
```

Display the encrypted bytes:

```bash
xxd patient.rsa | head
```

Example

```text
00000000: 75d0 01a2 ...
```

The encrypted file contains binary ciphertext and the original patient information is no longer visible.

---

# Decrypt the File

```bash
openssl pkeyutl \
-decrypt \
-inkey rsa_private.pem \
-in patient.rsa \
-out patient-rsa.dec \
-pkeyopt rsa_padding_mode:oaep \
-pkeyopt rsa_oaep_md:sha256
```

Display the decrypted contents:

```bash
cat patient-rsa.dec
```

Expected output

```text
Patient: Jane Doe | DOB: 1985-03-14 | MRN: MED-50421 | Diagnosis: Atrial Fibrillation
```

---

## Verify Integrity

Compare both files:

```bash
cmp patient.txt patient-rsa.dec
echo $?
```

Expected result

```text
0
```

A return value of **0** indicates that both files are identical.

Verify using SHA-256:

```bash
sha256sum patient.txt patient-rsa.dec
```

Example

```text
5c0a65d817510020e02ccb5d44ac30e6def0d5bf31b32a604c960aa1d4e03682 patient.txt
5c0a65d817510020e02ccb5d44ac30e6def0d5bf31b32a604c960aa1d4e03682 patient-rsa.dec
```

Matching hashes confirm that encryption and decryption were successful.

---

## MedDefense Connection

RSA is suitable for protecting small pieces of sensitive information such as cryptographic keys and certificates.

However, RSA is **not appropriate** for encrypting large assets such as:

- PostgreSQL EHR database
- MySQL Billing database
- PACS DICOM images
- NAS backups

Instead, MedDefense should use RSA only to protect symmetric AES keys while AES-256-GCM encrypts the actual healthcare data.

---

# Part 2 – RSA Limitation and ECC Key Generation

## Attempt to Encrypt the 100 MB Test File

The 100 MB test file created in Task 1 is used to demonstrate the limitations of asymmetric encryption.

### Verify the File

```bash
ls -lh testfile
```

Example output

```text
-rw-r--r-- 1 gomes gomes 100M Jul 27 12:20 testfile
```

---

## Attempt RSA Encryption

```bash
openssl pkeyutl \
-encrypt \
-pubin \
-inkey rsa_public.pem \
-in testfile \
-out testfile.rsa \
-pkeyopt rsa_padding_mode:oaep \
-pkeyopt rsa_oaep_md:sha256
```

Example output

```text
Public Key operation error
error:0200006E:rsa routines::data too large for key size
```

Depending on the OpenSSL version, the error message may vary slightly.

---

## Why RSA Cannot Encrypt Large Files

RSA is mathematically limited by the size of its modulus.

A 2048-bit RSA key has a modulus of:

```text
2048 bits = 256 bytes
```

After OAEP padding is applied, the maximum amount of plaintext that can be encrypted is approximately:

```text
190 bytes
```

The test file is:

```text
100 MB
=
104,857,600 bytes
```

Since 104,857,600 bytes greatly exceeds RSA's maximum payload size, encryption fails immediately.

RSA was never designed to encrypt large amounts of data.

Instead, RSA encrypts only very small pieces of information such as:

- AES session keys
- Digital signatures
- Certificate information

The actual files are encrypted using fast symmetric algorithms such as AES.

---

## MedDefense Connection

The following MedDefense assets are too large for RSA encryption:

- PostgreSQL EHR database
- MySQL Billing database
- PACS DICOM images
- NAS backups
- MRI image archives

RSA is therefore used only to protect AES encryption keys, while AES-256-GCM encrypts the healthcare data itself.

---

# Generate an ECC Key Pair

Elliptic Curve Cryptography (ECC) provides equivalent security using much smaller keys than RSA.

---

## Generate the ECC Private Key

```bash
openssl ecparam \
-genkey \
-name prime256v1 \
-out ecc_private.pem
```

The selected curve:

```text
prime256v1
```

is the NIST P-256 curve.

Protect the private key:

```bash
chmod 600 ecc_private.pem
```

---

## Generate the ECC Public Key

```bash
openssl ec \
-in ecc_private.pem \
-pubout \
-out ecc_public.pem
```

Example output

```text
read EC key
writing EC key
```

---

## Verify the ECC Keys

```bash
ls -lh ecc_private.pem ecc_public.pem
```

Example output

```text
-rw------- 1 gomes gomes 227 Jul 27 12:35 ecc_private.pem
-rw-r--r-- 1 gomes gomes 178 Jul 27 12:35 ecc_public.pem
```

---

## Inspect the ECC Private Key

```bash
openssl ec \
-in ecc_private.pem \
-text \
-noout
```

The output displays:

- Curve name
- Private key
- Public point

As with RSA, the private key must never be disclosed publicly.

---

# Compare RSA and ECC Key Sizes

Determine the exact file sizes.

```bash
wc -c rsa_private.pem ecc_private.pem
```

or

```bash
stat -c "%n : %s bytes" rsa_private.pem ecc_private.pem
```

Example output

```text
1704 rsa_private.pem
227 ecc_private.pem
```

---

## Calculate the Ratio

```bash
rsa=$(stat -c %s rsa_private.pem)

ecc=$(stat -c %s ecc_private.pem)

awk -v r="$rsa" -v e="$ecc" \
'BEGIN {printf "RSA/ECC Ratio = %.2f : 1\n", r/e}'
```

Example output

```text
RSA/ECC Ratio = 7.51 : 1
```

The exact ratio depends on the OpenSSL version and PEM encoding.

---

## Why ECC Uses Smaller Keys

RSA security depends on the difficulty of factoring very large integers.

ECC security depends on solving the Elliptic Curve Discrete Logarithm Problem (ECDLP), which is significantly harder per bit.

As a result:

| Algorithm | Approximate Security |
|-----------|---------------------:|
| RSA-2048 | ~112 bits |
| RSA-3072 | ~128 bits |
| ECC P-256 | ~128 bits |
| ECC P-384 | ~192 bits |

ECC therefore provides equivalent security using dramatically smaller keys.

Smaller keys result in:

- Lower CPU utilisation
- Less RAM usage
- Smaller certificates
- Faster TLS handshakes
- Lower bandwidth consumption
- Lower power consumption

---

## MedDefense Connection

Many MedDefense devices have limited processing power, including:

- BD Alaris infusion pumps
- Philips IntelliVue patient monitors
- Portable diagnostic equipment
- Medical IoT devices

ECC is preferable for these systems because it provides strong security while consuming significantly fewer computing resources than RSA.

This allows secure authentication and encrypted communication without negatively affecting medical device performance.

---

---

# Part 3 – The Hybrid Cryptographic Model

Modern secure communication does not rely exclusively on either symmetric or asymmetric cryptography. Instead, protocols such as TLS use a **hybrid cryptographic model**, combining the strengths of both approaches.

During the TLS handshake, asymmetric cryptography authenticates the server and securely establishes a shared secret between the client and the server. In modern TLS implementations, this is normally achieved using **ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)**, while the server's certificate is signed using either RSA or ECC.

Once both parties derive the same shared secret, symmetric session keys are generated. From that point onwards, all application data is encrypted using a fast symmetric algorithm such as **AES-256-GCM** or **ChaCha20-Poly1305**.

This approach combines the advantages of both cryptographic systems:

- Asymmetric cryptography solves the secure key exchange problem.
- Symmetric cryptography provides high-speed encryption for large amounts of data.

Using only RSA would make communication extremely slow and impractical. Using only AES would require both parties to share a secret key before communication begins, creating a key-distribution problem.

---

# MedDefense HTTPS Example

When a patient connects to the MedDefense Patient Portal using HTTPS, the following sequence occurs:

1. The browser connects to `https://portal.meddefense.com`.
2. The web server sends its X.509 certificate.
3. The browser validates the certificate chain and verifies the server identity.
4. An ephemeral key exchange (ECDHE) establishes a shared session secret.
5. Both sides derive identical AES session keys.
6. AES-256-GCM encrypts all HTTP requests and responses for the remainder of the session.

This process protects:

- Patient login credentials
- Appointment information
- Medical records
- Billing information
- Session cookies

Although RSA may be used to sign the server certificate, **RSA does not encrypt the website traffic itself**. The actual patient data is protected using symmetric encryption.

---

# Comparison of Common Cryptographic Algorithms

| Algorithm | Type | Common Key Lengths | Approximate Security | Status | Approved for Healthcare? | Typical MedDefense Usage |
|-----------|------|-------------------:|---------------------:|--------|-------------------------|--------------------------|
| AES-128 | Symmetric Block Cipher | 128 bits | 128-bit security | Approved | Yes | Internal encrypted communications |
| AES-192 | Symmetric Block Cipher | 192 bits | 192-bit security | Approved | Yes | Acceptable but less commonly deployed |
| AES-256 | Symmetric Block Cipher | 256 bits | 256-bit security | Recommended | Yes | EHR database, Billing database, backups, storage encryption |
| AES-256-GCM | Symmetric AEAD | 256 bits | Very Strong | Recommended | Yes | TLS, VPN, encrypted databases |
| RSA-2048 | Asymmetric | 2048 bits | ~112-bit security | Approved | Yes | Certificates, digital signatures, key exchange |
| RSA-4096 | Asymmetric | 4096 bits | ~150-bit security | Approved | Yes | High-assurance certificates |
| ECC P-256 | Asymmetric | 256-bit curve | ~128-bit security | Recommended | Yes | TLS, VPN, IoT, medical devices |
| ECC P-384 | Asymmetric | 384-bit curve | ~192-bit security | Recommended | Yes | Higher assurance environments |
| ChaCha20-Poly1305 | Symmetric AEAD | 256 bits | Very Strong | Recommended | Yes | TLS on devices without AES acceleration |
| DES | Symmetric Block Cipher | 56 bits | Broken | Deprecated | No | Must be removed from Kerberos compatibility |
| 3DES | Symmetric Block Cipher | 112/168 bits | Deprecated | Deprecated | No | Should not be used in modern healthcare environments |
| RC4 | Stream Cipher | 128 bits | Broken | Prohibited | No | Must be disabled (Finding 018) |

---

# Why AES-256-GCM Is Recommended

Compared with AES-CBC, AES-GCM provides both:

- Confidentiality
- Integrity (authentication)

If an attacker modifies encrypted data, AES-GCM detects the modification immediately.

AES-CBC encrypts data but requires an additional MAC (Message Authentication Code) to provide integrity protection.

For this reason, AES-GCM has become the recommended encryption mode for:

- TLS 1.2
- TLS 1.3
- VPNs
- Cloud storage
- Database encryption
- Backup encryption

---

# Connection to Previous MedDefense Findings

This exercise directly addresses multiple weaknesses identified during the previous projects.

| Previous Finding | Cryptographic Improvement |
|------------------|---------------------------|
| PostgreSQL database stored without encryption | Encrypt using AES-256-GCM |
| MySQL billing database stored in plaintext | Encrypt using AES-256-GCM |
| DICOM traffic transmitted in cleartext | Enable DICOM TLS |
| NAS backups stored without encryption | Encrypt backups before storage using AES-256 |
| Kerberos allows DES and RC4 | Disable DES and RC4; use AES-only Kerberos |
| TLS 1.0 enabled on Patient Portal | Upgrade to TLS 1.3 |
| Weak Apache cipher suites | Allow only strong AEAD cipher suites |
| Let's Encrypt certificate nearing expiry | Implement automatic renewal |

---

# Security Conclusions

This laboratory demonstrates the practical strengths and limitations of asymmetric cryptography.

RSA successfully encrypted the small patient record but failed to encrypt the 100 MB test file because asymmetric encryption can process only a very small amount of data relative to the key size.

ECC achieved comparable security while using significantly smaller keys than RSA, making it especially suitable for constrained medical devices.

Modern secure communication therefore relies on a hybrid approach: asymmetric cryptography securely establishes a shared secret, while symmetric cryptography performs the high-speed encryption of application data.

For MedDefense, the recommended cryptographic standards are:

- AES-256-GCM for data at rest and encrypted communications.
- ECDHE for TLS key exchange.
- RSA-2048 or ECC P-256 certificates.
- TLS 1.3 for all Internet-facing services.
- Complete removal of DES, RC4 and other deprecated algorithms.

Implementing these recommendations directly addresses the weaknesses identified during the vulnerability assessment and significantly improves the confidentiality, integrity and resilience of MedDefense's healthcare systems.

---

# Commands Summary

## RSA

```bash
openssl genrsa -out rsa_private.pem 2048

openssl rsa \
-in rsa_private.pem \
-pubout \
-out rsa_public.pem

openssl pkeyutl \
-encrypt \
-pubin \
-inkey rsa_public.pem \
-in patient.txt \
-out patient.rsa \
-pkeyopt rsa_padding_mode:oaep \
-pkeyopt rsa_oaep_md:sha256

openssl pkeyutl \
-decrypt \
-inkey rsa_private.pem \
-in patient.rsa \
-out patient-rsa.dec \
-pkeyopt rsa_padding_mode:oaep \
-pkeyopt rsa_oaep_md:sha256
```

---

## ECC

```bash
openssl ecparam \
-genkey \
-name prime256v1 \
-out ecc_private.pem

openssl ec \
-in ecc_private.pem \
-pubout \
-out ecc_public.pem
```

---

## Verification

```bash
ls -lh

cmp patient.txt patient-rsa.dec

sha256sum patient.txt patient-rsa.dec

wc -c rsa_private.pem ecc_private.pem

stat -c "%n : %s bytes" rsa_private.pem ecc_private.pem
```

---

# Final Conclusion

RSA and ECC solve the secure key distribution problem, while AES efficiently protects large volumes of sensitive information. Modern security protocols such as TLS combine both approaches to provide confidentiality, integrity, authentication and performance.

For MedDefense Health Systems, adopting AES-256-GCM, ECC-based key exchange, TLS 1.3 and modern certificate management significantly strengthens the protection of patient records, financial data, backups and encrypted network communications while eliminating the legacy cryptographic weaknesses identified during the previous security assessments.
