# 3. The Hash Laboratory

## Goal

This laboratory explores cryptographic hashing through practical experimentation. It demonstrates the avalanche effect, explains collision resistance and the birthday problem, tests how salts affect rainbow-table attacks, compares modern password-hashing algorithms, and documents an integrity-verification script for MedDefense.

> **Evidence requirement:** Outputs from terminal commands and results from `crackstation.net` must reflect the real results obtained during the laboratory. External results must not be fabricated.

---

# Part 1 - The Avalanche Effect

## SHA-256 Test

### Hashing `MedDefense`

Command:

```bash
echo -n "MedDefense" | sha256sum
```

Output:

```text
39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098  -
```

### Hashing `MedDefense1`

Command:

```bash
echo -n "MedDefense1" | sha256sum
```

Output:

```text
97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b92  -
```

The `-n` option prevents `echo` from adding a newline character to the input. Without this option, the command would hash `MedDefense\n` rather than exactly `MedDefense`, producing a different result.

---

## SHA-256 Comparison

SHA-256 produces a 256-bit output represented by 64 hexadecimal characters.

```text
MedDefense:
39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098

MedDefense1:
97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b92
```

The two SHA-256 outputs differ in **62 of the 64 hexadecimal character positions**.

At the bit level, **131 of the 256 bits differ**:

```text
131 / 256 × 100 = 51.2%
```

This demonstrates the avalanche effect. Adding only one character to the input caused approximately half of the hash output bits to change.

---

## MD5 Test

### Hashing `MedDefense`

Command:

```bash
echo -n "MedDefense" | md5sum
```

Output:

```text
75d47fd4b4d183456d0f98fd9ba6ae4d  -
```

### Hashing `MedDefense1`

Command:

```bash
echo -n "MedDefense1" | md5sum
```

Output:

```text
0d2aed72043f78c2935e61ba8520306d  -
```

---

## MD5 Comparison

MD5 produces a 128-bit output represented by 32 hexadecimal characters.

```text
MedDefense:
75d47fd4b4d183456d0f98fd9ba6ae4d

MedDefense1:
0d2aed72043f78c2935e61ba8520306d
```

The two MD5 outputs differ in **30 of the 32 hexadecimal character positions**.

At the bit level, **71 of the 128 bits differ**:

```text
71 / 128 × 100 = 55.5%
```

MD5 therefore also demonstrates an avalanche effect. However, the avalanche effect alone does not make a hashing algorithm secure. MD5 is cryptographically broken because practical collision attacks have been demonstrated.

---

## Hash Summary

| Algorithm | Input | Hash |
|---|---|---|
| SHA-256 | `MedDefense` | `39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098` |
| SHA-256 | `MedDefense1` | `97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b92` |
| MD5 | `MedDefense` | `75d47fd4b4d183456d0f98fd9ba6ae4d` |
| MD5 | `MedDefense1` | `0d2aed72043f78c2935e61ba8520306d` |

---

## MedDefense Connection

The avalanche effect is important for integrity monitoring. If an attacker modifies even one byte in a MedDefense patient record, database backup, DICOM image, configuration file, or administrative script, its SHA-256 hash will change significantly.

Comparing a trusted expected hash with the current file hash therefore allows MedDefense to identify accidental corruption or unauthorised modification.

---

# Part 2 - Hash Collisions and the Birthday Problem

## Number of Possible Outputs

MD5 produces a 128-bit hash:

```text
Possible MD5 outputs = 2^128
```

SHA-256 produces a 256-bit hash:

```text
Possible SHA-256 outputs = 2^256
```

Approximate decimal values:

```text
2^128 ≈ 3.40 × 10^38
```

```text
2^256 ≈ 1.16 × 10^77
```

---

## What Is a Hash Collision?

A hash collision occurs when two different inputs produce the same hash output.

```text
Hash(input A) = Hash(input B)
```

Example:

```text
legitimate-document.pdf  -> ABC123
malicious-document.pdf   -> ABC123
```

If the same hash were accepted for both files, an attacker could potentially replace a legitimate file without the integrity check detecting the substitution.

---

## The Birthday Problem

An attacker does not normally need to test all `2^n` possible outputs to find any collision.

Because of the birthday paradox, the number of attempts required for a generic collision search is approximately:

```text
2^(n/2)
```

For MD5:

```text
2^(128/2) = 2^64
```

For SHA-256:

```text
2^(256/2) = 2^128
```

| Algorithm | Output Size | Possible Outputs | Approximate Generic Collision Work |
|---|---:|---:|---:|
| MD5 | 128 bits | `2^128` | `2^64` |
| SHA-256 | 256 bits | `2^256` | `2^128` |

---

## Collision Analysis

MD5 has a much smaller output space than SHA-256 and is therefore more susceptible to collision attacks. A birthday attack exploits the probability that two different inputs will produce the same output after approximately `2^(n/2)` trials, rather than attempting to find a specific input for a chosen hash. For MD5, the generic birthday bound is approximately `2^64`, while SHA-256 provides a much larger `2^128` collision-security margin. MD5 also has known practical cryptographic weaknesses, making it unsuitable for digital signatures, certificate validation, or security-sensitive integrity verification.

---

## Finding 018 and Kerberos RC4

Finding 018 from Project 1x02 confirmed that MedDefense still permits RC4 for Kerberos authentication.

RC4-based Kerberos uses encryption keys derived from the user's unsalted NT hash, which is based on MD4. Legacy MD5-based constructions are also involved in RC4-HMAC Kerberos operations.

If an attacker captures an RC4-encrypted service ticket, the attacker can perform fast offline password guessing without repeatedly contacting Active Directory. Weak or reused service-account passwords may therefore be recovered quickly, enabling privilege escalation, lateral movement, and access to sensitive MedDefense systems.

The practical security problem is not only MD5 collision resistance. The NT hash is unsalted and computationally fast, allowing attackers to test large numbers of password guesses using GPUs.

---

# Part 3 - Rainbow Table Demonstration

The following demonstration was performed using:

```text
https://crackstation.net/
```

The site `crackstation.net` was used to test both an unsalted MD5 password hash and a salted MD5 password hash.

---

## Unsalted Password

Input:

```text
password123
```

Command:

```bash
echo -n "password123" | md5sum
```

Output:

```text
482c811da5d5b4bc6d497ffa98491e38  -
```

Hash submitted to `crackstation.net`:

```text
482c811da5d5b4bc6d497ffa98491e38
```

Result returned by `crackstation.net`:

```text
password123
```

The password was recovered because `password123` is a common password and its unsalted MD5 hash is present in precomputed password databases and rainbow tables.

---

## Salted Password

Salted input:

```text
s4lt9xQ2:password123
```

Command:

```bash
echo -n "s4lt9xQ2:password123" | md5sum
```

Output:

```text
6d537fa53f1db2c22b0451ef4ef9fbe8  -
```

Hash submitted to `crackstation.net`:

```text
6d537fa53f1db2c22b0451ef4ef9fbe8
```

Result returned by `crackstation.net`:

```text
Not found
```

The salted value was not present in the precomputed lookup database because the hash was calculated from the complete value:

```text
s4lt9xQ2:password123
```

rather than from `password123` alone.

---

## Why Salting Defeats Rainbow Tables

A salt is a random value combined with a password before hashing. It prevents identical passwords from producing identical hashes and makes precomputed rainbow tables ineffective because an attacker would require a separate table for every possible salt. Every user must receive a unique salt so that work performed against one account cannot be reused against other users who selected the same password. The salt does not need to remain secret, but it must be random, sufficiently long, and stored alongside the password hash.

Reference: `https://crackstation.net/` was used to demonstrate the difference between unsalted and salted password hashes.

---

## Salt Limitation

Adding a salt does not make MD5 suitable for password storage.

MD5 remains computationally fast, allowing attackers to test millions or billions of password guesses rapidly. A secure password-storage system must combine a unique salt with a deliberately slow password-hashing algorithm such as Argon2id, bcrypt, or PBKDF2.

---

# Part 4 - Key Stretching

A simple hash performs only one fast operation:

```text
Password -> Hash Function -> Password Hash
```

A password-hashing algorithm deliberately performs expensive operations:

```text
Password + Unique Salt
          |
          v
Repeated CPU and/or Memory Operations
          |
          v
Password Hash
```

This process is known as **key stretching**.

Key stretching increases the computational cost of every password guess, making offline brute-force attacks slower and more expensive.

---

## bcrypt

bcrypt was created specifically for password storage and automatically includes a salt in its output. It uses a configurable cost factor that controls the number of computational rounds; increasing the cost factor by one approximately doubles the processing work. bcrypt is significantly more resistant to brute-force attacks than simple MD5 or SHA-256 hashing, although it is not strongly memory-hard and has a practical input limit of 72 bytes.

Example:

```text
Cost 10 -> approximately 2^10 rounds
Cost 12 -> approximately 2^12 rounds
```

---

## PBKDF2

PBKDF2 repeatedly applies a pseudorandom function, commonly HMAC-SHA-256, to a password and salt. Its iteration count determines how many times the operation is repeated, making every password guess more computationally expensive. PBKDF2 is widely supported and useful in environments requiring broad compatibility, but it is not memory-hard and is therefore less resistant to specialised GPU attacks than Argon2id.

Example:

```text
Password + Salt + HMAC-SHA-256 × Iteration Count
```

---

## Argon2

Argon2 was designed specifically to resist password-cracking attacks using GPUs and specialised hardware. It is memory-hard, meaning that each password attempt requires a configurable amount of memory as well as CPU time. Argon2id combines resistance to side-channel attacks with strong protection against time-memory trade-off attacks.

The principal parameters are:

```text
m = memory cost
t = time cost or number of passes
p = degree of parallelism
```

Increasing these parameters makes legitimate password verification slower but also increases the cost of each attacker guess.

---

## Password Hashing Comparison

| Algorithm | Unique Salt | Adjustable CPU Cost | Adjustable Memory Cost | Main Advantage |
|---|---:|---:|---:|---|
| MD5 | Manual | No | No | None for password storage |
| SHA-256 alone | Manual | No | No | Not designed for password storage |
| bcrypt | Built in | Yes | Limited | Mature and widely supported |
| PBKDF2 | Required | Yes | No | Broad compatibility |
| Argon2id | Required | Yes | Yes | Strong GPU and ASIC resistance |

---

## Recommendation for MedDefense Applications

MedDefense should use **Argon2id** for password storage in newly developed applications.

Argon2id is recommended because it:

- was designed specifically for password hashing;
- uses a unique salt;
- is memory-hard;
- makes GPU attacks more expensive;
- supports adjustable memory, time, and parallelism parameters;
- can be tuned as hardware performance changes.

PBKDF2-HMAC-SHA-256 is an acceptable alternative where compatibility, platform limitations, or regulatory requirements prevent the use of Argon2id.

bcrypt remains acceptable for existing applications when configured with an appropriate cost factor, but Argon2id provides stronger resistance to modern hardware-based password cracking.

---

## Active Directory Password Storage

Active Directory does not use bcrypt, PBKDF2, or Argon2 for its primary password representation.

For Windows authentication compatibility, Active Directory retains the **NT hash**, which is calculated by applying MD4 to the user's Unicode password. The NT hash does not use an individual salt.

Although the Active Directory database applies additional protection to stored secrets, an attacker who extracts NT hashes can perform fast offline password guessing. The hashes can also be abused in pass-the-hash attacks without recovering the original password.

By modern password-storage standards, the NT hash is not adequate on its own.

MedDefense must compensate for this limitation by:

- disabling DES and RC4;
- preferring AES-based Kerberos encryption;
- enforcing long passwords or passphrases;
- requiring MFA;
- protecting domain controllers;
- using Windows LAPS for local administrator passwords;
- restricting privileged accounts;
- monitoring for credential dumping;
- disabling legacy NTLM authentication where operationally possible;
- rotating service-account passwords;
- using group managed service accounts where possible.

---

# Part 5 - Integrity Verification Script

The integrity-verification tool is stored in:

```text
3-hash_verify.sh
```

The script takes two arguments:

```text
Argument 1: Path to the file
Argument 2: Expected SHA-256 hash
```

The script:

1. validates the number of arguments;
2. verifies that the file exists;
3. validates that the expected hash contains exactly 64 hexadecimal characters;
4. computes the current SHA-256 hash;
5. compares the actual and expected values;
6. returns exit code `0` when they match;
7. returns exit code `1` when they do not match.

---

## Script Content

```bash
#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <file_path> <expected_sha256_hash>" >&2
    exit 1
fi

file_path="$1"
expected_hash="$2"

if [ ! -f "$file_path" ]; then
    echo "Error: file does not exist: $file_path" >&2
    exit 1
fi

if ! [[ "$expected_hash" =~ ^[a-fA-F0-9]{64}$ ]]; then
    echo "Error: expected hash must contain exactly 64 hexadecimal characters." >&2
    exit 1
fi

actual_hash="$(sha256sum "$file_path" | awk '{print $1}')"

expected_hash="${expected_hash,,}"
actual_hash="${actual_hash,,}"

if [ "$actual_hash" = "$expected_hash" ]; then
    echo "INTEGRITY OK"
    exit 0
else
    echo "INTEGRITY FAILED - expected $expected_hash got $actual_hash"
    exit 1
fi
```

---

## Script Permission and Syntax Validation

Make the script executable:

```bash
chmod +x 3-hash_verify.sh
```

Verify the permissions:

```bash
ls -l 3-hash_verify.sh
```

Expected permission pattern:

```text
-rwxr-xr-x
```

Validate the Bash syntax:

```bash
bash -n 3-hash_verify.sh
```

No output means that Bash did not detect a syntax error.

Verify that the first line is correct:

```bash
head -n 1 3-hash_verify.sh
```

Expected output:

```text
#!/bin/bash
```

---

## Successful Integrity Test

Obtain the SHA-256 hash of `patient.txt`:

```bash
expected_hash="$(sha256sum patient.txt | awk '{print $1}')"
```

Display it:

```bash
echo "$expected_hash"
```

Run the script:

```bash
./3-hash_verify.sh patient.txt "$expected_hash"
```

Expected output:

```text
INTEGRITY OK
```

Check the exit code immediately:

```bash
echo $?
```

Expected output:

```text
0
```

The exit code confirms that the calculated hash matches the expected hash.

---

## Failed Integrity Test

Run the script using an incorrect SHA-256 value:

```bash
./3-hash_verify.sh patient.txt \
0000000000000000000000000000000000000000000000000000000000000000
```

Expected output format:

```text
INTEGRITY FAILED - expected 0000000000000000000000000000000000000000000000000000000000000000 got [ACTUAL HASH]
```

Check the exit code:

```bash
echo $?
```

Expected output:

```text
1
```

The non-zero exit code allows another script, monitoring platform, or automated pipeline to identify the integrity failure.

---

## Invalid Hash Test

Run the script with an invalid short hash:

```bash
./3-hash_verify.sh patient.txt abc123
```

Expected output:

```text
Error: expected hash must contain exactly 64 hexadecimal characters.
```

Check the exit code:

```bash
echo $?
```

Expected output:

```text
1
```

---

## Missing File Test

```bash
./3-hash_verify.sh missing-file.txt \
0000000000000000000000000000000000000000000000000000000000000000
```

Expected output:

```text
Error: file does not exist: missing-file.txt
```

---

# MedDefense Use Cases

The integrity-verification script can support several MedDefense security processes.

## Database Backups

The script can verify PostgreSQL and MySQL backup files before restoration:

```bash
./3-hash_verify.sh ehr-backup.sql \
"expected_hash_from_trusted_manifest"
```

A changed hash could indicate corruption, ransomware modification, unauthorised alteration, or an incomplete transfer.

## DICOM Images

SHA-256 can verify that medical images have not changed during storage or transmission between the MRI workstation and PACS.

## Software Patches

MedDefense can compare downloaded software patches with hashes published by trusted vendors before installation.

## Configuration Files

Critical firewall, web server, database, and authentication configuration files can be monitored for unauthorised changes.

## Administrative Scripts

Scripts used by IT and Security can be validated before execution to reduce the risk of running modified or malicious code.

## Certificate Files

Certificate bundles and trusted CA files can be monitored for unexpected modification.

---

# Integrity Verification Limitation

A simple hash verifies integrity only when the expected hash comes from a trusted and protected source.

If an attacker can modify both:

```text
the protected file
```

and:

```text
the expected hash
```

the attacker can calculate a new matching hash and bypass the comparison.

For authenticated integrity, MedDefense should use:

- HMAC;
- digital signatures;
- signed hash manifests;
- immutable storage;
- access-controlled integrity databases;
- secure audit logging.

An HMAC combines a cryptographic hash with a secret key, while a digital signature allows integrity and authenticity to be verified using a public key.

---

# Final Conclusions

This laboratory demonstrates that hashing is fundamentally different from encryption. Encryption is reversible when the correct key is available, while a cryptographic hash is designed to be a one-way representation of data.

The main findings are:

1. SHA-256 and MD5 both demonstrate the avalanche effect.
2. The avalanche effect alone does not make a hash algorithm secure.
3. MD5 is unsuitable for security-sensitive use because practical collision attacks exist.
4. SHA-256 provides a much larger collision-security margin than MD5.
5. Unsalted fast password hashes are vulnerable to precomputed lookup and high-speed brute-force attacks.
6. Unique salts prevent attackers from reusing rainbow tables across multiple accounts.
7. Salting must be combined with a slow password-hashing algorithm.
8. Argon2id is the preferred password-storage algorithm for new MedDefense applications.
9. Active Directory's NT hash is a legacy weakness that requires strong compensating controls.
10. SHA-256 is suitable for file-integrity checks when the expected hash is stored securely.
11. HMAC or digital signatures should be used when authenticated integrity is required.

These lessons directly support MedDefense's need to protect patient records, billing information, DICOM images, backups, application passwords, Active Directory credentials, and critical configuration files.
