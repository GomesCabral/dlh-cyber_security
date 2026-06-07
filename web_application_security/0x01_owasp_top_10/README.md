# Web Application Security - OWASP Top 10

---

## Requirements
 
### General
 
- All scripts run on `Kali Linux 2025.4`
- Allowed editors: `vi`, `vim`, `emacs`
- The IP range must be substituted via `$1`
- The first line of all files must be exactly `#!/bin/bash`
- All files must end with a newline
- Backticks, `&&`, `||`, and `;` are **not allowed**
- Code must follow the **Betty** style (checked with `betty-style.pl` and `betty-doc.pl`)

---

## Tasks
 
### Task 0 — (A2:2021) Cryptographic Failures: XOR WebSphere Decoder
 
**File:** `1-xor_decoder.sh`
 
A Bash script that decodes XOR-encoded WebSphere password hashes.
 
#### How it works
  
1. Strips the `{xor}` prefix from the input
2. Decodes the Base64 string
3. XOR-decodes each byte against `0x5F` (decimal 95, the `_` character)

#### Usage
 
```bash
./1-xor_decoder.sh {xor}KzosKw==
```
 
#### Expected Output
 
```
test
```
---

### Task 1 - Cryptographic Failures - Catch The Flag
 
## Objective
 
Find the login credentials hidden in the target machine and retrieve the flag after signing in.
 
- **Target:** `Cyber - WebSec 0x01`
- **Login Page:** `http://[MACHINE-IP]/a2/crypto_encoding_failure/`
- **Profile Page:** `http://[MACHINE-IP]/a2/crypto_encoding_failure/profile`

---

