# 6. The Technical Proof

## Goal

This document records four rapid technical checks and explains what each result means for MedDefense in practical security terms. The purpose is not only to show command output, but also to demonstrate how the results would influence a real security decision.

---

# Check 1 - Certificate Inspection

## Commands

```bash
openssl x509 -in live_certificate.pem -noout -subject -issuer -dates
```

```bash
openssl x509 -in live_certificate.pem -noout -text | grep -A2 "Public Key Algorithm" | head -3
```

```bash
openssl x509 -in live_certificate.pem -noout -text | grep -A1 "Subject Alternative Name"
```

## Output

```text
subject=CN=github.com
issuer=C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
notBefore=Jul  3 00:00:00 2026 GMT
notAfter=Sep 30 23:59:59 2026 GMT
```

```text
Public Key Algorithm: id-ecPublicKey
Public-Key: (256 bit)
```

```text
X509v3 Subject Alternative Name:
DNS:github.com, DNS:www.github.com
```

## Five-Line Summary

```text
Subject: CN=github.com
Issuer: Sectigo Public Server Authentication CA DV E36
Validity: 03 July 2026 to 30 September 2026
Key Algorithm: Elliptic Curve public key, 256-bit
SAN Entries: github.com and www.github.com
```

## Interpretation

The certificate identifies `github.com` as the server and was issued by Sectigo, a publicly trusted Certificate Authority. The validity period shows when browsers should accept the certificate, while the SAN extension confirms that the certificate is valid for both `github.com` and `www.github.com`.

The 256-bit elliptic-curve public key is a modern and efficient choice for TLS. This check demonstrates how MedDefense should verify the patient portal certificate before deployment: the hostname must appear in the SAN list, the certificate must not be expired, the issuer must be trusted, and the public-key algorithm must meet the organisation's cryptographic policy.

A valid certificate does not prove that the web application itself is secure. It proves that the TLS identity and trust information are correctly configured.

---

# Check 2 - Hash Verification

## Commands

```bash
echo "Official FortiGate firmware validation test" > firmware_test.txt
sha256sum firmware_test.txt > hash_before.txt
```

```bash
echo "Unauthorised modification" >> firmware_test.txt
sha256sum firmware_test.txt > hash_after.txt
```

```bash
cat hash_before.txt
cat hash_after.txt
diff hash_before.txt hash_after.txt
echo $?
```

## Original Hash

```text
d1d54e913db8029f2d27a2b2a2ab55dda42bbc91b6a751359454ede47b62356c  firmware_test.txt
```

## Hash After Modification

```text
3332071b1e25754aca08be0ed573761e167e03f7725321684d4c2599fa81367d  firmware_test.txt
```

## Comparison Output

```text
1c1
< d1d54e913db8029f2d27a2b2a2ab55dda42bbc91b6a751359454ede47b62356c  firmware_test.txt
---
> 3332071b1e25754aca08be0ed573761e167e03f7725321684d4c2599fa81367d  firmware_test.txt
1
```

## Interpretation

The two SHA-256 hashes are completely different even though only one line was added to the file. The `diff` exit code of `1` confirms that the hash records do not match.

This demonstrates the avalanche effect of a cryptographic hash: a small file modification produces a significantly different digest. SHA-256 therefore provides a reliable integrity check when the expected hash comes from a trusted source.

For the FortiGate emergency upgrade, MedDefense should calculate the SHA-256 hash of the downloaded firmware and compare it with the hash published by Fortinet. A mismatch would indicate corruption, an incomplete download, or possible tampering, and the firmware must not be installed.

A matching hash confirms integrity against the supplied reference value. It does not by itself prove authenticity if the firmware file and the reference hash were obtained from the same untrusted source. MedDefense should therefore obtain both through an authorised Fortinet channel.

---

# Check 3 - Exploit Research

## Commands

```bash
searchsploit fortigate
```

```bash
searchsploit fortios
```

```bash
searchsploit --cve 2023-27997
```

## SearchSploit Findings

The `fortigate` search returned several historical entries, including:

```text
Fortigate Firewalls - 'EGREGIOUSBLUNDER' Remote Code Execution
Fortinet FortiGate 4.x < 5.0.7 - SSH Backdoor Access
Fortinet FortiGate FortiOS < 6.0.3 - LDAP Credential Disclosure
```

The `fortios` search returned entries including:

```text
Fortinet FortiOS 5.6.3 - 5.6.7 / FortiOS 6.0.0 - 6.0.4 - Credentials Disclosure
Fortinet FortiOS 6.0.4 - Unauthenticated SSL VPN User Password Modification
FortiOS SSL-VPN 7.4.4 - Insufficient Session Expiration & Cookie Reuse
```

The CVE-specific search returned:

```text
Exploits: No Results
Shellcodes: No Results
Papers: No Results
```

## Is There a Public Exploit for CVE-2023-27997?

No dedicated entry for CVE-2023-27997 was found in the local Exploit-DB/SearchSploit database.

However, this does **not** mean the vulnerability is safe or only theoretical. SearchSploit searches one public repository and may not contain every proof of concept, private exploit, security-research publication, or threat-actor tool.

CVE-2023-27997 is listed in the CISA Known Exploited Vulnerabilities catalogue and the supplied advisory reports active exploitation against hospitals. Therefore, real-world exploitability is already confirmed even though the local Exploit-DB search returned no exact match.

## Interpretation

The important security conclusion is:

```text
No SearchSploit result does not mean no exploit exists.
```

MedDefense must prioritise evidence of active exploitation over the absence of a single repository entry. The vulnerable FortiOS 7.0.9 appliance is internet-facing, requires no attacker authentication for exploitation, and is used as the initial-access vector in the current campaign.

This means patching or disabling SSL-VPN is an emergency action. Waiting for a convenient public Metasploit or Exploit-DB module would be an unsafe interpretation of the evidence.

---

# Check 4 - System Audit

## Command

```bash
sudo lynis audit system --quick
```

## Hardening Index

```text
hardening_index=66
```

## Warning

```text
warning[]=NETW-2704|Nameserver fd00::7eff:4dff:fef3:d5cf does not respond|-|-|
```

Only one warning was present in the retrieved Lynis report, so three distinct warnings could not be reported without inventing results.

## First Ten Suggestions

```text
DEB-0280 - Install libpam-tmpdir to set $TMP and $TMPDIR for PAM sessions.
DEB-0810 - Install apt-listbugs to display critical bugs before APT installation.
DEB-0811 - Install apt-listchanges to display significant changes before upgrades.
DEB-0880 - Install fail2ban to block hosts that generate repeated authentication failures.
BOOT-5122 - Set a password on the GRUB boot loader.
BOOT-5180 - Determine runlevel and services at startup.
BOOT-5264 - Harden system services with systemd-analyze security.
AUTH-9230 - Configure password hashing rounds in /etc/login.defs.
AUTH-9262 - Install a PAM module for password-strength testing.
AUTH-9282 - Set expiry dates for password-protected accounts where possible.
```

## Interpretation of the Hardening Index

A Hardening Index of `66` indicates that the machine has some baseline protections, but still has a meaningful number of hardening opportunities. The score must not be treated like a vulnerability count or a pass/fail certification.

Lynis evaluates configuration against its own tests and recommendations. A score of 66 therefore means the system should receive further review, prioritisation and hardening based on its business role.

For a production billing server, MedDefense should not try to increase the score blindly. Every change must be tested because aggressive hardening can break database services, scheduled jobs, authentication, monitoring agents or application integrations.

## Interpretation of the Warning

The non-responsive IPv6 nameserver may cause:

- DNS lookup delays;
- intermittent service failures;
- failed update or repository connections;
- delays in application connections that depend on name resolution.

For `billing-srv-01`, DNS reliability is important because billing applications may rely on database names, Active Directory, time services, APIs, monitoring and software repositories. The server team should confirm whether this nameserver is still required and either restore it or remove it from the resolver configuration.

## Recommendation for billing-srv-01

The first suggestion I would apply to `billing-srv-01` is:

```text
Install and configure fail2ban for exposed administrative authentication services, after confirming that it will not interfere with authorised automation or monitoring.
```

This is useful because repeated SSH or administrative login failures may indicate brute-force activity. Fail2ban can temporarily block the source address after a defined number of failures.

This control must be configured carefully:

- trusted management addresses should be allowlisted;
- thresholds should avoid locking out administrators;
- logs should be forwarded to the SIEM;
- it should complement, not replace, MFA, key-based SSH authentication and firewall restrictions.

A second high-value action would be to run:

```bash
systemd-analyze security SERVICE
```

for the billing database and related services, then apply safe service-level restrictions in a test environment before production deployment.

---

# Practical MedDefense Conclusions

| Check | Result | Practical Meaning for MedDefense |
|---|---|---|
| Certificate Inspection | Valid EC certificate with correct SAN entries | MedDefense must validate identity, issuer, dates, SAN and algorithm for the patient portal certificate |
| Hash Verification | Hash changed after one file modification | FortiGate firmware must be rejected if its SHA-256 does not match the authorised vendor value |
| Exploit Research | No exact Exploit-DB entry, but active exploitation confirmed | Absence from SearchSploit does not reduce urgency; patch or disable SSL-VPN immediately |
| Lynis Audit | Hardening Index 66 and one DNS warning | `billing-srv-01` requires risk-based hardening, reliable DNS and stronger authentication protection |

---

# Final Conclusion

The four checks demonstrate more than command execution.

The certificate check shows how to validate the identity and trust configuration of a TLS service. The hash test demonstrates how to detect firmware modification before installation. The exploit research shows why analysts must combine repositories with active-threat intelligence instead of treating an empty SearchSploit result as proof of safety. The Lynis audit identifies practical hardening work while also showing that automated findings must be interpreted in the context of a production system.

For MedDefense, the direct operational conclusions are:

1. verify the new FortiGate firmware with SHA-256 before installation;
2. treat CVE-2023-27997 as immediately exploitable despite the empty CVE-specific SearchSploit result;
3. validate certificates using SAN, validity, issuer and key algorithm;
4. harden `billing-srv-01` through tested, risk-based changes rather than applying suggestions blindly.


