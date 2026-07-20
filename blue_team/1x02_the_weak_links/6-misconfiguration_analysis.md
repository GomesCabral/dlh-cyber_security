# 6. Misconfiguration Findings

## Finding 003

**Finding ID:** 003

**Host:** 10.10.2.11 (ehr-db-01)

**Misconfiguration:** PostgreSQL accepts connections from the entire internal network (`listen_addresses='*'` and `pg_hba.conf` allows `10.10.0.0/16`).

**Why No CVE:** This is not a software flaw. PostgreSQL is working as designed; the administrator configured it too broadly.

**Severity Assessment:** **Critical.** Any compromised internal host could directly attempt to access the patient database containing PHI.

**Cross-Reference 1x00:** Network segmentation/control gap (1x00 T5/T7). The finding shows insufficient network restrictions around a critical database.

**Comparable CVE Risk:** Comparable to **CVE-2020-1938 (Ghostcat)** because both can expose sensitive database information. The misconfiguration may be even more dangerous because it provides direct database access if credentials are obtained.

---

## Finding 006

**Finding ID:** 006

**Host:** 10.10.2.15 (billing-srv-01)

**Misconfiguration:** MySQL is bound to `0.0.0.0`, allowing connections from every internal host.

**Why No CVE:** This is an insecure configuration, not a vulnerability in MySQL itself.

**Severity Assessment:** **High.** It unnecessarily increases the attack surface of the billing database.

**Cross-Reference 1x00:** Network scan (1x00 T7) and security control gap (1x00 T5).

**Comparable CVE Risk:** Comparable to **CVE-2021-44790** because compromising the billing server or another internal system could expose financial records.

---

## Finding 007

**Finding ID:** 007

**Host:** 10.10.2.20 (ad-dc-01)

**Misconfiguration:** LDAP signing is not required and SMBv1 remains enabled.

**Why No CVE:** Microsoft supports these features; the risk comes from insecure configuration choices.

**Severity Assessment:** **High.** Weakens Active Directory security and enables relay attacks.

**Cross-Reference 1x00:** Security control gap (1x00 T5).

**Comparable CVE Risk:** Comparable to **CVE-2017-0144 (EternalBlue)** because both increase the risk of compromise inside the Windows domain.

---

## Finding 015

**Finding ID:** 015

**Host:** 10.10.2.41 (NAS-01)

**Misconfiguration:** Synology DSM management is accessible across the entire network and backups are stored unencrypted.

**Why No CVE:** The product functions correctly; the exposure results from configuration decisions.

**Severity Assessment:** **High.** Backup compromise can prevent recovery after ransomware.

**Cross-Reference 1x00:** Asset protection/control gap (1x00 T5).

**Comparable CVE Risk:** Comparable to **CVE-2023-38408** because compromising the backup server or NAS could significantly impact recovery operations.

---

## Finding 023

**Finding ID:** 023

**Host:** Clinical workstations (10.10.1.20–42)

**Misconfiguration:** USB mass storage devices are not restricted by Group Policy.

**Why No CVE:** Windows is operating normally; administrators have not enforced a security policy.

**Severity Assessment:** **Medium.** USB devices increase malware and data exfiltration risk.

**Cross-Reference 1x00:** Administrative control gap (1x00 T5).

**Comparable CVE Risk:** Comparable to **CVE-2021-34527 (PrintNightmare)** because both could provide an attacker with an initial foothold inside the environment.

---

## Finding 025

**Finding ID:** 025

**Host:** 10.10.2.20 (ad-dc-01)

**Misconfiguration:** DNS zone transfers are allowed to any requester.

**Why No CVE:** DNS supports zone transfers by design. The issue is that they are not restricted.

**Severity Assessment:** **Medium.** It greatly assists attacker reconnaissance.

**Cross-Reference 1x00:** Network scan finding (1x00 T7).

**Comparable CVE Risk:** Comparable to **CVE-2021-43798** because both expose information that helps attackers identify valuable targets.

---

# Why "Our CVE scan shows nothing critical, we are secure" is dangerous

This statement provides false assurance because many of the most serious security weaknesses are configuration errors rather than software vulnerabilities. Misconfigurations such as unrestricted database access, disabled LDAP signing, exposed management interfaces, unrestricted USB devices and open DNS zone transfers have no CVE identifier, no CVSS score and may not appear in vulnerability dashboards. However, attackers frequently exploit these weaknesses because they require little or no technical exploitation. A secure organization must evaluate software vulnerabilities, configuration weaknesses, network architecture and security controls together instead of relying only on CVE counts.
