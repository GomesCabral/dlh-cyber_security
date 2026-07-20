# 16. The Noise Filter

## Full Triage

Finding 001 | CVSS 9.8 Critical | 10.10.2.15 (`billing-srv-01`) | Category: AC | Reason: Unauthenticated network RCE on the billing server can chain directly into root compromise through Finding 002.

Finding 002 | CVSS 7.8 High | 10.10.2.15 (`billing-srv-01`) | Category: AC | Reason: Although local in isolation, it becomes immediately exploitable after Finding 001 and gives root access to a critical financial system.

Finding 003 | Scanner-rated Critical | 10.10.2.11 (`ehr-db-01`) | Category: AC | Reason: The patient database is reachable from the entire internal network and can be accessed directly with stolen or reused credentials.

Finding 004 | Scanner-rated Critical | 10.10.1.70 (`WS-RAD-01`) | Category: AC | Reason: The unsupported MRI workstation exposes multiple weaponized RCE vulnerabilities and is not isolated from ordinary workstations.

Finding 005 | CVSS 7.5 High | 10.10.2.50 (`web-srv-01`) | Category: AS | Reason: TLS 1.0 weakens confidentiality on the patient portal and should be disabled during planned remediation.

Finding 006 | Scanner-rated High | 10.10.2.15 (`billing-srv-01`) | Category: AS | Reason: MySQL is unnecessarily reachable from the internal network, increasing the impact of any internal compromise.

Finding 007 | Scanner-rated High | 10.10.2.20 (`ad-dc-01`) | Category: AC | Reason: Missing LDAP signing and enabled SMBv1 weaken the domain controller and may enable relay attacks or broader domain compromise.

Finding 008 | Scanner-rated High | 10.10.2.31 (`print-srv-01`) | Category: AS | Reason: The EOL print server runs an exposed Print Spooler with known weaponized vulnerabilities and requires migration or strong isolation.

Finding 009 | Scanner-rated High | 10.10.2.15 (`billing-srv-01`) | Category: AS | Reason: SSH password authentication without lockout enables brute-force attempts against a high-value server.

Finding 010 | CVSS 7.5 High | 10.10.3.40-46 (BD Alaris pumps) | Category: AC | Reason: Default credentials on all seven infusion pumps and flat-network access create immediate patient-safety and denial-of-service risk even though the CVE mapping requires validation.

Finding 011 | Scanner-rated High | 10.10.2.15 (`billing-srv-01`) | Category: AS | Reason: Ubuntu 18.04 without ESM is outside standard support and is not receiving required OS-level security updates.

Finding 012 | Scanner-rated Medium | 10.10.2.50 (`web-srv-01`) | Category: AS | Reason: Missing security headers reduce browser-side defenses on an internet-facing patient portal.

Finding 013 | Scanner-rated Medium | 10.10.2.50 (`web-srv-01`) | Category: AS | Reason: The patient portal certificate expires in 23 days and could interrupt access or train users to ignore browser warnings.

Finding 014 | Scanner-rated Medium | 10.10.10.1 (Westside Netgear router) | Category: AS | Reason: A consumer router controls the site-to-site VPN and lacks enterprise-grade logging, hardening and access control.

Finding 015 | Scanner-rated Medium | 10.10.2.41 (`NAS-01`) | Category: AC | Reason: The backup-management interface is broadly reachable and all backup data is unencrypted, creating major ransomware and recovery risk.

Finding 016 | Scanner-rated Medium | 10.10.3.10-32 (Philips IntelliVue monitors) | Category: AC | Reason: Unauthenticated medical-device interfaces and HL7 services are reachable from the flat network and may expose clinical data or disrupt monitoring.

Finding 017 | Scanner-rated Medium | 10.10.2.10 (`ehr-srv-01`) | Category: AS | Reason: Tomcat version and stack-trace disclosure directly enabled the discovery of the Critical Ghostcat vulnerability in Finding 031.

Finding 018 | Scanner-rated Medium | 10.10.2.20 and 10.10.2.21 (`ad-dc-01`, `ad-dc-02`) | Category: AS | Reason: DES and RC4 support increases the risk of Kerberoasting and offline password cracking.

Finding 019 | Scanner-rated Medium | Multiple workstations and Westside server | Category: AS | Reason: RDP exposure increases brute-force and lateral-movement risk even though NLA provides partial mitigation.

Finding 020 | CVSS 9.8 / Scanner-rated Medium | 10.10.2.40 (`backup-srv-01`) | Category: FP | Reason: CVE-2023-38408 requires forwarded ssh-agent and specific PKCS#11 conditions that are unlikely on this server and must be validated before action.

Finding 021 | Scanner-rated Medium | 10.10.2.50 (`web-srv-01`) | Category: AS | Reason: HTTP TRACE is a real but lower-priority web weakness that becomes useful when combined with XSS.

Finding 022 | Scanner-rated Low | 10.10.2.10 (`ehr-srv-01`) | Category: I | Reason: A single 47-second clock skew is a low-risk operational observation that should be monitored and rechecked.

Finding 023 | Scanner-rated Low | Clinical workstations | Category: AS | Reason: Unrestricted USB storage creates a realistic malware entry and data-exfiltration path across approximately 280 endpoints.

Finding 024 | Scanner-rated Low | 10.10.2.12 (`pacs-srv-01`) | Category: AS | Reason: Unencrypted DICOM traffic exposes patient identifiers and medical images to internal interception.

Finding 025 | Scanner-rated Low | 10.10.2.20 (`ad-dc-01`) | Category: AS | Reason: Unrestricted DNS zone transfers disclose the internal network structure and improve attacker reconnaissance.

Finding 026 | Scanner-rated Low | 10.10.2.15 (`billing-srv-01`) | Category: AS | Reason: The outdated kernel has many known CVEs and strengthens the existing RCE-to-root attack chain.

Finding 027 | Informational | Multiple Windows workstations | Category: AS | Reason: Fifteen endpoints have inactive or non-reporting endpoint protection and require investigation and agent restoration.

Finding 028 | Informational | 10.10.2.99 (unknown Linux device) | Category: AC | Reason: An undocumented server-subnet host exposes SSH, Cockpit and a Jupyter-like interface and may represent active shadow IT or persistence.

Finding 029 | Informational | 10.10.10.200 (unknown Westside Linux device) | Category: AC | Reason: An unmanaged Grafana 8.2.0 host exposes a public file-read vulnerability and may provide a pivot through the Westside VPN.

Finding 030 | Informational | 10.10.2.10 (`ehr-srv-01`) | Category: I | Reason: The certificate mismatch occurs only when clients use the IP address and is an operational issue rather than a direct vulnerability.

Finding 031 | CVSS 9.8 High | 10.10.2.10 (`ehr-srv-01`) | Category: AC | Reason: Ghostcat is manually confirmed, publicly exploitable, reachable from the flat network and may expose EHR database credentials.

---

# Triage Summary

| Category | Meaning | Count |
|---|---|---:|
| AC | Actionable Critical | 11 |
| AS | Actionable Standard | 17 |
| I | Informational | 2 |
| FP | False Positive | 1 |
| **Total** |  | **31** |

---

# Actionable Findings List

## Actionable Critical — Immediate Remediation (24-48 hours)

1. **Finding 004 — Windows XP MRI workstation**  
   Isolate immediately because multiple KEV-listed RCE vulnerabilities affect a clinically critical device.

2. **Finding 031 — Ghostcat on the EHR server**  
   Disable or restrict AJP and patch Tomcat because database credentials may be exposed.

3. **Finding 003 — Unrestricted EHR database access**  
   Restrict PostgreSQL to `ehr-srv-01` and approved administrative hosts only.

4. **Finding 001 — Apache mod_lua RCE**  
   Patch Apache or disable `mod_lua` because exploitation requires no authentication.

5. **Finding 002 — Apache privilege escalation**  
   Remediate together with Finding 001 because the chain leads to root access.

6. **Finding 007 — Domain controller LDAP/SMB weaknesses**  
   Require LDAP signing and disable SMBv1 to reduce relay and domain-compromise risk.

7. **Finding 010 — BD Alaris pumps**  
   Change default credentials, validate firmware and isolate the pumps immediately.

8. **Finding 016 — Philips IntelliVue monitors**  
   Restrict web and HL7 access to approved clinical systems only.

9. **Finding 015 — NAS backup exposure**  
   Restrict DSM administration, encrypt backups and separate backup access.

10. **Finding 029 — Unknown Grafana device**  
    Isolate and investigate because the host is unmanaged and exposes a known public exploit.

11. **Finding 028 — Unknown Jupyter/Cockpit device**  
    Isolate and identify the owner because the host may provide direct command execution on the server subnet.

---

## Actionable Standard — Scheduled Remediation (7-30 days)

1. **Finding 008 — EOL print server**
2. **Finding 011 — Ubuntu 18.04 without ESM**
3. **Finding 006 — MySQL unrestricted network binding**
4. **Finding 009 — SSH password authentication**
5. **Finding 018 — Weak Kerberos encryption**
6. **Finding 027 — Inactive endpoint protection**
7. **Finding 023 — USB storage unrestricted**
8. **Finding 005 — TLS 1.0 enabled**
9. **Finding 013 — Patient portal certificate expiry**
10. **Finding 012 — Missing HTTP security headers**
11. **Finding 014 — Consumer-grade Westside router**
12. **Finding 019 — RDP enabled on multiple hosts**
13. **Finding 024 — Unencrypted DICOM**
14. **Finding 017 — Tomcat information disclosure**
15. **Finding 026 — Outdated billing-server kernel**
16. **Finding 025 — DNS zone transfer**
17. **Finding 021 — HTTP TRACE enabled**

---

# Triage Rationale

The scanner's severity is only the starting point. The final category also considers:

- asset criticality;
- exploit availability;
- CISA KEV status;
- network reachability;
- flat-network amplification;
- chainability with other findings;
- patient-safety impact;
- whether the observation is confirmed or contextual.

This is why several Informational and Medium findings were elevated to Actionable Critical, while the technically severe Finding 020 was placed in False Positive pending validation.
