# 13. The Web Exposure

## Scope and Assumptions

This analysis includes findings involving:

- Internet-facing web applications
- Internal web management interfaces
- TLS and certificate weaknesses
- HTTP security misconfiguration
- Information disclosure
- Web application vulnerabilities
- Web-accessible medical and infrastructure devices

The separate 1x01 kill-chain document was not available with this task. Attack-chain references below are therefore provisional and based on the scan evidence.

---

# 1. Patient Portal

## Host

**10.10.2.50 — web-srv-01**

## Exposure

**Internet-facing**

The scan identifies this system as the patient portal. Because patients access it remotely, it should be treated as externally exposed even though the scan itself was performed internally.

## Findings

- **Finding 005 — TLS 1.0 enabled**
- **Finding 012 — Missing HTTP security headers**
- **Finding 013 — TLS certificate expires in 23 days**
- **Finding 021 — HTTP TRACE enabled**

## Combined Risk

The individual findings are mostly Medium or High, but together they show weak web-server hardening and poor certificate management.

The main risks are:

- downgrade or interception attacks against old TLS;
- clickjacking because `X-Frame-Options` is missing;
- XSS impact increased by the lack of Content Security Policy;
- SSL stripping risk because HSTS is missing;
- Cross-Site Tracing if TRACE is combined with XSS;
- loss of patient access if the certificate expires;
- reduced patient trust due to browser warnings.

The scan does not prove an exploitable XSS vulnerability. However, the missing controls reduce defense in depth if another web flaw exists.

## Attack Scenario

A realistic chain would be:

1. An external attacker identifies the patient portal.
2. The attacker fingerprints supported TLS versions and missing security headers.
3. The attacker looks for a separate XSS or session-management weakness.
4. If XSS is found, TRACE and missing browser protections may help steal session data.
5. The attacker accesses patient information or impersonates a patient.
6. If the certificate expires, users may become accustomed to ignoring browser warnings, increasing phishing and man-in-the-middle risk.

Provisional kill-chain mapping:

- Reconnaissance
- Initial access
- Credential/session theft
- Collection
- Exfiltration

## Priority

**Second priority among the web hosts**

It is the most exposed web system because it is patient-facing. However, the confirmed Ghostcat vulnerability on the EHR server presents a more immediate route to sensitive credentials and patient data.

Recommended actions:

1. Disable TLS 1.0 and 1.1.
2. Enable TLS 1.2 and TLS 1.3.
3. Renew the certificate and configure automatic renewal.
4. Add HSTS, CSP, X-Frame-Options and X-Content-Type-Options.
5. Disable HTTP TRACE.
6. Perform an authenticated web application test for XSS, broken access control and session weaknesses.

---

# 2. EHR Application Server

## Host

**10.10.2.10 — ehr-srv-01**

## Exposure

**Internal, but accessible across the flat network**

The server is not described as internet-facing. However, any compromised internal host may be able to reach Tomcat and the AJP connector because the network is flat.

## Findings

- **Finding 017 — Tomcat default error-page information disclosure**
- **Finding 031 — Ghostcat on AJP port 8009**
- **Finding 030 — TLS certificate common-name mismatch**

## Combined Risk

This is the highest-risk web host in the report.

Finding 017 reveals:

- Tomcat version 9.0.31;
- stack traces;
- internal path information.

That information led SecurePoint to test for Ghostcat manually.

Finding 031 then confirmed:

- AJP is active on port 8009;
- CVE-2020-1938 is present;
- arbitrary file read is possible;
- application configuration may expose database credentials.

Finding 030 is not a direct vulnerability, but repeated certificate warnings can normalize unsafe user behavior.

## Attack Scenario

A realistic chain would be:

1. An attacker compromises any workstation through phishing, malware or stolen credentials.
2. The attacker scans the flat network and finds Tomcat on port 8080.
3. The default error page reveals the exact Tomcat version and internal paths.
4. The attacker identifies Ghostcat as a likely vulnerability.
5. The attacker connects to AJP on port 8009.
6. Configuration files are retrieved.
7. Database credentials are recovered.
8. Finding 003 allows direct connection to `ehr-db-01` from the internal network.
9. Patient data is collected, altered, encrypted or exfiltrated.

Provisional kill-chain mapping:

- Internal reconnaissance
- Vulnerability identification
- Exploitation
- Credential access
- Lateral movement
- Collection
- Exfiltration
- Impact

## Priority

**First priority among all web hosts**

This is a confirmed, chainable vulnerability affecting the EHR environment.

Recommended actions:

1. Disable AJP if it is not required.
2. Patch Tomcat to a fixed version.
3. Bind AJP to localhost or an explicitly approved interface.
4. Require a strong AJP secret.
5. Block port 8009 between user networks and the server subnet.
6. Replace default error pages.
7. Remove stack traces and version banners.
8. Rotate database credentials after remediation.
9. Investigate whether sensitive files were accessed.

---

# 3. Billing Application Server

## Host

**10.10.2.15 — billing-srv-01**

## Exposure

**Internal; external exposure is not confirmed**

Port 80 is open. The scan does not state whether the billing application is accessible from the internet, so internet exposure must be verified. At minimum, the server is accessible from the flat internal network.

## Findings

- **Finding 001 — Apache mod_lua buffer overflow**
- **Finding 002 — Apache privilege escalation**
- **Finding 006 — MySQL exposed to the internal network**
- **Finding 011 — Unsupported Ubuntu 18.04 without ESM**
- **Finding 026 — Outdated kernel**

The first two are the primary web-related findings. The others increase the impact of a web compromise.

## Combined Risk

Finding 001 may allow unauthenticated remote code execution as the Apache account.

Finding 002 can then elevate that access to root.

The combined chain can result in:

- full operating-system compromise;
- billing-data theft;
- MySQL credential theft;
- service disruption;
- malware persistence;
- ransomware deployment.

The old operating system and kernel reduce confidence that the host can be safely maintained.

## Attack Scenario

1. An attacker reaches Apache internally or externally.
2. A crafted multipart HTTP request exploits Finding 001.
3. The attacker obtains code execution as `www-data`.
4. Finding 002 is used to escalate to root.
5. The attacker accesses MySQL, application secrets and financial data.
6. The attacker creates persistence or encrypts the billing system.

Provisional kill-chain mapping:

- Initial access
- Exploitation
- Execution
- Privilege escalation
- Credential access
- Collection
- Impact

## Priority

**Third priority among the main web hosts**

It is technically critical, but the EHR chain has direct PHI implications and the patient portal is internet-facing.

Recommended actions:

1. Patch or replace Apache immediately.
2. Disable `mod_lua` if not required.
3. Upgrade or rebuild the Ubuntu host.
4. Restrict MySQL to localhost or required application hosts.
5. verify whether port 80 is internet-accessible.
6. Review for prior compromise and persistence.

---

# 4. Backup NAS Management Interface

## Host

**10.10.2.41 — NAS-01**

## Exposure

**Internal-only, but accessible from the entire internal network**

DSM is exposed on ports 5000 and 5001.

## Findings

- **Finding 015 — Synology DSM management interface broadly accessible**
- Backup data is stored unencrypted

## Combined Risk

The web management interface is not itself reported as vulnerable in this scan, but its broad exposure creates a high-value attack surface.

If an attacker obtains credentials or exploits a future DSM vulnerability, they may gain access to:

- server backups;
- configuration files;
- database backups;
- recovery data;
- administrative credentials.

Because backups are unencrypted, a successful compromise could expose large volumes of sensitive data.

## Attack Scenario

1. An attacker compromises a normal workstation.
2. The attacker scans internal web services.
3. DSM is discovered on ports 5000/5001.
4. The attacker attempts credential reuse, brute force or exploitation of a DSM CVE.
5. Backup files are stolen or deleted.
6. During ransomware deployment, recovery capability is disabled.

Provisional kill-chain mapping:

- Internal reconnaissance
- Credential access
- Lateral movement
- Collection
- Impact/inhibit recovery

## Priority

**Fourth priority**

It is not internet-facing, but compromise would seriously damage recovery capability.

Recommended actions:

1. Restrict ports 5000 and 5001 to administrative IPs.
2. Disable HTTP and use HTTPS only.
3. Require MFA.
4. Encrypt backups.
5. Isolate the NAS in a backup VLAN.
6. Maintain offline or immutable backups.
7. Patch DSM and installed packages.

---

# 5. Unknown Linux Device on Server Subnet

## Host

**10.10.2.99 — Unknown Linux device**

## Exposure

**Internal, flat-network accessible**

## Findings

- **Finding 028 — Unknown Linux host**
- SSH on port 22
- Cockpit web interface on port 9090
- Jupyter Notebook-like interface on port 8888

## Combined Risk

The greatest issue is not a confirmed CVE but the absence of ownership and inventory control.

Jupyter and Cockpit are powerful administrative interfaces. If weakly authenticated or misconfigured, they may provide:

- command execution;
- file access;
- package installation;
- credential theft;
- persistent access to the server network.

Because the device is undocumented, it may also lack patching, monitoring and approved security controls.

## Attack Scenario

1. An attacker discovers ports 8888 and 9090.
2. The attacker tests for no authentication, weak credentials or default credentials.
3. Jupyter provides command execution or Cockpit provides administrative control.
4. The attacker pivots to other servers in `10.10.2.0/24`.
5. The device becomes a persistent internal foothold.

## Priority

**High investigation priority**

Recommended actions:

1. Identify the owner immediately.
2. Isolate the host until approved.
3. Verify authentication on Jupyter and Cockpit.
4. Review running notebooks, users, SSH keys and processes.
5. Patch or remove the device.
6. Add it to the asset inventory if legitimate.

---

# 6. Unknown Grafana Device at Westside Clinic

## Host

**10.10.10.200 — Unknown Westside Linux device**

## Exposure

**Internal at Westside, with possible reachability through the site-to-site VPN**

## Findings

- **Finding 029 — Unknown Linux host**
- Grafana 8.2.0 on port 3000
- CVE-2021-43798 path traversal noted
- SSH and HTTP also exposed

## Combined Risk

This is a strong internal compromise candidate.

Grafana 8.2.0 is associated with an unauthenticated arbitrary file-read vulnerability. Sensitive files may reveal:

- passwords;
- API keys;
- datasource credentials;
- configuration files;
- SSH material.

Because the Westside router terminates a VPN to MedDefense Central, compromise of this device may support movement toward central systems.

## Attack Scenario

1. An attacker compromises a Westside endpoint or gains VPN access.
2. Grafana is discovered on port 3000.
3. CVE-2021-43798 is used to read local files.
4. Credentials or secrets are recovered.
5. The attacker pivots through the Westside network or VPN.
6. Central MedDefense assets are targeted.

## Priority

**High**

Recommended actions:

1. Identify and isolate the device.
2. Upgrade Grafana immediately.
3. Rotate credentials and API keys.
4. Review Grafana logs and accessed files.
5. restrict port 3000 to approved administrators.
6. review the Westside VPN trust relationship.

---

# 7. Westside Clinic Router Administration Page

## Host

**10.10.10.1 — Westside Netgear Router**

## Exposure

**Internal at Westside**

The administration page is accessible from the internal network.

## Findings

- **Finding 014 — Consumer-grade router with internal administration page**
- Device terminates the site-to-site VPN to MedDefense Central

## Combined Risk

The issue is primarily architectural and administrative.

A compromised router could allow an attacker to:

- alter VPN configuration;
- redirect traffic;
- disable logging;
- create new access rules;
- capture traffic;
- pivot directly toward MedDefense Central.

The lack of enterprise logging and granular controls increases detection difficulty.

## Attack Scenario

1. An attacker compromises a Westside workstation.
2. The router administration page is discovered.
3. Weak/default credentials or a router vulnerability provide access.
4. The attacker changes VPN or firewall settings.
5. A trusted path into the central server network is created.

## Priority

**High, especially because it controls the VPN boundary**

Recommended actions:

1. Replace the consumer router with an enterprise firewall.
2. Restrict management to a dedicated admin host.
3. Change credentials and require MFA if supported.
4. update firmware.
5. review VPN configuration and logs.
6. block management access from ordinary clinic workstations.

---

# 8. Medical Device Web Interfaces

## Hosts

- **10.10.3.40–46 — BD Alaris infusion pumps**
- **10.10.3.10–32 — Philips IntelliVue monitors**

## Exposure

**Internal, flat-network accessible**

## Findings

- **Finding 010 — BD Alaris web interfaces and default credentials**
- **Finding 016 — Philips IntelliVue web management interfaces without meaningful authentication**

## Combined Risk

These interfaces are not internet-facing, but they are reachable from the flat internal network.

The Alaris devices use default credentials on all seven scanned pumps. The Philips monitors rely on network location as their main protection, but the flat network provides no meaningful trust boundary.

A compromised workstation may therefore access medical-device management functions directly.

## Attack Scenario

1. An attacker compromises a clinical or administrative workstation.
2. The attacker scans the medical-device subnet.
3. Default credentials or unauthenticated interfaces provide access.
4. Device configuration is changed or services are disrupted.
5. Patient-care availability is affected.

## Priority

**Critical from a clinical availability perspective**

Recommended actions:

1. Move medical devices to dedicated VLANs.
2. Allow only required clinical systems.
3. Change default credentials.
4. block web management from ordinary workstations.
5. monitor device traffic.
6. coordinate firmware updates with vendors.

---

# Relative Priority Order

| Rank | Host / Group | Reason |
|---:|---|---|
| 1 | `ehr-srv-01` | Confirmed Ghostcat plus credential path to patient database |
| 2 | Medical device web interfaces | Direct clinical availability impact and default/no authentication |
| 3 | `web-srv-01` | Internet-facing patient portal |
| 4 | `billing-srv-01` | RCE-to-root chain on financial system |
| 5 | `10.10.10.200` unknown Grafana device | Public file-read exploit and undocumented system |
| 6 | `NAS-01` | Backup confidentiality and recovery risk |
| 7 | Westside router | Controls VPN trust boundary |
| 8 | `10.10.2.99` unknown Jupyter/Cockpit host | Possible shadow IT and command-execution surface |

This order may change after confirming actual internet exposure, asset criticality and evidence of compromise.

---

# Why Finding 017 Matters

Finding 017 was rated Medium because version disclosure and stack traces are not direct compromise by themselves. However, the information revealed the exact Tomcat version and indicated that Ghostcat might be relevant.

SecurePoint investigated further and discovered Finding 031, a confirmed CVSS 9.8 vulnerability on the EHR server.

This demonstrates that Medium information-disclosure findings can act as **investigation pivots**. They help an attacker or analyst answer:

- What software is running?
- Which version is installed?
- Which connectors or modules may be enabled?
- Which CVEs should be tested manually?
- What internal paths or configuration details are exposed?

The lesson is not that every version banner is Critical. The lesson is that severity and investigative value are different concepts. A Medium finding may reveal the evidence needed to uncover a Critical vulnerability that the automated scanner could not confirm.
