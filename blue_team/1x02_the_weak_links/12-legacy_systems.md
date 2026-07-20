# 12. The Legacy Systems

## Scope and Research Method

This assessment covers the three end-of-life or unsupported systems identified in the MedDefense scan:

1. `10.10.1.70` — Windows XP SP3 MRI workstation
2. `10.10.2.31` — Windows Server 2012 R2 print server
3. `10.10.2.15` — Ubuntu 18.04 LTS billing server without ESM

The NVD research window used was:

**20 July 2024 through 20 July 2026**

A strict product search was used for each operating-system CPE, with attention to CVSS v3 Critical results.

## Important NVD Counting Limitation

NVD counts are a point-in-time result and depend on:

- the exact CPE selected;
- whether the CVE is mapped to the operating system or only to an installed component;
- whether NVD has completed enrichment;
- whether the vendor still publishes affected-version data for an EOL product;
- whether the system receives paid extended security updates.

A result of zero does **not** mean that an EOL system is safe. For very old products such as Windows XP, new CVEs are often no longer tested or formally mapped to that operating system. The system still retains all previously disclosed unpatched vulnerabilities.

---

# System 1 — Windows XP SP3 MRI Workstation

## System Information

- **Host:** `10.10.1.70`
- **Hostname:** `WS-RAD-01`
- **Role:** MRI scanner control workstation
- **Operating system:** Microsoft Windows XP SP3
- **Support ended:** 8 April 2014

## EOL Research

### NVD result count

A strict NVD search for **Critical CVEs published between 20 July 2024 and 20 July 2026 and directly mapped to Windows XP SP3 returned 0 results**.

This result must not be interpreted as evidence that Windows XP has no recent exposure. Microsoft no longer supports or routinely evaluates Windows XP against newly disclosed flaws. New vulnerabilities in shared Windows components may not be mapped back to XP even when similar code exists.

### Two most critical known exposures relevant to this host

Because the recent strict search returned zero, the two most critical confirmed vulnerabilities from the MedDefense scan are used:

#### CVE-2008-4250 — MS08-067

- Remote code execution in the Windows Server service
- Network reachable through SMB/RPC
- Mature public exploits and Metasploit support
- Scanner listed CVSS 10.0
- Port 445 is open on the workstation

#### CVE-2019-0708 — BlueKeep

- Remote code execution in Remote Desktop Services
- CVSS 9.8 Critical
- Public exploitation and CISA KEV status
- Port 3389 is open on the workstation

A third major exposure is **CVE-2017-0144 (EternalBlue)** through SMBv1.

## Permanent Exposure

An unpatched supported system has a temporary security gap: the vendor has produced, or is expected to produce, a patch that can close the known vulnerability. An EOL system has lost that remediation path. New weaknesses may remain unpatched permanently, and the number of known attack methods can only remain the same or increase.

Patching alone cannot close the risk because no normal security-update channel exists. The organization must migrate, replace, isolate, or accept the continuing exposure.

## Scan Findings

### Finding 004 — Windows XP End-of-Life Detection

The finding confirms:

- Windows XP SP3;
- CVE-2017-0144;
- CVE-2019-0708;
- CVE-2008-4250;
- SMB open on port 445;
- RDP open on port 3389;
- no VLAN isolation;
- placement on the same subnet as ordinary workstations.

### Are the vulnerabilities exploitable specifically because the OS is EOL?

Yes. The vulnerabilities remain exploitable because the device cannot receive the normal security fixes and modern platform protections available to supported Windows systems.

EOL also means:

- no cumulative security updates;
- no modern exploit mitigations;
- likely dependence on SMBv1 and legacy protocols;
- limited compatibility with current endpoint security;
- increasing difficulty validating secure configuration.

## Compensating Controls

The exact 1x00 T6 document was not available with this task. The scan itself recommends network isolation for medical devices, and the most likely compensating controls for the MRI are:

- dedicated medical-device VLAN;
- firewall allowlisting;
- block SMB and RDP except where operationally essential;
- permit communication only with approved radiology workstations and the PACS server;
- use a hardened jump host for administration;
- monitor traffic with IDS/IPS;
- deploy application allowlisting where supported;
- restrict USB devices;
- maintain tested recovery images and configuration backups.

### Are those controls sufficient?

They reduce likelihood but do not remove the vulnerabilities. Isolation can prevent ordinary workstations from directly exploiting the MRI, but it does not protect against:

- an already compromised allowed radiology workstation;
- malicious USB media;
- vendor remote-access abuse;
- incorrect firewall rules;
- attacks using permitted protocols;
- insider access.

### Additional recommendations

1. Remove direct RDP access where possible.
2. Disable SMBv1 and block port 445 at the VLAN boundary.
3. Use one-way or tightly restricted PACS communication.
4. Apply virtual patching through an IPS.
5. Monitor every connection to and from the workstation.
6. Prevent internet access.
7. Develop a vendor-approved replacement plan.
8. Test clinical downtime procedures before migration.

---

# System 2 — Windows Server 2012 R2 Print Server

## System Information

- **Host:** `10.10.2.31`
- **Hostname:** `print-srv-01`
- **Role:** Central print server
- **Operating system:** Windows Server 2012 R2
- **Extended support ended:** 10 October 2023

## EOL Research

### NVD result count

A strict NVD search for **CVSS v3 Critical CVEs published between 20 July 2024 and 20 July 2026 and mapped to Windows Server 2012 R2 returned 0 Critical results in the reviewed search**.

However, multiple recent **High-severity** CVEs are explicitly mapped to Windows Server 2012 R2. This demonstrates that the operating system continues to accumulate important vulnerabilities even though ordinary support has ended.

### Two most severe recent examples

#### CVE-2025-49657

- Windows Routing and Remote Access Service heap-based buffer overflow
- Remote code execution over a network
- CVSS 8.8 High
- Published 8 July 2025
- Windows Server 2012 R2 is included in the affected CPE configurations

#### CVE-2025-49676

- Windows Routing and Remote Access Service heap-based buffer overflow
- Remote code execution over a network
- CVSS 8.8 High
- Published 8 July 2025
- Windows Server 2012 R2 is included in the affected CPE configurations

Another important example is **CVE-2025-24045**, a network-reachable Remote Desktop Services RCE rated CVSS 8.1 High.

## Permanent Exposure

A normally unpatched server can return to a supported state by installing current vendor fixes. An EOL server no longer receives ordinary security updates. Windows Server 2012 R2 may receive some fixes only if the organization has purchased and correctly deployed Extended Security Updates, but the scan states that security patches are no longer being provided in the present environment.

Without migration or an ESU arrangement, patching alone cannot provide a sustainable solution.

## Scan Findings

### Finding 008 — Windows Server 2012 R2 End-of-Life

The finding confirms:

- EOL operating system;
- Print Spooler service running;
- exposure to the PrintNightmare vulnerability family;
- public PoC and weaponized exploit availability.

The report specifically references:

- **CVE-2021-34527 — PrintNightmare**
- CVSS 8.8
- remote code execution/local privilege escalation potential.

### Are the vulnerabilities exploitable specifically because the OS is EOL?

The PrintNightmare weakness is not caused by EOL status, but EOL makes remediation and future protection more difficult. If the server lacks ESU coverage, newly disclosed Windows and Print Spooler vulnerabilities may remain unpatched.

The server's role also increases exposure because clients must communicate with the Print Spooler service.

## Compensating Controls

Recommended controls include:

- isolate the print server in a server VLAN;
- restrict RPC/SMB and print traffic to approved clients;
- disable the Print Spooler if central printing is not required;
- restrict driver installation to administrators;
- disable Point and Print exceptions;
- monitor spooler service changes;
- apply Windows Server 2012 R2 ESU patches if licensed;
- prevent interactive user logon;
- deploy EDR.

### Are those controls sufficient?

They can reduce exposure but do not provide a permanent solution. Printing requires the vulnerable service to remain reachable, so the attack surface cannot be completely removed while the server continues in its present role.

### Additional recommendations

1. Migrate print queues to a supported Windows Server version.
2. Use modern universal print services where appropriate.
3. Remove unused drivers and queues.
4. Allow administration only through a hardened management network.
5. Review whether the print server genuinely needs internet access.
6. Establish an accelerated replacement deadline.

---

# System 3 — Ubuntu 18.04 Billing Server Without ESM

## System Information

- **Host:** `10.10.2.15`
- **Hostname:** `billing-srv-01`
- **Role:** Billing application server with Apache, MySQL, financial and billing data
- **Operating system:** Ubuntu 18.04.6 LTS
- **Standard support ended:** June 2023
- **Ubuntu Pro/ESM:** Not activated

## EOL Research

### NVD result count

A strict NVD operating-system CPE search for **Critical CVEs published between 20 July 2024 and 20 July 2026 and mapped directly to Ubuntu 18.04 LTS did not provide a stable, complete count suitable for treating as the server's full exposure**.

This is because Ubuntu exposure is primarily package based. A single Ubuntu installation contains hundreds of packages, and a CVE may be mapped to Apache, OpenSSH, the Linux kernel, `apport`, `glibc`, MySQL, or another component rather than only to the Ubuntu 18.04 CPE.

The correct operational count must therefore come from the installed package inventory and Canonical's Ubuntu Security Notices, not from an OS-name search alone.

### Two notable recent examples

#### CVE-2025-5054 — Apport race condition

- Ubuntu 18.04 is listed among affected operating systems
- Local attacker may obtain sensitive information from core dumps
- CNA CVSS 4.7 Medium
- Public proof-of-concept information exists
- Fixed Ubuntu 18.04 package is delivered through ESM

This example is important because the ESM fix exists, but `billing-srv-01` is not enrolled.

#### CVE-2024-6387 — OpenSSH “regreSSHion”

- Signal-handler race condition in OpenSSH server
- Potential unauthenticated remote code execution on affected Linux systems
- CVSS 8.1 High
- Published in July 2024
- Exact exposure depends on the installed OpenSSH build and Canonical patch status

The two examples show why package-level verification is necessary.

## Permanent Exposure

Ubuntu 18.04 is different from fully abandoned Windows XP because Canonical still offers Extended Security Maintenance through Ubuntu Pro. However, MedDefense has not enabled ESM, so the server is effectively outside its available security-update channel.

The risk cannot be closed through ordinary `apt update` alone. MedDefense must either activate ESM temporarily or migrate the server to a supported Ubuntu release. ESM should be treated as a bridge, not a permanent substitute for modernization.

## Scan Findings

The billing server has the highest concentration of findings in the scan.

### Finding 001

- CVE-2021-44790
- Apache `mod_lua` buffer overflow
- unauthenticated remote code execution
- CVSS 9.8

### Finding 002

- CVE-2019-0211
- Apache local privilege escalation
- can chain with Finding 001 to gain root access

### Finding 006

- MySQL bound to `0.0.0.0`
- database reachable from the internal network

### Finding 009

- SSH password authentication enabled
- no account lockout
- brute-force exposure

### Finding 011

- Ubuntu 18.04 outside standard support
- ESM not activated
- last `apt update` 42 days before the scan

### Finding 026

- outdated Linux kernel
- 47 known CVEs with patches available
- local privilege-escalation exposure

### Are any exploitable specifically because the OS is EOL?

Yes, especially Findings 011 and 026. The absence of ESM prevents the server from receiving security fixes that may already exist.

Findings 001 and 002 are Apache vulnerabilities rather than Ubuntu design flaws, but the unsupported platform explains why old vulnerable packages remain installed. The EOL state turns fixable package vulnerabilities into continuing exposure.

## Compensating Controls

Recommended controls include:

- activate Ubuntu Pro/ESM immediately;
- restrict Apache access to required networks;
- remove or disable `mod_lua` if not required;
- restrict MySQL to localhost or named application hosts;
- require SSH keys;
- disable SSH password authentication;
- deploy a host firewall;
- install EDR/file-integrity monitoring;
- centralize logs;
- rebuild the server from a trusted image because of the crypto-miner compromise history;
- segment billing from ordinary workstations.

### Are those controls sufficient?

They materially reduce risk but are not sufficient as a long-term strategy. The server has multiple chainable findings:

```text
Finding 001 remote execution
        ↓
Finding 002 privilege escalation
        ↓
root control
        ↓
Finding 006 database access
```

The server's compromise history also means configuration hardening cannot prove that the host is trustworthy. A clean rebuild and migration are preferable.

### Additional recommendations

1. Enroll in ESM as an emergency bridge.
2. Patch Apache and the kernel immediately.
3. Rebuild rather than simply clean the existing host.
4. Migrate the billing application to a supported Ubuntu LTS.
5. Rotate application, database and SSH credentials.
6. inspect for persistence, cron jobs, SSH keys and altered binaries.
7. validate backups before migration.

---

# Comparison

| System | Business Role | Main Exposure | Patch Path | Overall Risk |
|---|---|---|---|---|
| Windows XP MRI | Direct clinical imaging control | Multiple weaponized unauthenticated RCEs; flat network | No normal patch path | Critical |
| Windows Server 2012 R2 Print Server | Enterprise printing | Print Spooler and continuing Windows flaws | ESU may be possible, otherwise migration | High |
| Ubuntu 18.04 Billing Server | Billing application and financial data | Six findings, RCE-to-root chain, unsupported packages | ESM available as temporary bridge | Critical |

---

# Business Decision

## Recommended first migration: Windows XP MRI workstation

If MedDefense can migrate only one of the three systems in the next quarter, it should prioritize **`WS-RAD-01`, the Windows XP MRI workstation**.

## Justification

### Asset criticality

The MRI workstation directly supports patient diagnosis and treatment workflows. Its availability is clinically critical, while unauthorized changes could affect medical-device operation or imaging integrity.

### Threat exposure

The host has:

- three confirmed, mature remote-code-execution vulnerabilities;
- open SMB and RDP ports;
- CISA KEV-listed vulnerabilities;
- no VLAN isolation;
- placement beside normal user workstations;
- no remaining vendor security-patch path.

A ransomware affiliate that compromises one workstation could use SMB or RDP exploitation to disrupt MRI services.

### Why not migrate billing first?

The billing server is also Critical and has the clearest multi-stage compromise chain. However, MedDefense can immediately reduce its risk by:

- activating Ubuntu ESM;
- patching Apache and the kernel;
- disabling `mod_lua`;
- restricting MySQL;
- enforcing SSH keys;
- rebuilding onto a supported Ubuntu release shortly afterward.

Ubuntu 18.04 therefore still has a temporary technical bridge.

### Why not migrate the print server first?

The print server is important, but its business impact is lower than loss of MRI operations or compromise of billing data. It can also be isolated, tightly filtered, enrolled in ESU if available, or temporarily replaced with alternative print services.

### Final decision

The Windows XP MRI workstation represents the least manageable risk:

- highest clinical availability impact;
- mature weaponized exploits;
- weak network placement;
- no sustainable patch option;
- dependence on a permanently unsupported operating system.

Therefore, it should receive the first migration budget. The billing server should be rebuilt and enrolled in ESM immediately as a parallel emergency action, while the print server should be isolated and scheduled next.

---

# Conclusion

End-of-life risk is not a one-time missing patch. It is a permanently weakening security position. Compensating controls can reduce the probability of exploitation, but they cannot restore vendor support, modern security architecture or confidence that future vulnerabilities will be fixed. MedDefense should use isolation and virtual patching only as temporary measures tied to funded migration deadlines.
