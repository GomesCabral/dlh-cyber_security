# 20. Priority Matrix

This priority matrix organizes all **Actionable Critical (AC)** and **Actionable Standard (AS)** findings into practical remediation timelines based on exploitability, asset criticality, operational impact and implementation complexity.

---

# Immediate (24–48 Hours)

**Criteria:** Weaponized exploit, critical asset, active threat, or high likelihood of exploitation.

| Finding | Description | Remediation Action | Owner | Estimated Cost |
|---------|-------------|-------------------|-------|---------------|
| 001 | Apache mod_lua Remote Code Execution (billing-srv-01) | Patch Apache to the latest supported version and verify mod_lua configuration. | Linux Server Team | $0–1K |
| 002 | Apache Privilege Escalation (billing-srv-01) | Apply Apache security update together with Finding 001. | Linux Server Team | $0–1K |
| 003 | PostgreSQL accepts connections from entire internal network | Restrict PostgreSQL access to approved application servers only. | Database Administration | $0–1K |
| 004 | Windows XP MRI workstation (BlueKeep and EOL) | Immediately isolate the workstation using firewall rules and a dedicated VLAN. | Security + Clinical Engineering | $1–10K |
| 007 | LDAP Signing Disabled / SMBv1 Enabled (ad-dc-01) | Enable LDAP signing and disable SMBv1 after compatibility testing. | Windows Infrastructure Team | $0–1K |
| 010 | BD Alaris infusion pumps with default credentials | Replace default credentials, validate firmware and restrict network access. | Clinical Engineering + Vendor | $1–10K |
| 015 | Synology NAS management interface exposed | Restrict DSM access, encrypt backup storage and limit administrative access. | Infrastructure Team | $1–10K |
| 016 | Philips IntelliVue monitors exposed on flat network | Move devices into a medical VLAN and restrict HL7/Web management access. | Clinical Engineering + Network Team | $10–50K |
| 028 | Unknown Linux device exposing Jupyter/Cockpit | Isolate, identify owner and remove unauthorized services. | Security Operations | $0–1K |
| 029 | Unknown Grafana server | Patch Grafana immediately and investigate ownership. | IT Operations | $0–1K |
| 031 | Ghostcat (Tomcat AJP) on EHR server | Disable AJP or patch Tomcat immediately. | IT Operations | $0–1K |

---

# Short-Term (7 Days)

**Criteria:** High/Critical vulnerability with public Proof of Concept or affecting important infrastructure.

| Finding | Description | Remediation Action | Owner | Estimated Cost |
|---------|-------------|-------------------|-------|---------------|
| 006 | MySQL exposed to entire internal network | Restrict MySQL binding and firewall access. | Database Team | $0–1K |
| 008 | Windows Server 2012 R2 Print Server (PrintNightmare / EOL) | Apply Microsoft updates and begin migration planning. | Windows Team | $0–1K |
| 009 | SSH password authentication enabled | Disable password authentication and enforce SSH keys. | Linux Team | $0–1K |
| 011 | Ubuntu 18.04 without ESM | Enable Ubuntu Pro/ESM or plan upgrade to a supported LTS release. | Linux Team | $1–10K |
| 017 | Tomcat information disclosure | Remove unnecessary version disclosure and secure server configuration. | Application Team | $0–1K |
| 018 | Weak Kerberos encryption (DES/RC4) | Disable weak encryption algorithms after compatibility validation. | Active Directory Team | $0–1K |
| 027 | Endpoint protection inactive on multiple systems | Restore endpoint protection agents and verify reporting. | Desktop Support | $1–10K |

---

# Medium-Term (30 Days)

**Criteria:** Medium or High vulnerabilities, security misconfigurations and defense improvements.

| Finding | Description | Remediation Action | Owner | Estimated Cost |
|---------|-------------|-------------------|-------|---------------|
| 005 | Weak TLS configuration | Disable TLS 1.0/1.1 and weak cipher suites. | Web Team | $0–1K |
| 012 | Missing HTTP security headers | Implement HSTS, CSP, X-Frame-Options and related headers. | Web Team | $0–1K |
| 013 | SSL certificate expires soon | Renew certificate and automate certificate monitoring. | Web Team | $0–1K |
| 014 | Consumer-grade VPN router | Replace with enterprise firewall or managed VPN appliance. | Network Team | $10–50K |
| 019 | RDP enabled on multiple hosts | Restrict RDP through firewall rules and administrative jump hosts. | Windows Team | $1–10K |
| 021 | HTTP TRACE enabled | Disable the HTTP TRACE method. | Web Team | $0–1K |
| 023 | USB storage unrestricted | Apply Group Policy to restrict removable storage. | Desktop Support | $1–10K |
| 024 | Unencrypted DICOM communications | Enable DICOM TLS where supported or isolate imaging systems. | Clinical Engineering | $10–50K |
| 025 | DNS zone transfers unrestricted | Restrict zone transfers to authorized DNS servers only. | Infrastructure Team | $0–1K |
| 026 | Outdated Linux kernel | Apply kernel updates during scheduled maintenance. | Linux Team | $0–1K |

---

# Long-Term (90 Days)

**Criteria:** Architectural improvements, legacy migrations and strategic security projects.

| Project | Description | Remediation Action | Owner | Estimated Cost |
|---------|-------------|-------------------|-------|---------------|
| Network Segmentation | Flat internal network | Implement VLAN segmentation for servers, users and medical devices. | Network Team | $50K+ |
| Windows XP Replacement | MRI workstation | Replace unsupported Windows XP platform with vendor-supported hardware/software. | Clinical Engineering + Vendor | $50K+ |
| Windows Server 2012 Migration | Print Server | Replace with a supported Windows Server version. | Windows Infrastructure | $10–50K |
| Ubuntu 18.04 Migration | Billing server | Upgrade to Ubuntu 24.04 LTS or another supported release. | Linux Team | $10–50K |
| Medical Device Lifecycle Program | Medical IoT | Develop a long-term replacement and firmware-management program for legacy medical devices. | Clinical Engineering | $50K+ |

---

# Budget Summary

| Horizon | Estimated Cost |
|----------|---------------:|
| Immediate | ~$30,000 |
| Short-Term | ~$15,000 |
| Medium-Term | ~$35,000 |
| Long-Term | ~$160,000 |
| **Estimated Total** | **~$240,000** |

The estimated remediation cost is approximately **$240,000**, which is **about twice** MedDefense's annual security budget of **$120,000**.

Because of this budget limitation, remediation must be prioritized. Immediate and short-term actions focus on vulnerabilities with public exploits, critical assets and active attack paths. Long-term projects such as network segmentation, replacement of Windows XP medical systems and migration of legacy servers require significant capital investment and should be planned across future budget cycles. Until these projects are completed, compensating controls such as network segmentation through firewalls, strict access controls, continuous monitoring and enhanced logging should be used to reduce residual risk.
