# 18. Threat–Vulnerability Correlation

## Threat–Vulnerability Correlation Matrix

| Finding | Threat Actor(s) | Attack Vector | Kill Chain Position | Attack Scenario | Related Gap (1x00) |
|---------|-----------------|---------------|---------------------|-----------------|-------------------|
| **004 – CVE-2019-0708 (BlueKeep)** | Ransomware groups, Cybercriminals | Network-based (RDP) | Initial Access → Lateral Movement → Impact | An attacker compromises an internal workstation, exploits BlueKeep on the MRI workstation, then disrupts clinical operations and spreads ransomware. | Legacy Windows XP system, no network segmentation, unsupported OS. |
| **031 – CVE-2020-1938 (Ghostcat)** | Cybercriminals, Ransomware operators, APT groups | Network-based (Tomcat AJP) | Initial Access → Credential Access → Collection | Ghostcat exposes configuration files containing database credentials, allowing access to the EHR database and patient records. | Flat network, exposed AJP service, weak internal segmentation. |
| **001 – CVE-2021-44790 (Apache mod_lua RCE)** | Cybercriminals, Ransomware groups | Web-based | Initial Access | Remote code execution on the billing server provides an initial foothold for further privilege escalation. | Outdated Apache version, unsupported Ubuntu installation. |
| **002 – CVE-2019-0211 (Apache Privilege Escalation)** | Cybercriminals | Local privilege escalation | Privilege Escalation | Used immediately after Finding 001 to obtain root access on the billing server. | Lack of timely patching and unsupported operating system. |
| **010 – BD Alaris Pumps** | Insider threat, Ransomware groups | Network-based / Medical IoT | Impact | Default credentials and flat network access allow attackers to interfere with infusion pumps or deny their availability. | Default credentials, lack of medical-device VLAN, weak access controls. |
| **029 – Grafana Path Traversal** | Cybercriminals, Advanced Persistent Threat (APT) | Web-based | Initial Access → Credential Access | Arbitrary file disclosure exposes credentials that may allow movement from Westside Clinic into the main MedDefense network. | Unknown unmanaged asset, shadow IT, weak asset inventory. |
| **008 – PrintNightmare (Print Server)** | Ransomware groups | Network-based | Privilege Escalation → Lateral Movement | Compromise of the print server enables movement through the Windows environment toward domain controllers. | Windows Server 2012 R2 EOL, Print Spooler enabled. |
| **005 – Weak TLS Configuration** | Cybercriminals | Network-based | Initial Access (supporting) | Weak TLS enables downgrade or interception attacks against the patient portal, especially when combined with phishing or session theft. | Weak cryptographic configuration, missing hardening controls. |

---

# Threat Context Assessment

Considering threat actor capability, attack path, exploit availability and asset criticality, **Finding 031 (Ghostcat on the EHR server)** represents the greatest overall organizational risk.

Although several findings have similar CVSS scores, Ghostcat directly affects the Electronic Health Record environment, where confidentiality, integrity and availability are all critical. The vulnerability has public exploit code, appears in known attack campaigns, and allows attackers to retrieve configuration files containing database credentials. Combined with the flat network architecture and unrestricted database access identified elsewhere in the scan, a successful compromise could lead to theft of protected health information, ransomware deployment, interruption of clinical operations and regulatory penalties. The attack requires relatively little sophistication compared to the potential business impact, making it the highest-priority vulnerability when technical severity is combined with real-world threat intelligence and organizational context.
