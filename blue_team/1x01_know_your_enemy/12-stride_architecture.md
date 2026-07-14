# STRIDE Across the Architecture

---

# System: PACS / Medical Imaging

**Architecture Notes:** PACS server (pacs-srv-01), MRI workstation running Windows XP, radiology workstations connected through the flat internal network.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| S | Shared PACS credentials allow user impersonation. | Unauthorized access to medical images. | High |
| T | Medical images can be modified by an attacker. | Incorrect diagnosis or treatment decisions. | Critical |
| R | Shared accounts prevent accountability. | User actions cannot be traced. | High |
| I | Patient imaging data is exposed. | HIPAA violation and privacy breach. | Critical |
| D | Ransomware encrypts the PACS server. | Imaging services become unavailable. | Critical |
| E | Windows XP vulnerabilities allow privilege escalation. | Full compromise of the radiology environment. | Critical |

**Top Threat:** Denial of Service (D) is the most dangerous because ransomware could make medical imaging unavailable, directly affecting patient care.

---

# System: Active Directory

**Architecture Notes:** ad-dc-01 and ad-dc-02 provide authentication and authorization for the entire MedDefense environment.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| S | Stolen administrator credentials. | Attackers impersonate domain administrators. | Critical |
| T | Group Policies are modified maliciously. | Malware can be deployed across all systems. | Critical |
| R | Poor logging limits accountability. | Malicious actions cannot be investigated properly. | High |
| I | Active Directory database is exposed. | User accounts and sensitive information are leaked. | High |
| D | Domain Controllers become unavailable. | Users cannot authenticate to critical systems. | Critical |
| E | Privilege escalation to Domain Admin. | Complete control of the environment. | Critical |

**Top Threat:** Elevation of Privilege (E) is the most dangerous because compromising Domain Admin gives attackers control over the entire organization.

---

# System: Network Infrastructure

**Architecture Notes:** FortiGate firewall, core switch, Westside consumer router and VPN connectivity. No internal network segmentation.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| S | VPN credentials are stolen. | Unauthorized remote network access. | High |
| T | Firewall or router configuration is modified. | Security controls are bypassed. | Critical |
| R | Configuration changes are not logged properly. | Difficult to investigate incidents. | Medium |
| I | Network traffic is intercepted. | Sensitive information is exposed. | High |
| D | Firewall or VPN is overwhelmed or disabled. | Loss of connectivity between sites. | Critical |
| E | Administrator privileges obtained on network devices. | Full control of network traffic. | Critical |

**Top Threat:** Tampering (T) is the most dangerous because changing firewall or VPN configurations can bypass security controls and expose the entire MedDefense network.
