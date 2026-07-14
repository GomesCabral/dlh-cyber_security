# MedDefense Attack Surface Map

## Section 1: External Surface

| Entry Point | Asset | Existing Protection | Documented Gap |
|-------------|-------|--------------------|----------------|
| Patient Portal | web-srv-01 | Firewall, HTTPS | GAP-006 – Public-facing services may contain unpatched vulnerabilities. |
| VPN Endpoint (FortiGate) | Remote Access Gateway | Firewall, VPN authentication | GAP-004 – Lack of network segmentation increases impact if compromised. |
| Microsoft 365 Email | O365 Email Platform | Password Policy, Email Security | GAP-011 – No automated account lifecycle management. |
| Public Website | web-srv-01 | Firewall | GAP-006 – Web application vulnerabilities may be exploited. |
| DNS Services | ad-dc-01 / ad-dc-02 | Firewall Rules | GAP-007 – No centralized monitoring of DNS activity. |

---

## Section 2: Internal Surface

| Asset | Exposure | Why It Matters |
|-------|----------|----------------|
| billing-srv-01 | MySQL (TCP 3306) accessible from the entire network | Any compromised workstation can attempt to access the database because the network is flat. |
| ehr-db-01 | PostgreSQL (TCP 5432) accessible from the entire network | Sensitive patient records become reachable after any internal compromise. |
| NAS-01 | Management Interface (TCP 5000/5001) | Attackers could target backups from anywhere inside the network. |
| Medical IoT Devices | HTTP/HTTPS Management Interfaces | Patient monitors and infusion pumps are reachable from general workstations. |
| WS-RAD-01 (MRI) | Windows XP Embedded | Unsupported operating system vulnerable to known exploits. |
| print-srv-01 | Windows Server 2012 R2 | End-of-life operating system no longer receiving security updates. |
| Medical Devices | Default or weak management credentials | Unauthorized users may gain administrative access. |
| Entire Internal Network | No Network Segmentation | Once an attacker gains access, lateral movement across servers, workstations and medical devices is unrestricted. |

---

## Section 3: Human Surface

| Role | Access | Why Targetable | Related Gap |
|------|--------|----------------|-------------|
| Clinical Staff | EHR and patient records | Busy environment and frequent access to sensitive information make phishing more effective. | GAP-002 – Unattended EHR sessions. |
| Reception Staff | Patient registration systems | First point of contact for visitors and external communications. | GAP-002 – Weak session management. |
| IT Staff | Administrative systems, servers and Active Directory | High privileges make them valuable phishing and credential theft targets. | GAP-007 – Limited monitoring of privileged activity. |
| Executives | Financial approvals and strategic information | Primary targets for Business Email Compromise (BEC). | GAP-011 – Weak identity management and account controls. |
| External Contractors | Vendor maintenance access | Third-party access extends trust beyond MedDefense's direct control. | GAP-010 – Third-party supply chain risk. |

---

# Surface Assessment Summary

The internal attack surface represents the greatest risk for MedDefense because the network is flat and critical systems, databases and medical devices are accessible across the internal environment. Once an attacker compromises a single endpoint through phishing, a vulnerable server or stolen credentials, they can move laterally with few technical barriers. This significantly increases the impact of ransomware, insider threats and opportunistic attacks.
