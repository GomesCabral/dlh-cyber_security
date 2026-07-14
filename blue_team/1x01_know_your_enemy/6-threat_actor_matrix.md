# MedDefense Threat Actor Matrix

| Threat Actor | Likelihood | Capability | Primary Motivation | Preferred Vector | Primary Target | MedDefense Exposure |
|--------------|------------|------------|--------------------|------------------|----------------|---------------------|
| **Ransomware Groups (Organized Crime)** | **Critical** – Healthcare is the most targeted sector, and MedDefense matches the profile of a mid-size hospital with limited security resources. | High – Organized groups using Ransomware-as-a-Service, phishing, stolen credentials and known exploits. | Financial Gain | Phishing, VPN exploitation, vulnerable public-facing services, stolen credentials. | EHR System, Active Directory, Billing Server, Backup Infrastructure. | GAP-001 (Flat Network), GAP-003 (Unsupported Billing Server), GAP-004 (No Network Segmentation), GAP-007 (No Centralized Monitoring). |
| **Nation-State APT** | Low – MedDefense does not perform pharmaceutical research or clinical trials. | Very High – Custom malware, zero-day exploits and long-term persistence. | Espionage | Zero-day vulnerabilities and supply chain compromise. | EHR System and patient information. | GAP-004 (No Network Segmentation), GAP-007 (No Monitoring), GAP-010 (Third-Party Risk). |
| **Insider (Malicious)** | Medium – Healthcare frequently experiences intentional insider misuse involving patient information. | Medium – Legitimate access to internal systems. | Revenge or Financial Gain | Abuse of legitimate credentials, unauthorized data access. | EHR System, HR Records, Billing Data. | GAP-002 (Unattended Sessions), GAP-011 (No Automated Offboarding), GAP-013 (No DLP). |
| **Insider (Negligent)** | High – Clinical workflows encourage shortcuts and accidental security violations. | Low | Human Error | Shared accounts, Shadow IT, poor security practices. | Patient Records, Medical Devices, Internal Network. | GAP-002 (Unattended Sessions), GAP-005 (Shadow IT), GAP-011 (Account Management). |
| **Hacktivist** | Low – MedDefense has little political or public exposure. | Medium | Political or Ideological Beliefs | Website attacks, DDoS, web application exploitation. | Patient Portal and Public Website. | GAP-006 (Public-Facing Services), GAP-007 (No Monitoring). |
| **Unskilled / Opportunistic Attacker** | High – Automated internet scanning continuously targets vulnerable systems. | Low | Financial Gain | Automated exploitation of known vulnerabilities, weak passwords and exposed services. | Billing Server, Public Web Server, VPN. | GAP-003 (Unsupported Billing Server), GAP-006 (Public-Facing Vulnerabilities), GAP-007 (No Monitoring). |

---

# Top 3 Priority Ranking

## 1. Ransomware Groups (Organized Crime)

Ransomware groups represent the greatest threat because healthcare is currently the most targeted critical infrastructure sector. MedDefense has several weaknesses that match their preferred attack path, including a flat network, unsupported systems and limited detection capabilities. A successful attack would disrupt patient care, expose sensitive data and cause major financial losses.

---

## 2. Insider (Negligent)

Negligent insiders are highly likely because daily clinical operations involve broad access to sensitive patient information. Shared accounts, unattended EHR sessions and Shadow IT increase the risk of accidental data exposure or compromise. Even without malicious intent, these actions can result in serious security incidents.

---

## 3. Unskilled / Opportunistic Attacker

Opportunistic attackers constantly scan the internet for vulnerable systems without specifically targeting MedDefense. The previous cryptomining incident on **billing-srv-01** demonstrates that MedDefense has already been affected by this type of attacker. Unpatched systems and exposed services make future attacks highly likely.
