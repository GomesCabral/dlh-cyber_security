# 14. The Network Posture

## CVE Analysis 1

**CVE:** CVE-2021-44790

**Host:** 10.10.2.15 (`billing-srv-01`)

**CVSS Base Score:** 9.8 (Critical)

### Scenario A: Current (flat network)

**Who can reach this vulnerability:**
Any compromised host in the internal `10.10.0.0/16` network, including workstations, servers, medical devices and VPN-connected sites.

**What the attacker can reach AFTER exploitation:**
After remote code execution, the attacker can pivot to Active Directory, the EHR environment, the backup server, NAS, medical devices and other internal systems because the network is flat.

**Effective Risk:**
Critical. One compromised endpoint can become an enterprise-wide attack.

### Scenario B: Hypothetical (segmented network)

**Who can reach this vulnerability:**
Only systems inside the Billing VLAN or explicitly allowed through firewall rules.

**What the attacker can reach AFTER exploitation:**
Mainly the billing application and approved services. Reaching other environments would require crossing firewall rules or another successful compromise.

**Effective Risk:**
High. The vulnerability remains serious, but the blast radius is greatly reduced.

**Risk Amplification Factor:**
Approximately **3×** because the flat network allows both easier exploitation and unrestricted lateral movement.

---

## CVE Analysis 2

**CVE:** CVE-2020-1938 (Ghostcat)

**Host:** 10.10.2.10 (`ehr-srv-01`)

**CVSS Base Score:** 9.8 (Critical)

### Scenario A: Current (flat network)

**Who can reach this vulnerability:**
Any compromised internal host can reach the Tomcat AJP service.

**What the attacker can reach AFTER exploitation:**
The attacker may read configuration files, recover database credentials, access `ehr-db-01`, and continue moving to other critical systems.

**Effective Risk:**
Critical. The flat network enables a direct path from any compromised endpoint to patient records.

### Scenario B: Hypothetical (segmented network)

**Who can reach this vulnerability:**
Only approved systems inside the EHR application VLAN.

**What the attacker can reach AFTER exploitation:**
Primarily the EHR application and its approved database connection. Other VLANs would remain protected by firewalls.

**Effective Risk:**
High. Patient data is still at risk, but lateral movement is much harder.

**Risk Amplification Factor:**
Approximately **4×** because unrestricted internal connectivity makes exploitation and credential abuse significantly easier.

---

## CVE Analysis 3

**CVE:** CVE-2019-0708 (BlueKeep)

**Host:** 10.10.1.70 (`WS-RAD-01` MRI Workstation)

**CVSS Base Score:** 9.8 (Critical)

### Scenario A: Current (flat network)

**Who can reach this vulnerability:**
Any compromised internal system that can reach RDP (TCP 3389).

**What the attacker can reach AFTER exploitation:**
The attacker can compromise the MRI workstation, disrupt clinical services, attack nearby medical devices and pivot to servers across the internal network.

**Effective Risk:**
Critical. A compromise may affect both patient care and the wider enterprise.

### Scenario B: Hypothetical (segmented network)

**Who can reach this vulnerability:**
Only approved radiology administration systems inside the medical-device VLAN.

**What the attacker can reach AFTER exploitation:**
Only radiology systems and explicitly permitted services. Firewall rules would block access to the EHR, billing and other business systems.

**Effective Risk:**
High. The workstation remains vulnerable, but segmentation greatly limits attacker movement.

**Risk Amplification Factor:**
Approximately **5×** because the flat network exposes an unsupported clinical device to every compromised endpoint.

---

# Network Posture Summary

The flat network amplifies almost every vulnerability in the scan by increasing both the number of systems that can reach vulnerable services and the number of systems that can be reached after exploitation. A single compromised workstation can become a stepping stone to the billing server, EHR, Active Directory, NAS and medical devices.

Network segmentation is arguably more impactful than patching any single CVE because it reduces the effective risk of many vulnerabilities simultaneously. While patching removes one attack path, segmentation limits lateral movement, reduces the attack surface, protects legacy systems and contains incidents before they spread across the organization.
