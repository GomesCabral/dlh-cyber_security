# 14. The Network Posture

## Purpose

This analysis shows how MedDefense's flat `10.10.0.0/16` network increases the practical risk of vulnerabilities that would otherwise be more contained.

The three selected CVEs affect different systems and business functions:

1. `CVE-2021-44790` — Billing application server
2. `CVE-2020-1938` — EHR application server
3. `CVE-2019-0708` — MRI workstation

---

# 1. CVE-2021-44790 — Apache mod_lua Buffer Overflow

## CVE

**CVE-2021-44790**

## Host

**10.10.2.15 — billing-srv-01**

## CVSS Base Score

**9.8 Critical**

Vector:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

---

## Scenario A — Current Flat Network

### Who Can Reach This Vulnerability

Any compromised host anywhere in the internal `10.10.0.0/16` environment may be able to reach the Apache service on `billing-srv-01`, unless a local host firewall blocks it.

This potentially includes:

- employee workstations;
- reception systems;
- clinical workstations;
- nurse stations;
- medical devices;
- unknown or unmanaged Linux devices;
- Westside Clinic systems through the VPN;
- other servers.

An attacker does not need direct internet access to the billing server. A single compromised endpoint may provide the necessary internal position.

### What the Attacker Can Reach After Exploitation

Successful exploitation may provide code execution as the Apache service account.

From that position, the attacker may:

- exploit Finding 002 to escalate to root;
- access local billing application files;
- obtain MySQL credentials;
- connect to systems throughout the flat network;
- target the EHR environment;
- attack Active Directory;
- reach backup systems;
- scan and attack medical devices;
- establish persistence;
- deploy ransomware across multiple subnets.

The effective impact radius is the entire internal environment.

### Effective Risk

**Critical**

The CVSS score already assumes network reachability and total CIA impact. The flat network adds organizational reach, making this vulnerability a potential enterprise-wide foothold rather than only a billing-server compromise.

---

## Scenario B — Hypothetical Segmented Network

### Who Can Reach This Vulnerability

Only systems in the billing application VLAN or specifically approved systems would be allowed to reach Apache.

For example:

- approved employee browsers;
- a reverse proxy;
- an application load balancer;
- administrative hosts.

Clinical devices, nurse workstations, medical-device VLANs, backup systems and the EHR database would not have direct access.

### What the Attacker Can Reach After Exploitation

The attacker would initially be limited to:

- `billing-srv-01`;
- other approved billing-segment systems;
- explicitly permitted application or database connections.

To reach Active Directory, EHR, medical devices or backup systems, the attacker would need to:

- find an allowed firewall path;
- steal credentials;
- compromise a dual-homed system;
- exploit a firewall or management system;
- bypass segmentation controls.

### Effective Risk

**High to Critical**

The vulnerable server is still a high-value financial asset and the RCE remains serious. However, the blast radius is substantially reduced.

---

## Risk Amplification Factor

**Approximately 3×**

This is a qualitative estimate, not a mathematical CVSS multiplier.

The flat network increases risk by:

1. increasing the number of systems that can attempt exploitation;
2. allowing the compromised server to reach many unrelated assets;
3. enabling attack chaining with Active Directory, EHR, NAS and medical devices.

---

# 2. CVE-2020-1938 — Ghostcat

## CVE

**CVE-2020-1938**

## Host

**10.10.2.10 — ehr-srv-01**

## CVSS Base Score

**9.8 Critical**

Vector from the scan:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
```

---

## Scenario A — Current Flat Network

### Who Can Reach This Vulnerability

Any compromised host on the internal `10.10.0.0/16` network may be able to reach the AJP service on port 8009.

This includes ordinary user endpoints and unmanaged devices that should not require access to the EHR application connector.

### What the Attacker Can Reach After Exploitation

Ghostcat may allow the attacker to read:

- Tomcat configuration files;
- application secrets;
- database credentials;
- internal paths;
- service account information.

The attacker can then combine the result with Finding 003:

- PostgreSQL accepts connections from the entire internal network;
- the attacker can connect directly to `ehr-db-01`;
- patient data may be read, altered, encrypted or exfiltrated.

From the EHR server, the attacker may also scan or target:

- domain controllers;
- billing servers;
- backup infrastructure;
- PACS;
- clinical workstations;
- medical devices.

### Effective Risk

**Critical**

The flat network converts Ghostcat from an internal application-server vulnerability into a realistic patient-data breach chain.

---

## Scenario B — Hypothetical Segmented Network

### Who Can Reach This Vulnerability

Only approved systems in the EHR application VLAN would be allowed to reach AJP, ideally only localhost or a specific reverse proxy.

Ordinary workstations, medical devices and unrelated servers would be blocked from port 8009.

### What the Attacker Can Reach After Exploitation

Even if the EHR application server were compromised, the attacker would be limited to:

- the EHR application VLAN;
- the database connection explicitly permitted to `ehr-db-01`;
- approved logging, backup and authentication paths.

Firewall rules could prevent access to:

- medical-device networks;
- billing systems;
- user VLANs;
- backup management;
- administrative interfaces.

### Effective Risk

**High**

Patient data would still be at risk because the application server legitimately communicates with the database. However, the attacker would have fewer initial paths and a much smaller lateral-movement radius.

---

## Risk Amplification Factor

**Approximately 4×**

Ghostcat is especially amplified by the flat network because:

- any compromised endpoint can attack AJP;
- the unrestricted database configuration creates a direct second-stage target;
- the attacker can move from application disclosure to enterprise-wide reconnaissance.

---

# 3. CVE-2019-0708 — BlueKeep

## CVE

**CVE-2019-0708**

## Host

**10.10.1.70 — WS-RAD-01 MRI Workstation**

## CVSS Base Score

**9.8 Critical**

Vector:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

---

## Scenario A — Current Flat Network

### Who Can Reach This Vulnerability

Any compromised host in the internal environment may be able to connect to RDP on port 3389.

The scan confirms:

- RDP is open;
- the workstation runs unsupported Windows XP;
- there is no VLAN isolation;
- it shares the subnet with normal workstations.

A phishing compromise of one user workstation may therefore provide a direct path to the MRI control workstation.

### What the Attacker Can Reach After Exploitation

After compromising `WS-RAD-01`, the attacker may:

- disrupt MRI operations;
- use the workstation as persistence inside the clinical network;
- scan nearby clinical endpoints;
- attack PACS or radiology workstations;
- capture unencrypted DICOM traffic;
- move toward servers in the flat network;
- deploy ransomware or destructive malware.

The impact radius includes both clinical operations and the broader enterprise network.

### Effective Risk

**Critical**

The vulnerability affects an unsupported medical workstation and may directly affect patient-care availability.

---

## Scenario B — Hypothetical Segmented Network

### Who Can Reach This Vulnerability

Only approved radiology administration systems or a hardened jump host would be able to reach RDP.

Normal workstations, reception systems, guest devices and unrelated server VLANs would be blocked.

### What the Attacker Can Reach After Exploitation

The attacker would be restricted to the medical-device or radiology VLAN.

Firewall rules should allow only necessary traffic to:

- PACS;
- specific radiology workstations;
- monitoring systems;
- vendor support gateways.

The attacker would need to bypass a firewall to reach the EHR, billing server, Active Directory or backups.

### Effective Risk

**High to Critical**

The MRI workstation itself remains critically vulnerable and clinically important. Segmentation cannot fix Windows XP, but it can significantly reduce the number of attackers who can reach it and the systems available after compromise.

---

## Risk Amplification Factor

**Approximately 5×**

This vulnerability receives the highest amplification estimate because the current architecture exposes a legacy clinical device to ordinary internal systems.

In a segmented design, only a few approved hosts should ever reach RDP. In the current design, compromise of many unrelated endpoints may provide a direct path.

---

# Comparison Summary

| CVE | Host | Flat Network Risk | Segmented Risk | Amplification |
|---|---|---|---|---:|
| CVE-2021-44790 | Billing server | Enterprise foothold and RCE-to-root chain | Mainly billing-segment compromise | ~3× |
| CVE-2020-1938 | EHR application server | Direct path from any internal host to EHR credentials and database | Restricted application/database path | ~4× |
| CVE-2019-0708 | MRI workstation | Any compromised endpoint may attack a clinical device | Only approved radiology systems can reach it | ~5× |

---

# Network Posture Summary

The flat network amplifies almost every finding in the scan by increasing both **reachability before exploitation** and **blast radius after exploitation**. Vulnerabilities on the billing server, EHR server, domain controllers, NAS, unknown devices and medical systems are not isolated problems because any compromised endpoint may become a launch point against them. After exploitation, the attacker can scan and move toward unrelated business and clinical assets with few architectural barriers.

Network segmentation is arguably more impactful than patching any single CVE because patching removes one attack path, while segmentation reduces the effective risk of many vulnerabilities at the same time. Proper VLANs, firewall allowlists and restricted management networks would reduce the number of systems that can reach vulnerable services, limit lateral movement, contain ransomware and protect legacy systems that cannot be patched. Segmentation does not replace patching, but it changes a single-host compromise from a possible organization-wide incident into a smaller and more manageable security event.
