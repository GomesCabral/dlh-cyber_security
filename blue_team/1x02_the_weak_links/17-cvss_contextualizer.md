# 17. The CVSS Contextualizer

## Scope and Method

This report recalculates eight actionable findings using CVSS v3.1 Temporal and Environmental metrics.

The following factors were applied:

- **CR / IR / AR:** Confidentiality, Integrity and Availability requirements
- **MAV:** Modified Attack Vector where MedDefense's real network placement differs from the base assumption
- **E:** Exploit Code Maturity
- **RL:** Remediation Level
- **RC:** Report Confidence

The separate 1x00 Asset Registry, 1x00 Criticality Matrix, 1x00 Control Matrix and 1x01 T10 kill chains were not available with this task. CIA ratings, kill-chain names and existing-control references are therefore **provisional**, inferred from the scan report, and should be replaced if the original project documents use different values.

CVSS measures technical severity. Final business priority may remain higher than the Environmental score when patient safety, attack chaining or regulatory impact are not fully represented by CVSS.

---

# Finding 004 - BlueKeep on MRI Workstation

**Finding:** 004 - CVE-2019-0708  
**CVSS Base Score:** 9.8 Critical

## Factor 1 - Asset Criticality

**Asset:** `WS-RAD-01`, Windows XP MRI control workstation  
**CIA Rating:** Provisional: C=High, I=Critical, A=Critical  
**Criticality Impact on Priority:** Raises urgency because compromise may disrupt medical imaging and patient care.

## Factor 2 - Kill Chain Position

**Appears in Kill Chain(s):** Provisional clinical ransomware/lateral-movement chain  
**Chain Role:** Lateral movement target and clinical impact point  
**Kill Chain Impact on Priority:** Raises urgency because any compromised workstation may attack the MRI through the flat network.

## Factor 3 - Exploitability

**Exploitability Score:** 5/5  
**CISA KEV:** Yes  
**Exploit Impact on Priority:** Raises urgency because public exploitation methods and real-world exploitation are confirmed.

## Factor 4 - Compensating Controls

**Existing Controls:** No VLAN isolation; RDP is open; no effective compensating control confirmed  
**Control Impact on Priority:** Does not lower urgency.

## Environmental CVSS (recalculated)

**Environmental Metrics Applied:** `CR:M/IR:H/AR:H/E:H/RL:O/RC:C`  
**Adjusted Score:** **9.4 Critical**

## Final Priority

**Critical**

## Final Justification

This vulnerability affects an unsupported clinical workstation, has mature public exploits, appears in CISA KEV and is reachable from ordinary internal systems. Although an official patch historically existed, MedDefense's EOL platform and lack of segmentation make reliable remediation difficult. The combination of exploit maturity, patient-safety impact and broad internal reach keeps this at Critical priority.

---

# Finding 031 - Ghostcat on EHR Server

**Finding:** 031 - CVE-2020-1938  
**CVSS Base Score:** 9.8 Critical

## Factor 1 - Asset Criticality

**Asset:** `ehr-srv-01`, Electronic Health Record application server  
**CIA Rating:** Provisional: C=Critical, I=Critical, A=Critical  
**Criticality Impact on Priority:** Raises urgency because the server supports clinical access to patient records.

## Factor 2 - Kill Chain Position

**Appears in Kill Chain(s):** Provisional EHR data-breach chain  
**Chain Role:** Credential-access and lateral-movement enabler  
**Kill Chain Impact on Priority:** Raises urgency because configuration files may reveal credentials for `ehr-db-01`.

## Factor 3 - Exploitability

**Exploitability Score:** 5/5  
**CISA KEV:** Yes  
**Exploit Impact on Priority:** Raises urgency because public PoCs and Metasploit support exist, and AJP was manually confirmed active.

## Factor 4 - Compensating Controls

**Existing Controls:** Internal-only exposure, but the network is flat and port 8009 is reachable  
**Control Impact on Priority:** Internal placement provides only limited mitigation and does not materially reduce urgency.

## Environmental CVSS (recalculated)

**Environmental Metrics Applied:** `CR:H/IR:H/AR:H/MAV:A/E:H/RL:O/RC:C`  
**Adjusted Score:** **8.4 High**

## Final Priority

**Critical**

## Final Justification

The Environmental score falls because AJP is internal rather than directly internet-facing and an official fix exists. However, the flat network, confirmed AJP exposure, KEV status, exploit tooling and direct path to EHR database credentials make the business priority Critical. This is a case where contextual risk is higher than the numeric Environmental severity.

---

# Finding 001 - Apache mod_lua Remote Code Execution

**Finding:** 001 - CVE-2021-44790  
**CVSS Base Score:** 9.8 Critical

## Factor 1 - Asset Criticality

**Asset:** `billing-srv-01`, billing application and financial-data server  
**CIA Rating:** Provisional: C=High, I=Critical, A=High  
**Criticality Impact on Priority:** Raises urgency because compromise may affect billing data, revenue operations and system availability.

## Factor 2 - Kill Chain Position

**Appears in Kill Chain(s):** Provisional billing-server compromise chain  
**Chain Role:** Initial exploitation and code-execution point  
**Kill Chain Impact on Priority:** Raises urgency because Finding 002 can immediately escalate the web-shell access to root.

## Factor 3 - Exploitability

**Exploitability Score:** 4/5  
**CISA KEV:** No  
**Exploit Impact on Priority:** Public exploit code raises urgency, although exploit reliability may require adaptation.

## Factor 4 - Compensating Controls

**Existing Controls:** No confirmed network restriction; service is reachable internally; unsupported Ubuntu platform  
**Control Impact on Priority:** Does not materially lower urgency.

## Environmental CVSS (recalculated)

**Environmental Metrics Applied:** `CR:H/IR:H/AR:H/E:F/RL:O/RC:C`  
**Adjusted Score:** **9.1 Critical**

## Final Priority

**Critical**

## Final Justification

This is unauthenticated network code execution on a high-value financial server. Public exploit code exists, the vulnerable module is confirmed loaded and Finding 002 creates a realistic RCE-to-root chain. The available vendor fix slightly lowers the recalculated score, but the asset role and chainability keep the final priority Critical.

---

# Finding 002 - Apache Privilege Escalation

**Finding:** 002 - CVE-2019-0211  
**CVSS Base Score:** 7.8 High

## Factor 1 - Asset Criticality

**Asset:** `billing-srv-01`  
**CIA Rating:** Provisional: C=High, I=Critical, A=High  
**Criticality Impact on Priority:** Raises urgency because root compromise would expose billing data and the entire operating system.

## Factor 2 - Kill Chain Position

**Appears in Kill Chain(s):** Provisional billing-server compromise chain  
**Chain Role:** Privilege-escalation step  
**Kill Chain Impact on Priority:** Strongly raises urgency because Finding 001 supplies the exact low-privileged access required.

## Factor 3 - Exploitability

**Exploitability Score:** 5/5 in the MedDefense chain  
**CISA KEV:** Yes  
**Exploit Impact on Priority:** Raises urgency due to public exploit code and confirmed real-world exploitation.

## Factor 4 - Compensating Controls

**Existing Controls:** Local access is required, but Finding 001 defeats this practical barrier  
**Control Impact on Priority:** The normal local-access limitation does not lower urgency in this environment.

## Environmental CVSS (recalculated)

**Environmental Metrics Applied:** `CR:H/IR:H/AR:H/E:H/RL:O/RC:C`  
**Adjusted Score:** **7.5 High**

## Final Priority

**Critical as part of the chain**

## Final Justification

The numerical score remains High because CVSS evaluates this as a local privilege-escalation vulnerability. In MedDefense, however, Finding 001 provides a direct remote path to the required local context. KEV status, public exploit availability and the root-level impact on the billing server justify Critical remediation when Findings 001 and 002 are treated as one chain.

---

# Finding 010 - BD Alaris Availability Vulnerability

**Finding:** 010 - CVE-2020-25165  
**CVSS Base Score:** 7.5 High

## Factor 1 - Asset Criticality

**Asset:** BD Alaris infusion pumps  
**CIA Rating:** Provisional: C=Medium, I=Critical, A=Critical  
**Criticality Impact on Priority:** Strongly raises urgency because availability or integrity failures may affect medication delivery and patient safety.

## Factor 2 - Kill Chain Position

**Appears in Kill Chain(s):** Provisional medical-device disruption chain  
**Chain Role:** Final clinical target and impact point  
**Kill Chain Impact on Priority:** Raises urgency because a compromised workstation can reach the pumps through the flat network.

## Factor 3 - Exploitability

**Exploitability Score:** 3/5 pending firmware validation  
**CISA KEV:** No  
**Exploit Impact on Priority:** The CVE association may be a false version match, but default credentials are independently confirmed.

## Factor 4 - Compensating Controls

**Existing Controls:** No dedicated VLAN; default credentials remain; no effective access restriction  
**Control Impact on Priority:** Does not lower urgency.

## Environmental CVSS (recalculated)

**Environmental Metrics Applied:** `CR:L/IR:H/AR:H/MAV:A/E:P/RL:O/RC:C`  
**Adjusted Score:** **7.5 High**

## Final Priority

**Critical**

## Final Justification

The technical CVE requires validation because vendor information suggests firmware 12.1.2 may already include the fix. Nevertheless, unchanged default credentials, flat-network reachability and direct patient-safety consequences make the overall finding Critical. CVSS does not fully capture the physical safety impact of unavailable or improperly managed infusion equipment.

---

# Finding 029 - Grafana Path Traversal on Unknown Device

**Finding:** 029 - CVE-2021-43798  
**CVSS Base Score:** 7.5 High

## Factor 1 - Asset Criticality

**Asset:** Unknown Linux/Grafana device at Westside Clinic  
**CIA Rating:** Provisional: C=High, I=Medium, A=Medium  
**Criticality Impact on Priority:** Raises urgency because ownership is unknown and stored credentials may provide access to the clinic or central VPN-connected environment.

## Factor 2 - Kill Chain Position

**Appears in Kill Chain(s):** Provisional Westside-to-Central pivot chain  
**Chain Role:** Initial internal foothold and credential-access point  
**Kill Chain Impact on Priority:** Raises urgency because arbitrary file read may expose secrets used for lateral movement.

## Factor 3 - Exploitability

**Exploitability Score:** 4/5  
**CISA KEV:** Yes  
**Exploit Impact on Priority:** Raises urgency because exploitation is public, simple and known to be used in real attacks.

## Factor 4 - Compensating Controls

**Existing Controls:** Internal location, but device is undocumented and the Westside site has a trusted VPN path  
**Control Impact on Priority:** Internal placement only slightly lowers technical exposure.

## Environmental CVSS (recalculated)

**Environmental Metrics Applied:** `CR:H/IR:M/AR:M/MAV:A/E:H/RL:O/RC:C`  
**Adjusted Score:** **7.9 High**

## Final Priority

**High**

## Final Justification

The adjusted score increases because confidentiality is especially important and exploit maturity is high. The device's unknown ownership, public file-read exploit and possible access to credentials make it a high-priority investigation and isolation target. It is below the EHR and medical-device findings because direct patient-care impact has not been confirmed.

---

# Finding 008 - PrintNightmare on EOL Print Server

**Finding:** 008 - CVE-2021-34527  
**CVSS Base Score:** 8.8 High

## Factor 1 - Asset Criticality

**Asset:** `print-srv-01`, central print server  
**CIA Rating:** Provisional: C=Medium, I=High, A=Medium  
**Criticality Impact on Priority:** Maintains High urgency because domain-connected print infrastructure can support lateral movement, although the business function is less critical than EHR or MRI.

## Factor 2 - Kill Chain Position

**Appears in Kill Chain(s):** Provisional Windows lateral-movement chain  
**Chain Role:** Execution and privilege-escalation enabler  
**Kill Chain Impact on Priority:** Raises urgency because a compromised print server can distribute access across many Windows systems.

## Factor 3 - Exploitability

**Exploitability Score:** 5/5  
**CISA KEV:** Yes  
**Exploit Impact on Priority:** Raises urgency because weaponized public tooling exists.

## Factor 4 - Compensating Controls

**Existing Controls:** Internal-only service; no strong segmentation confirmed  
**Control Impact on Priority:** Internal placement lowers the Environmental score slightly, but the EOL operating system limits long-term remediation.

## Environmental CVSS (recalculated)

**Environmental Metrics Applied:** `CR:M/IR:H/AR:H/MAV:A/E:H/RL:O/RC:C`  
**Adjusted Score:** **7.6 High**

## Final Priority

**High**

## Final Justification

The service is internal, which reduces direct exposure, but the vulnerability is weaponized, KEV-listed and hosted on an EOL Windows server. The print server's central position makes it useful for privilege escalation and lateral movement. Planned migration and immediate service restriction are required.

---

# Finding 005 - Weak TLS on Patient Portal

**Finding:** 005 - CVE-2011-3389 / CVE-2014-3566  
**CVSS Base Score:** 7.5 High

## Factor 1 - Asset Criticality

**Asset:** `web-srv-01`, internet-facing patient portal  
**CIA Rating:** Provisional: C=Critical, I=High, A=High  
**Criticality Impact on Priority:** Raises urgency because the portal transmits protected health information.

## Factor 2 - Kill Chain Position

**Appears in Kill Chain(s):** Provisional patient-session theft chain  
**Chain Role:** Initial interception or credential/session compromise enabler  
**Kill Chain Impact on Priority:** Moderately raises urgency, particularly when combined with weak browser protections.

## Factor 3 - Exploitability

**Exploitability Score:** 3/5  
**CISA KEV:** No  
**Exploit Impact on Priority:** Lowers urgency relative to remote-code-execution findings because practical attacks require interception conditions.

## Factor 4 - Compensating Controls

**Existing Controls:** TLS 1.2 is also supported, but TLS 1.0 remains enabled; no HSTS is configured  
**Control Impact on Priority:** Partial modern-TLS support provides limited mitigation but does not remove downgrade risk.

## Environmental CVSS (recalculated)

**Environmental Metrics Applied:** `CR:H/IR:L/AR:L/E:P/RL:O/RC:C`  
**Adjusted Score:** **8.4 High**

## Final Priority

**High**

## Final Justification

The adjusted score rises because confidentiality is critical for a patient portal. Exploit conditions are less straightforward than the RCE findings, but the system is internet-facing and handles PHI. The weakness should be remediated quickly, though it remains below the confirmed EHR, billing and medical-device compromise paths.

---

# Priority Comparison Table

| Finding | CVSS Base | Environmental Score | Adjusted Priority | Change Direction |
|---:|---:|---:|---|---|
| 004 | 9.8 Critical | 9.4 Critical | Critical | Same |
| 031 | 9.8 Critical | 8.4 High | **Critical business priority** | Numeric lower, priority same |
| 001 | 9.8 Critical | 9.1 Critical | Critical | Same |
| 002 | 7.8 High | 7.5 High | **Critical in chain** | Priority higher |
| 010 | 7.5 High | 7.5 High | **Critical patient-safety priority** | Priority higher |
| 029 | 7.5 High | 7.9 High | High | Slightly higher |
| 008 | 8.8 High | 7.6 High | High | Lower |
| 005 | 7.5 High | 8.4 High | High | Higher |

## Significant Differences

### Finding 002

The Base and Environmental scores remain High, but the final priority rises to Critical because Finding 001 supplies the local access prerequisite and creates a complete RCE-to-root chain.

### Finding 010

The Environmental score remains High, but patient-safety impact and default credentials raise the final operational priority to Critical.

### Finding 031

The Environmental score falls to High because the service is internal and a vendor fix exists. Nevertheless, the manually confirmed AJP exposure, flat network, KEV status and path to EHR credentials keep the final business priority Critical.

---

# Final Lesson

Environmental CVSS improves technical prioritization by considering asset requirements, exploit maturity, remediation availability and local network placement. It does not replace organizational risk analysis. Patient safety, regulatory exposure, attack chaining, undocumented assets and business interruption may justify a final priority that is higher than the numeric Environmental score.
