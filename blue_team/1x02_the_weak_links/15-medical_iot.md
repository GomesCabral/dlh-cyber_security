# 15. The Medical IoT

## Scope

This assessment covers the medical-device findings in the MedDefense scan:

- Finding 010 — BD Alaris infusion pumps
- Finding 016 — Philips IntelliVue patient monitors
- Finding 024 — Unencrypted DICOM traffic
- Related findings involving the MRI workstation, flat network, USB access, and network segmentation

---

# 1. BD Alaris Assessment

## Affected Devices

**Hosts:** `10.10.3.40–46`  
**Devices:** Seven BD Alaris infusion pumps  
**Detected firmware:** Version 12.1.2

## Vulnerability Reported by the Scan

The scan associates the devices with:

**CVE-2020-25165 — Network Session Authentication Vulnerability**

The vulnerability affects the authentication process between certain BD Alaris PC Units and the BD Alaris Systems Manager. An attacker with network access may modify configuration headers in transit, causing a denial of service and loss of wireless connectivity. The pump may then require manual operation.

The NVD assigns:

- **CVSS v3.1:** 7.5 High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CWE:** CWE-287 — Improper Authentication

## Important Firmware Discrepancy

The scan states that firmware 12.1.2 is affected by CVE-2020-25165. However, BD's official advisory states that:

- affected PC Unit versions are 9.33.1 and earlier;
- BD released Alaris PC Unit software 12.1.1 and newer to remediate the vulnerability.

Therefore, firmware 12.1.2 should already contain the vendor fix for CVE-2020-25165.

This part of Finding 010 requires manual validation and may be a scanner version-mapping error or false positive.

MedDefense should confirm:

1. the exact device model;
2. whether `12.1.2` refers to PC Unit firmware, Guardrails software, or another component;
3. the Alaris Systems Manager version;
4. the device's patch and regulatory authorization status.

## Vendor Mitigation

BD recommends:

- upgrading affected Alaris PC Units to version 12.1.1 or newer where regulatory authorization permits;
- contacting the BD representative to schedule remediation;
- using network controls and monitoring as additional protection;
- following vendor-approved procedures rather than installing unapproved changes.

## Has MedDefense Implemented the Recommendation?

**Partially, but not adequately.**

If the detected firmware is genuinely PC Unit version 12.1.2, then the software-update recommendation for CVE-2020-25165 appears to have been implemented.

However, MedDefense has not implemented the essential environmental controls:

- the pumps are not isolated on a dedicated VLAN;
- all seven devices use default `admin/admin` credentials;
- the devices are reachable from the flat network;
- firewall access is not restricted to approved clinical systems.

Therefore, even if CVE-2020-25165 is patched, the devices remain exposed to unauthorized access and denial-of-service risks.

## Confirmed Risk from Default Credentials

The scan confirmed default credentials on all seven pumps.

An attacker with internal network access could attempt to:

- access management functions;
- change device configuration;
- disrupt connectivity;
- gather device information;
- use the pumps as internal footholds;
- interfere with clinical workflows.

The exact clinical actions available through the web interface must be validated with BD documentation, but unchanged default credentials are unacceptable on patient-care devices.

## Recommendations

1. Confirm the exact firmware and Systems Manager versions with BD.
2. Validate whether CVE-2020-25165 truly applies to version 12.1.2.
3. Change all default credentials immediately using vendor-approved procedures.
4. Place the pumps in a dedicated medical-device VLAN.
5. Permit communication only with approved clinical workstations and management servers.
6. Block management interfaces from ordinary user networks.
7. Monitor for unusual sessions, repeated authentication attempts, and connectivity loss.
8. Maintain a manual clinical procedure for pump operation during network outages.
9. Coordinate all firmware changes with BD and clinical engineering.

---

# 2. Philips IntelliVue Assessment

## Affected Devices

**Hosts:** `10.10.3.10–32`  
**Detected devices:** 13 Philips IntelliVue monitors  
**Ports:** 80, 443, and 2575  
**Firmware dates:** 2019–2022

## Exposed Interfaces

The scan found:

- HTTP/HTTPS web-management interfaces;
- HL7 communication on TCP port 2575;
- no authentication beyond network location;
- access from the flat internal network.

Because the network is flat, network location provides almost no meaningful protection.

## Data Flowing Through the Interfaces

### Web Interfaces

The web interfaces may expose device-management and status information such as:

- device identity and model;
- firmware version;
- network settings;
- operational status;
- alarm or diagnostic information;
- configuration pages;
- patient-monitoring context.

The exact functions depend on the IntelliVue model and installed software.

### HL7 Interface

HL7 is used to exchange clinical information between monitoring systems and hospital applications.

Depending on the implementation, HL7 messages may contain:

- patient name;
- patient identifier or medical-record number;
- date of birth;
- admission and discharge information;
- bed or room location;
- clinical observations;
- vital signs;
- device measurements;
- timestamps;
- alarm or event information.

## What an Attacker with Network Access Could See

Because the interfaces are reachable without meaningful authentication, an attacker may be able to:

- identify all monitors and their software versions;
- view device status and configuration information;
- observe patient identifiers and clinical measurements;
- capture unencrypted HL7 messages;
- map rooms, beds, and patients;
- collect information useful for later targeted attacks.

Finding 024 shows that DICOM traffic is also unencrypted. Together, HL7 and DICOM exposure may reveal both patient identifiers and medical imaging information.

## What an Attacker Could Potentially Do

Depending on the functions exposed by the specific model, an attacker may attempt to:

- change network settings;
- interrupt communications with central monitoring;
- cause denial of service;
- alter device configuration;
- inject or replay HL7 messages;
- interfere with alarm delivery;
- use the interface for internal reconnaissance.

The scan does not prove that all these actions are possible. They are realistic attack hypotheses that require controlled vendor-approved validation.

## Attack Chain

A likely attack path is:

1. A user workstation is compromised through phishing or malware.
2. The attacker scans the flat network.
3. IntelliVue web interfaces and HL7 ports are discovered.
4. The attacker reads device information and patient-related traffic.
5. Device versions and network relationships are mapped.
6. The attacker disrupts monitoring communications or pivots toward other clinical systems.
7. Clinical staff lose reliable central monitoring or must switch to manual procedures.

## Recommendations

1. Move all monitors into dedicated medical-device VLANs.
2. Allow HL7 traffic only between the monitors and approved clinical integration systems.
3. Restrict web management to clinical engineering and dedicated administrative hosts.
4. Block ordinary workstations from ports 80, 443, and 2575 on medical devices.
5. Encrypt clinical traffic where the product supports it.
6. Monitor abnormal HL7 volume, new connections, and configuration changes.
7. Verify firmware support status with Philips.
8. Apply only Philips-approved patches and configuration changes.
9. Contact Philips support for model-specific hardening instructions.
10. Maintain procedures for local monitoring if central communications fail.

---

# 3. Related Medical IoT Findings

## Finding 024 — Unencrypted DICOM Traffic

**Host:** `10.10.2.12` (`pacs-srv-01`)  
**Ports:** 4242 and 11112

DICOM traffic between the MRI workstation, radiology workstations, and PACS is transmitted without TLS.

This may expose:

- patient names and identifiers;
- medical images;
- study descriptions;
- timestamps;
- imaging metadata.

An internal attacker may capture sensitive radiology information or potentially manipulate traffic if no integrity protection exists.

### Recommendation

- enable DICOM TLS where supported;
- isolate imaging systems;
- restrict DICOM ports to approved devices;
- monitor unusual image transfers;
- use encrypted tunnels as a compensating control when native TLS is unavailable.

## Finding 004 — Windows XP MRI Workstation

The MRI control workstation runs unsupported Windows XP and has multiple weaponized remote-code-execution vulnerabilities.

This increases medical IoT risk because an attacker could:

- compromise the MRI workstation;
- disrupt imaging availability;
- use it to access PACS;
- observe unencrypted DICOM traffic;
- pivot toward other clinical devices.

## Finding 023 — USB Storage Not Restricted

Clinical workstations allow unrestricted USB storage.

USB devices can introduce malware into networks where medical equipment cannot be patched easily. They can also provide a route for patient-data exfiltration.

## Flat Network Architecture

The common weakness beneath all medical IoT findings is the absence of strong segmentation.

A compromised administrative workstation can potentially reach:

- infusion pumps;
- patient monitors;
- the MRI workstation;
- PACS;
- EHR systems;
- other clinical endpoints.

---

# 4. Patient Safety Dimension

Medical-device vulnerabilities are different from ordinary IT vulnerabilities because they can affect physical clinical processes, not only information. A compromised workstation may expose data or interrupt office work, while a compromised infusion pump could disrupt medication delivery, force manual operation, or contribute to an incorrect clinical action. The worst case for an infusion pump is patient injury or death caused by unavailable, delayed, or altered therapy. The worst case for a normal workstation is usually data theft, fraud, ransomware, or loss of productivity, although a clinical workstation can also indirectly affect care.

---

# 5. Remediation Challenge

Patching medical devices is harder than patching ordinary IT systems for several reasons.

## 1. Regulatory and Safety Validation

Medical-device updates must often be tested and approved to confirm that they do not interfere with the device's intended clinical function.

A technically successful patch could still create unacceptable safety or regulatory risk if it changes performance, compatibility, or alarm behavior.

## 2. Operational Availability

Patient-care devices may be needed continuously.

Taking monitors or infusion pumps offline may require:

- clinical scheduling;
- spare devices;
- manual procedures;
- patient transfer;
- coordination with nursing and biomedical engineering.

An ordinary laptop can often be rebooted quickly; a device actively supporting a patient cannot.

## 3. Vendor Dependency

Hospitals may not be permitted to install standard operating-system or third-party patches directly.

They often depend on the manufacturer to:

- test the patch;
- approve it;
- publish installation procedures;
- provide replacement firmware;
- preserve warranty and regulatory compliance.

## 4. Long Product Lifecycles

Medical devices may remain in service for ten or more years, while their operating systems and components become obsolete much earlier.

Replacement can require major capital expenditure and clinical approval.

## 5. Specialized Compatibility

A medical device may depend on:

- a specific firmware version;
- a central monitoring platform;
- proprietary protocols;
- approved wireless modules;
- vendor service tools;
- integration with EHR, PACS, or HL7 systems.

Updating one component may break the full clinical workflow.

## 6. Limited Security Tooling

Traditional EDR, antivirus, vulnerability agents, or host firewalls may not be supported on the device.

Security therefore depends heavily on compensating controls such as segmentation, monitoring, allowlisting, and physical access control.

---

# 6. Overall Risk Assessment

## Highest Confirmed Risks

1. Default credentials on all seven BD Alaris pumps
2. Flat-network access to medical-device interfaces
3. Unauthenticated or network-trusted Philips management interfaces
4. Exposed HL7 traffic containing patient and clinical data
5. Unencrypted DICOM traffic
6. Unsupported Windows XP MRI workstation

## Important Validation Finding

The CVE-2020-25165 association with Alaris firmware 12.1.2 appears inconsistent with BD's official advisory, which says version 12.1.1 and later contain the remediation.

This does not make Finding 010 harmless. It means the CVE mapping must be validated while the default credentials and missing segmentation are treated as confirmed weaknesses.

## Priority Actions

1. Segment all medical devices.
2. Change default credentials.
3. Restrict management and clinical protocol ports.
4. Validate device firmware with each vendor.
5. Encrypt HL7 and DICOM traffic where supported.
6. Monitor medical-device communications.
7. Maintain clinical downtime and manual-operation procedures.
8. Plan replacement of unsupported devices.

---

# Sources

- BD Alaris 8015 PC Unit and Systems Manager advisory:  
  https://www.bd.com/en-us/about-bd/cybersecurity/bulletin/bd-alaris-8015-pc-unit-and-bd-alaris-systems-manager-network-s
- NVD CVE-2020-25165:  
  https://nvd.nist.gov/vuln/detail/CVE-2020-25165
- Philips security advisories:  
  https://www.philips.com/a-w/security/security-advisories
