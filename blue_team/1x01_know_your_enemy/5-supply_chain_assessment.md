# Supply Chain Assessment

## Vendor: MedTech Solutions

**Service:** Electronic Health Record (EHR) maintenance and technical support.

**Access Type:** Network and Application access.

**Access Scope:** Direct maintenance access to the EHR servers, databases and supporting applications containing patient records.

**Compromise Scenario:** If MedTech Solutions is compromised, an attacker could use the vendor's maintenance access to reach the EHR environment, steal patient records or deploy malware into critical clinical systems.

**Existing Controls:** VPN access, Password Policy, Access Control Policy and Firewall Rules (Control Matrix).

**Risk Assessment:** **Critical** – The vendor has privileged access to MedDefense's most critical clinical system.

---

## Vendor: Microsoft

**Service:** Microsoft 365 (Exchange Online, SharePoint, OneDrive and identity services).

**Access Type:** Application and Data access.

**Access Scope:** Email, cloud storage, collaboration platforms and user identities.

**Compromise Scenario:** A compromise could expose organizational email, sensitive documents and user accounts, allowing phishing, credential theft and business email compromise.

**Existing Controls:** Multi-factor authentication (where implemented), Password Policy and Conditional Access.

**Risk Assessment:** **High** – A compromise would affect nearly every employee and critical business data.

---

## Vendor: Sophos

**Service:** Endpoint protection platform.

**Access Type:** Application and Network management.

**Access Scope:** All managed workstations and servers through the endpoint management console.

**Compromise Scenario:** If the management platform is compromised, an attacker could disable endpoint protection or distribute malicious updates across the environment.

**Existing Controls:** Administrative access restrictions and endpoint management procedures.

**Risk Assessment:** **High** – The vendor has privileged access to almost every managed endpoint.

---

## Vendor: Siemens

**Service:** MRI maintenance and firmware support.

**Access Type:** Physical and Application access.

**Access Scope:** MRI workstation, Windows XP Embedded system and MRI firmware.

**Compromise Scenario:** A compromised maintenance session could provide attackers with access to the legacy MRI workstation and potentially the hospital network because the device is not isolated.

**Existing Controls:** Physical access controls and compensating controls proposed for the MRI workstation.

**Risk Assessment:** **High** – The workstation is a legacy system connected to the production network.

---

## Vendor: Greenfield Building Management

**Service:** Building network infrastructure management.

**Access Type:** Network access.

**Access Scope:** Building network infrastructure supporting MedDefense's VLAN and connectivity.

**Compromise Scenario:** If the building management network is compromised, attackers could attempt to pivot into MedDefense's network or disrupt network connectivity.

**Existing Controls:** Firewall rules and VLAN configuration.

**Risk Assessment:** **Medium** – The vendor has indirect access to MedDefense's network infrastructure but does not directly manage clinical systems.

---

# Supply Chain Risk Summary

The compromise of **MedTech Solutions** would present the greatest risk because the vendor has privileged access to the EHR environment, which stores MedDefense's most sensitive patient information and supports critical clinical operations. A compromise could result in data theft, ransomware deployment and disruption of patient care. The highest-priority control to reduce supply chain risk is implementing **Multi-Factor Authentication (MFA) with least-privilege remote access** for all third-party vendors, ensuring vendors only have access to the systems required for their support activities.
