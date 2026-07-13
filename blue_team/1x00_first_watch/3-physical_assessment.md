# Physical Assessment

## Observation 1

**Vulnerability:**
The server room is accessible using the same generic employee badge issued to all staff. There is no CCTV monitoring and no visitor log.

**Threat:**
An unauthorized employee or visitor could enter the server room and tamper with or steal critical infrastructure.

**Impact:**

* **Confidentiality:** Sensitive data stored on servers or backup media could be accessed.
* **Integrity:** Systems could be modified or malicious devices installed.
* **Availability:** Critical servers could be shut down or damaged, disrupting hospital operations.

**Severity:** **Critical** – The server room contains critical infrastructure, and unrestricted physical access could compromise all three CIA pillars.

---

## Observation 2

**Vulnerability:**
The network closet is unlocked, and switch management credentials are exposed on the wall.

**Threat:**
An unauthorized person could access the switches, modify network configurations, or connect a rogue device.

**Impact:**

* **Confidentiality:** Network traffic could be intercepted.
* **Integrity:** Network configurations could be changed without authorization.
* **Availability:** Network services could be disrupted by disabling ports or changing switch settings.

**Severity:** **Critical** – Physical access combined with exposed administrative credentials provides direct access to critical network infrastructure.

---

## Observation 3

**Vulnerability:**
An unattended workstation is logged into the EHR system, and staff are instructed not to log out between shifts.

**Threat:**
An unauthorized individual could view or modify patient records using the active session.

**Impact:**

* **Confidentiality:** Patient health information could be viewed without authorization.
* **Integrity:** Patient records could be modified.

**Severity:** **High** – An active authenticated session exposes protected health information without requiring additional authentication.

---

## Observation 4

**Vulnerability:**
The medical device is running outdated firmware and shares the same network segment as user workstations.

**Threat:**
A compromised workstation could exploit vulnerabilities in the medical device or communicate directly with it.

**Impact:**

* **Confidentiality:** Patient or device information could be exposed.
* **Integrity:** Device settings or monitoring data could be altered.
* **Availability:** The device could become unavailable during patient care.

**Severity:** **Critical** – Outdated firmware and the lack of network segmentation significantly increase the risk to patient-care systems.

---

## Observation 5

**Vulnerability:**
A fire exit connecting a public area to a restricted administrative area is intentionally propped open.

**Threat:**
An unauthorized visitor could enter restricted areas without being challenged.

**Impact:**

* **Confidentiality:** Sensitive information or documents could be accessed.
* **Integrity:** Systems or equipment could be tampered with.
* **Availability:** Critical IT equipment or services could be disrupted.

**Severity:** **High** – The open door bypasses physical access controls and provides unrestricted access to sensitive administrative and IT areas.
