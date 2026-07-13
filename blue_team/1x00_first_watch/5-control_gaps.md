# Control Gaps

## Gap G-001

**Gap ID:** G-001

**Gap Description:** No centralized log management or Security Information and Event Management (SIEM) solution is implemented.

**Category x Function Missing:** Technical Detective

**Affected Asset(s) or Zone:** Entire IT environment

**Risk if Unaddressed:** Security incidents may remain undetected, allowing attackers to compromise confidentiality and integrity before they are discovered.

**Evidence:** Artifact 8 states that no centralized log management or automated alerting exists.

---

## Gap G-002

**Gap ID:** G-002

**Gap Description:** No tested disaster recovery procedure exists for restoring critical systems.

**Category x Function Missing:** Administrative Corrective

**Affected Asset(s) or Zone:** Critical production servers

**Risk if Unaddressed:** Recovery from ransomware, hardware failure or disaster may be delayed, reducing system availability.

**Evidence:** Artifact 5 states that a full disaster recovery test has never been performed.

---

## Gap G-003

**Gap ID:** G-003

**Gap Description:** Endpoint protection is not deployed on Windows servers, Linux servers or mobile devices.

**Category x Function Missing:** Technical Preventive

**Affected Asset(s) or Zone:** Windows servers, Linux servers and physician iPads

**Risk if Unaddressed:** Malware may compromise sensitive systems, affecting confidentiality, integrity and availability.

**Evidence:** Artifact 4 shows that only Windows workstations are protected by Sophos.

---

## Gap G-004

**Gap ID:** G-004

**Gap Description:** The server room and other critical infrastructure areas are not covered by CCTV.

**Category x Function Missing:** Physical Detective

**Affected Asset(s) or Zone:** Server room, network closets and administrative wing

**Risk if Unaddressed:** Unauthorized physical access may not be detected or investigated.

**Evidence:** Artifact 6 states that no cameras monitor these areas.

---

## Gap G-005

**Gap ID:** G-005

**Gap Description:** Security awareness training does not include healthcare-specific topics such as PHI handling or medical device security.

**Category x Function Missing:** Administrative Preventive

**Affected Asset(s) or Zone:** All employees

**Risk if Unaddressed:** Staff may mishandle sensitive healthcare information or fail to recognize healthcare-specific cyber threats, affecting confidentiality and integrity.

**Evidence:** Artifact 7 states that PHI handling and medical device security are not included in the training program.

---

## Gap G-006

**Gap ID:** G-006

**Gap Description:** No automated monitoring or alerting exists for security logs.

**Category x Function Missing:** Technical Detective

**Affected Asset(s) or Zone:** Servers, Active Directory and network infrastructure

**Risk if Unaddressed:** Security events may not be detected promptly, allowing attackers to maintain persistence and increase the impact of an incident.

**Evidence:** Artifact 8 states that logs are reviewed manually and no automated alerting is implemented.

---

## Overall Assessment

MedDefense's current security posture is primarily prevention-oriented, with several preventive controls already implemented, including firewall rules, password policies and endpoint protection. However, detective and corrective capabilities are limited, reducing the organization's ability to quickly identify, investigate and respond to incidents that bypass preventive controls.
