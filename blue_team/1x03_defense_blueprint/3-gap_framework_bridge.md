# 3. Gap-to-Framework Bridge

## Gap 1

**Gap Reference:** GAP-001

**Description:** No centralized security monitoring or SIEM capability.

**Vulnerability Evidence:** Findings 001–031 (all findings rely on manual discovery rather than continuous monitoring).

**Threat Context:** Ransomware groups – Kill Chain #1 (Initial Access → Lateral Movement → Ransomware Deployment).

**NIST CSF Function:** Detect (DE)

**CIS Control:** Control 13 – Network Monitoring and Defense

**Recommended Action:** Deploy centralized logging, a SIEM platform and network monitoring with IDS/IPS capabilities.

---

## Gap 2

**Gap Reference:** GAP-002

**Description:** Flat network architecture with little or no segmentation.

**Vulnerability Evidence:** Finding 003 (PostgreSQL unrestricted access), Findings 010, 016 and 024 (Medical IoT), Windows XP workstation exposure.

**Threat Context:** Ransomware operators – Kill Chain #1 (Lateral Movement).

**NIST CSF Function:** Protect (PR)

**CIS Control:** Control 12 – Network Infrastructure Management

**Recommended Action:** Segment the network into security zones separating servers, users, medical devices and administrative systems.

---

## Gap 3

**Gap Reference:** GAP-003

**Description:** Unsupported end-of-life operating systems remain in production.

**Vulnerability Evidence:** Windows XP MRI workstation, Windows Server 2012 R2 print server, Ubuntu 18.04 billing server.

**Threat Context:** Cybercriminals and ransomware groups exploiting known vulnerabilities.

**NIST CSF Function:** Protect (PR)

**CIS Control:** Control 7 – Continuous Vulnerability Management

**Recommended Action:** Replace unsupported operating systems or isolate them using compensating controls until migration is completed.

---

## Gap 4

**Gap Reference:** GAP-004

**Description:** Critical vulnerabilities are not patched in a timely manner.

**Vulnerability Evidence:** Findings 001, 002, 031 and other Critical CVEs.

**Threat Context:** External attackers exploiting publicly available Proof-of-Concept exploits.

**NIST CSF Function:** Protect (PR)

**CIS Control:** Control 7 – Continuous Vulnerability Management

**Recommended Action:** Implement a formal vulnerability and patch management process with defined remediation timelines.

---

## Gap 5

**Gap Reference:** GAP-005

**Description:** Weak authentication and default credentials.

**Vulnerability Evidence:** Default credentials on BD Alaris devices, SSH password authentication enabled.

**Threat Context:** Insider threats and external attackers performing credential attacks.

**NIST CSF Function:** Protect (PR)

**CIS Control:** Control 6 – Access Control Management

**Recommended Action:** Enforce MFA, disable default accounts and implement strong authentication for privileged access.

---

## Gap 6

**Gap Reference:** GAP-006

**Description:** No formal Incident Response Plan.

**Vulnerability Evidence:** Previous crypto-miner compromise demonstrated reactive incident handling.

**Threat Context:** All major threat actors, especially ransomware groups.

**NIST CSF Function:** Respond (RS)

**CIS Control:** Control 17 – Incident Response Management

**Recommended Action:** Develop, document and test an Incident Response Plan with defined roles and escalation procedures.

---

## Gap 7

**Gap Reference:** GAP-007

**Description:** Backup and recovery processes are not regularly validated.

**Vulnerability Evidence:** Synology backup infrastructure exists but recovery testing was not demonstrated.

**Threat Context:** Ransomware attacks targeting backup systems.

**NIST CSF Function:** Recover (RC)

**CIS Control:** Control 11 – Data Recovery

**Recommended Action:** Perform regular backup restoration testing and maintain isolated offline backup copies.

---

## Gap 8

**Gap Reference:** GAP-008

**Description:** Security governance and policies are informal.

**Vulnerability Evidence:** No formal security framework or documented governance was identified during Project 1x00.

**Threat Context:** All threat actors benefit from inconsistent governance and security processes.

**NIST CSF Function:** Govern (GV)

**CIS Control:** Control 15 – Service Provider Management (supported by organizational governance) and overall security governance.

**Recommended Action:** Adopt NIST CSF 2.0 as the primary framework, implement CIS Controls v8 and establish an ISO/IEC 27001-aligned Information Security Management System (ISMS).

---

# Traceability Summary

| Gap | Vulnerability Evidence | Threat Context | NIST CSF Function | CIS Control | Recommended Action |
|------|------------------------|----------------|-------------------|-------------|--------------------|
| GAP-001 | Multiple findings; no centralized detection | Ransomware – Kill Chain #1 | Detect | Control 13 | Deploy SIEM and IDS/IPS |
| GAP-002 | Finding 003, 010, 016, 024 | Ransomware – Lateral Movement | Protect | Control 12 | Implement network segmentation |
| GAP-003 | Windows XP, Windows Server 2012 R2, Ubuntu 18.04 | Cybercriminals exploiting EOL systems | Protect | Control 7 | Replace or isolate unsupported systems |
| GAP-004 | Findings 001, 002, 031 | Public exploit availability | Protect | Control 7 | Formalize vulnerability and patch management |
| GAP-005 | Default credentials, weak authentication | Credential attacks | Protect | Control 6 | Enforce MFA and remove default credentials |
| GAP-006 | Crypto-miner incident | Ransomware and advanced attackers | Respond | Control 17 | Develop and test an Incident Response Plan |
| GAP-007 | Backup infrastructure | Ransomware | Recover | Control 11 | Validate backup recovery regularly |
| GAP-008 | Lack of governance | All threat actors | Govern | Control 15 / Governance | Implement NIST CSF, CIS Controls and ISO 27001 governance |

---

# Conclusion

This traceability bridge demonstrates that every major security recommendation is directly supported by technical evidence, mapped to a recognized security framework and justified by the organization's threat landscape. Rather than implementing controls because they are considered industry best practices, MedDefense can clearly explain how each action reduces a specific business risk. This structured approach enables executive leadership to prioritize investments based on measurable risk reduction and alignment with NIST CSF 2.0 and CIS Controls v8.
