# 1. NIST CSF Current Profile – MedDefense Health Systems

## Function 1 – GOVERN (GV)

**Current Level:** Partial

### Evidence

- MedDefense has no formal cybersecurity framework in place.
- There is no documented enterprise cybersecurity strategy.
- The Board requested a formal security roadmap after reviewing the Security Posture Assessment, Threat Landscape Report and Vulnerability Assessment.
- The Deputy CISO (James Chen) and the IT Director provide leadership, but governance activities are informal.
- Auditors asked which security framework the organization follows, and the answer was "none formally."

### Key Gaps

The organization lacks documented security governance, formal cybersecurity policies, defined risk appetite and a structured review process.

### Target Level

**Managed**

Within six months MedDefense should establish a formal cybersecurity governance program based on NIST CSF 2.0, define cybersecurity roles and responsibilities, approve organizational security policies and begin regular Board-level security reporting.

---

# Function 2 – IDENTIFY (ID)

**Current Level:** Partial

### Evidence

- A complete asset inventory was created only during Project 1x00.
- Critical asset classification and CIA ratings were developed during the assessment.
- Threat and vulnerability assessments were performed for the first time during Projects 1x01 and 1x02.
- Risk assessments are not yet part of normal business operations.

### Key Gaps

Asset inventories, risk assessments and business impact analysis are not continuously maintained.

### Target Level

**Managed**

MedDefense should maintain an accurate asset inventory, perform scheduled risk assessments, update the criticality matrix regularly and integrate risk management into normal operational processes.

---

# Function 3 – PROTECT (PR)

**Current Level:** Partial

### Evidence

- Multiple critical vulnerabilities remain unpatched.
- The network uses a flat architecture with little segmentation.
- Windows XP and Windows Server 2012 R2 remain in production.
- Weak TLS configurations and default credentials were identified.
- SSH password authentication is still enabled.
- Medical devices rely heavily on compensating controls rather than secure configurations.

### Key Gaps

Protective controls are inconsistent and several critical assets lack modern security safeguards.

### Target Level

**Managed**

Within six months MedDefense should improve patch management, deploy stronger authentication, implement network segmentation, harden critical servers and replace or isolate unsupported systems.

---

# Function 4 – DETECT (DE)

**Current Level:** Not Implemented

### Evidence

- Marcus reported that MedDefense has virtually no monitoring capability.
- No SIEM platform exists.
- No centralized log collection was identified.
- No continuous network monitoring is performed.
- Limited capability exists to detect attacks before significant damage occurs.

### Key Gaps

The organization cannot consistently detect malicious activity or correlate security events.

### Target Level

**Managed**

MedDefense should deploy centralized logging, implement a SIEM solution, monitor critical infrastructure continuously and establish alert triage procedures.

---

# Function 5 – RESPOND (RS)

**Current Level:** Partial

### Evidence

- Previous incidents (including the crypto-miner compromise) demonstrate reactive rather than structured incident handling.
- No formally tested Incident Response Plan exists.
- Communication and escalation procedures are largely informal.
- Incident containment processes are not standardized.

### Key Gaps

Incident response activities lack documentation, testing and consistent execution.

### Target Level

**Managed**

MedDefense should create an Incident Response Plan, define escalation procedures, assign response roles, perform tabletop exercises and document lessons learned after every incident.

---

# Function 6 – RECOVER (RC)

**Current Level:** Partial

### Evidence

- Backup systems exist (Synology NAS).
- Backup testing and recovery validation were not demonstrated.
- No formal Disaster Recovery Plan or Business Continuity Plan was identified.
- Recovery objectives (RTO/RPO) have not been formally defined.

### Key Gaps

Recovery capabilities are not regularly tested and business continuity planning is incomplete.

### Target Level

**Managed**

Within six months MedDefense should establish a Disaster Recovery Plan, define RTO and RPO objectives, test backup restoration regularly and perform annual business continuity exercises.

---

# Overall Current Profile Summary

| NIST CSF Function | Current Level | Target Level |
|-------------------|---------------|--------------|
| Govern | Partial | Managed |
| Identify | Partial | Managed |
| Protect | Partial | Managed |
| Detect | Not Implemented | Managed |
| Respond | Partial | Managed |
| Recover | Partial | Managed |

---

# Overall Assessment

MedDefense demonstrates a developing cybersecurity program but lacks the governance, monitoring and repeatable operational processes expected from a mature organization. The organization has recently completed asset identification, threat analysis and vulnerability assessment, providing a strong foundation for improvement. The most significant weakness is the **Detect** function, where the absence of centralized monitoring, SIEM capabilities and continuous event analysis limits MedDefense's ability to identify attacks before they impact critical systems. Achieving a **Managed** maturity level across all six NIST CSF functions within six months is realistic if the organization follows the security roadmap developed during this project.
