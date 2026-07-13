# Risk Treatment Decisions

## Selected High-Priority Gaps

The following seven gaps were selected from the updated Gap Analysis (Tasks 12 and 13) because they present the highest risk to MedDefense's Critical assets, Restricted data and clinical operations.

- GAP-001 – Legacy MRI Workstation Running Unsupported Windows XP
- GAP-002 – Unattended EHR Sessions
- GAP-003 – Unsupported Billing Server
- GAP-004 – Flat Network Architecture
- GAP-007 – No Centralized Security Monitoring
- GAP-011 – No Automated Account Lifecycle Management
- GAP-012 – Default Credentials on Medical Devices

---

## GAP-001

**Gap ID:** GAP-001

**Gap Title:** Legacy MRI Workstation Running Unsupported Windows XP

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Replacing the MRI is not feasible. Isolating it greatly reduces risk while maintaining clinical operations.

**Proposed Control(s):**
- Technical Compensating: Network segmentation
- Technical Preventive: Firewall ACLs
- Physical Preventive: Restricted physical access

**Estimated Cost:** $10K–50K

**Implementation Effort:** Short-term (< 1 month)

**Expected Risk Reduction:** High

**Trade-offs:** Requires network changes and scheduled maintenance.

---

## GAP-002

**Gap ID:** GAP-002

**Gap Title:** Unattended EHR Sessions

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Automatic session locking protects Restricted patient data with minimal operational impact.

**Proposed Control(s):**
- Technical Preventive: Automatic session timeout
- Administrative Preventive: Security awareness training

**Estimated Cost:** $1K–10K

**Implementation Effort:** Quick Win (< 1 week)

**Expected Risk Reduction:** High

**Trade-offs:** Users must authenticate more frequently.

---

## GAP-003

**Gap ID:** GAP-003

**Gap Title:** Unsupported Billing Server

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** The server has already suffered ransomware and cryptomining attacks.

**Proposed Control(s):**
- Technical Preventive: Upgrade operating system
- Technical Detective: Vulnerability scanning

**Estimated Cost:** $10K–50K

**Implementation Effort:** Long-term (> 1 month)

**Expected Risk Reduction:** High

**Trade-offs:** Requires migration planning and scheduled downtime.

---

## GAP-004

**Gap ID:** GAP-004

**Gap Title:** Flat Network Architecture

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Network segmentation prevents attackers from moving between workstations, servers and medical devices.

**Proposed Control(s):**
- Technical Compensating: VLAN segmentation
- Technical Preventive: Internal firewall ACLs

**Estimated Cost:** $10K–50K

**Implementation Effort:** Long-term (> 1 month)

**Expected Risk Reduction:** Very High

**Trade-offs:** Network redesign requires careful testing.

---

## GAP-007

**Gap ID:** GAP-007

**Gap Title:** No Centralized Security Monitoring

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Without centralized monitoring, attacks may remain undetected for long periods.

**Proposed Control(s):**
- Technical Detective: Cloud SIEM
- Administrative Detective: Monitoring procedures

**Estimated Cost:** $10K–50K

**Implementation Effort:** Long-term (> 1 month)

**Expected Risk Reduction:** High

**Trade-offs:** Requires analyst training and recurring operational effort.

---

## GAP-011

**Gap ID:** GAP-011

**Gap Title:** No Automated Account Lifecycle Management

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Automatically disabling accounts after employee termination prevents unauthorized access.

**Proposed Control(s):**
- Administrative Preventive: HR offboarding workflow
- Technical Preventive: Automated account disablement

**Estimated Cost:** $1K–10K

**Implementation Effort:** Short-term (< 1 month)

**Expected Risk Reduction:** High

**Trade-offs:** Requires HR and IT process integration.

---

## GAP-012

**Gap ID:** GAP-012

**Gap Title:** Default Credentials on Medical Devices

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Default credentials are one of the most common attack vectors against medical devices.

**Proposed Control(s):**
- Technical Preventive: Replace default passwords
- Administrative Preventive: Credential management procedure

**Estimated Cost:** $0–1K

**Implementation Effort:** Quick Win (< 1 week)

**Expected Risk Reduction:** High

**Trade-offs:** Requires coordination with Biomedical Engineering and device vendors.

---

# Budget Summary

| Activity | Estimated Cost |
|----------|----------------|
| MRI network isolation | $20,000 |
| Automatic EHR session locking | $5,000 |
| Billing server upgrade | $20,000 |
| Network segmentation | $35,000 |
| Cloud SIEM deployment | $30,000 |
| Automated offboarding | $5,000 |
| Medical device credential update | $5,000 |

**Estimated Total:** **$120,000**

The proposed mitigation plan remains within the available annual security budget. Immediate funding should prioritize controls that protect Critical assets and Restricted data. Lower-priority improvements not included in these seven gaps should be scheduled for the next fiscal year after the highest operational risks have been reduced.
