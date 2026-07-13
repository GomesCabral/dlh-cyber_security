# Risk Treatment Decisions

---

## GAP-001

**Gap ID:** GAP-001

**Gap Title:** Legacy MRI Workstation Running Unsupported Windows XP

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Replacing the MRI is not financially or operationally feasible. Network isolation significantly reduces the likelihood of compromise while preserving clinical operations.

**Proposed Control(s):**
- Technical Compensating: Dedicated VLAN
- Technical Preventive: Firewall ACLs
- Physical Preventive: Restricted access to MRI workstation

**Estimated Cost:** $10K–50K

**Implementation Effort:** Short-term (< 1 month)

**Expected Risk Reduction:** High. Limits lateral movement and reduces exposure of the legacy workstation.

**Trade-offs:** Network redesign requires coordination with Radiology and temporary maintenance windows.

---

## GAP-002

**Gap ID:** GAP-002

**Gap Title:** Unattended EHR Sessions

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Automatic session locking reduces unauthorized access without disrupting clinical workflows.

**Proposed Control(s):**
- Technical Preventive: Automatic session timeout
- Administrative Preventive: Updated workstation usage policy
- Administrative Preventive: Staff awareness training

**Estimated Cost:** $1K–10K

**Implementation Effort:** Quick Win (< 1 week)

**Expected Risk Reduction:** High. Reduces unauthorized access to Restricted patient information.

**Trade-offs:** Staff may experience slightly more frequent logins.

---

## GAP-003

**Gap ID:** GAP-003

**Gap Title:** Unsupported Billing Server

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** The server has already suffered ransomware and cryptomining incidents. Upgrading and hardening the platform is essential.

**Proposed Control(s):**
- Technical Preventive: Upgrade operating system
- Technical Detective: Continuous vulnerability scanning

**Estimated Cost:** $10K–50K

**Implementation Effort:** Long-term (> 1 month)

**Expected Risk Reduction:** High. Removes known vulnerabilities and improves resilience.

**Trade-offs:** Planned downtime and migration effort.

---

## GAP-004

**Gap ID:** GAP-004

**Gap Title:** Flat Network Architecture

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Network segmentation prevents attackers from moving freely between workstations, servers and medical devices.

**Proposed Control(s):**
- Technical Compensating: VLAN Segmentation
- Technical Preventive: Internal Firewall ACLs

**Estimated Cost:** $10K–50K

**Implementation Effort:** Long-term (> 1 month)

**Expected Risk Reduction:** Very High. Limits lateral movement and protects critical assets.

**Trade-offs:** Requires network redesign and testing.

---

## GAP-007

**Gap ID:** GAP-007

**Gap Title:** No Centralized Security Monitoring

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Without centralized monitoring, attacks may remain undetected for extended periods.

**Proposed Control(s):**
- Technical Detective: Cloud-based SIEM
- Administrative Detective: Security monitoring procedures

**Estimated Cost:** $50K+

**Implementation Effort:** Long-term (> 1 month)

**Expected Risk Reduction:** High. Improves detection and incident response capabilities.

**Trade-offs:** Requires ongoing licensing costs and analyst training.

---

## GAP-011

**Gap ID:** GAP-011

**Gap Title:** No Automated Account Lifecycle Management

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Automating account deactivation eliminates unnecessary access after employee termination.

**Proposed Control(s):**
- Administrative Preventive: HR-IT offboarding workflow
- Technical Preventive: Automated account disablement

**Estimated Cost:** $1K–10K

**Implementation Effort:** Short-term (< 1 month)

**Expected Risk Reduction:** High. Prevents former employees from accessing organizational systems.

**Trade-offs:** Requires integration between HR and Active Directory.

---

## GAP-012

**Gap ID:** GAP-012

**Gap Title:** Default Credentials on Medical Devices

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Default credentials provide attackers with immediate privileged access.

**Proposed Control(s):**
- Technical Preventive: Replace vendor default passwords
- Administrative Preventive: Medical device credential management process

**Estimated Cost:** $0–1K

**Implementation Effort:** Quick Win (< 1 week)

**Expected Risk Reduction:** High. Eliminates one of the most common attack vectors.

**Trade-offs:** Requires coordination with Biomedical Engineering and device vendors.

---

# Budget Summary

| Mitigation Activity | Estimated Cost |
|---------------------|----------------|
| MRI Network Isolation | $20,000 |
| Automatic EHR Session Locking | $5,000 |
| Billing Server Upgrade | $20,000 |
| Network Segmentation | $35,000 |
| Cloud-Based SIEM | $25,000 |
| Automated Offboarding | $10,000 |
| Medical Device Credential Hardening | $5,000 |

**Total Estimated Cost:** **$120,000**

The proposed mitigation plan fits within the available annual security budget. Priority is given to controls that reduce the highest operational and patient safety risks. Larger infrastructure improvements, such as expanding SIEM capabilities or replacing legacy medical systems, should be considered in the next fiscal year after the highest-risk vulnerabilities have been addressed.
