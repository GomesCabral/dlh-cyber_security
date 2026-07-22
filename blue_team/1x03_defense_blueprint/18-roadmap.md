# 18. Security Roadmap – MedDefense Health Systems

## Overview

This roadmap converts the MedDefense Security Strategy into a practical six-month implementation plan. Activities are scheduled based on priority, dependencies, available resources, and the approved annual cybersecurity budget of **$120,000**.

The roadmap follows the NIST Cybersecurity Framework (CSF) and CIS Controls v8, focusing first on governance and high-value controls before progressing to architecture improvements and validation.

---

# Month 1 – Governance and Quick Wins

## Objectives

- Establish governance
- Reduce immediate cyber risk
- Begin policy implementation

| Action | Owner | Dependencies | Completion Criteria |
|---------|-------|--------------|---------------------|
| Approve Security Strategy | CEO & Deputy CISO | None | Board approval received |
| Publish Acceptable Use Policy (AUP) | Deputy CISO | Strategy approval | Employees acknowledge policy |
| Enable MFA for VPN and Administrative Accounts | IT Director | None | 100% privileged accounts protected |
| Disable Dormant Accounts | IT Director | None | All inactive accounts disabled |
| Patch Critical Internet-Facing Systems | IT Operations | None | No Critical Internet-facing vulnerabilities remain |
| Block Unauthorized USB Devices | IT Director | AUP published | USB restrictions enforced through Group Policy |
| Create Risk Register | Security Analyst | Strategy approval | Risk Register approved and published |

---

# Month 2 – Procurement and Security Foundation

## Objectives

- Acquire required technologies
- Prepare infrastructure
- Establish visibility

| Action | Owner | Dependencies | Completion Criteria |
|---------|-------|--------------|---------------------|
| Procure Firewall Hardware | IT Director | Budget approval | Hardware delivered |
| Build Wazuh Server | Security Analyst | Hardware available | SIEM server operational |
| Configure Centralized Logging | Security Analyst | Wazuh installed | Servers sending logs |
| Configure Immutable Backups | IT Director | Cloud storage available | Successful backup verification |
| Security Awareness Training | Security Analyst | AUP published | 100% employee completion |

---

# Month 3 – Network Security

## Objectives

- Remove flat network
- Improve infrastructure security

| Action | Owner | Dependencies | Completion Criteria |
|---------|-------|--------------|---------------------|
| Implement VLAN Segmentation | IT Director | Firewall installed | VLANs operational |
| Configure Firewall Policies | IT Director | VLAN implementation | Firewall rules validated |
| Install Westside Clinic Firewall | IT Director | Hardware delivery | Branch protected |
| Update Network Documentation | Security Analyst | VLAN deployment | Network diagrams completed |

---

# Month 4 – Monitoring and Validation

## Objectives

- Improve visibility
- Validate security posture

| Action | Owner | Dependencies | Completion Criteria |
|---------|-------|--------------|---------------------|
| Deploy Wazuh Agents | Security Analyst | SIEM operational | All servers reporting |
| Configure Security Alerts | Security Analyst | Agent deployment | Critical alerts tested |
| Monthly Vulnerability Scan | Security Analyst | Segmentation complete | Scan completed |
| Remediate Critical Findings | IT Operations | Vulnerability Scan | High-risk findings resolved |

---

# Month 5 – Optimization

## Objectives

- Improve operational maturity
- Test incident readiness

| Action | Owner | Dependencies | Completion Criteria |
|---------|-------|--------------|---------------------|
| Incident Response Exercise | Deputy CISO | SIEM operational | Exercise completed |
| Backup Recovery Test | IT Director | Immutable backups operational | Successful restore |
| Firewall Rule Review | IT Director | Firewall operational | Rule audit completed |
| Risk Register Review | Deputy CISO | Previous activities complete | Risks updated |

---

# Month 6 – Final Validation

## Objectives

- Validate implementation
- Prepare continuous improvement

| Action | Owner | Dependencies | Completion Criteria |
|---------|-------|--------------|---------------------|
| Full Vulnerability Assessment | Security Analyst | All controls implemented | Risk reduction validated |
| Internal Security Audit | Deputy CISO | All phases complete | Audit report issued |
| Board Security Report | Deputy CISO | Audit completed | Report presented |
| Year 2 Roadmap Planning | Executive Team | Audit results | Next roadmap approved |

---

# Dependency Chain

Several activities depend on earlier implementations.

### Dependency 1

MFA Deployment

↓

VPN Hardening

↓

Reduced Credential Theft Risk

---

### Dependency 2

Firewall Installation

↓

Network Segmentation (VLANs)

↓

Medical Device Isolation (Year 2)

---

### Dependency 3

Wazuh Server Deployment

↓

Centralized Logging

↓

Security Alerting

↓

Incident Detection

↓

Future Managed SOC (Year 2)

---

### Dependency 4

Acceptable Use Policy

↓

Security Awareness Training

↓

Improved User Compliance

↓

Reduced Insider Risk

---

### Dependency 5

Immutable Backups

↓

Backup Validation

↓

Recovery Testing

↓

Business Continuity

---

# Project Milestones

## Milestone 1 – Governance Established

**Target Date:** End of Month 1

### Deliverables

- Security Strategy approved
- Risk Register created
- Acceptable Use Policy published
- MFA enabled

### Success Indicator

✔ Governance framework fully operational

---

## Milestone 2 – Security Foundation Complete

**Target Date:** End of Month 2

### Deliverables

- SIEM deployed
- Logging centralized
- Immutable backups configured
- Employee awareness training completed

### Success Indicator

✔ Organization has visibility into security events

---

## Milestone 3 – Core Infrastructure Secured

**Target Date:** End of Month 4

### Deliverables

- Network segmentation completed
- Firewall deployed
- Vulnerability remediation completed
- Alert monitoring operational

### Success Indicator

✔ Critical attack paths disrupted

---

## Milestone 4 – Operational Readiness

**Target Date:** End of Month 6

### Deliverables

- Incident Response exercise completed
- Internal audit completed
- Board report delivered
- Year 2 roadmap approved

### Success Indicator

✔ MedDefense transitions into continuous security operations

---

# Risks to the Timeline

## Risk 1 – Procurement Delays

### Cause

Firewall hardware or cloud services may be delayed by vendors.

### Impact

Network segmentation cannot begin on schedule.

### Contingency Plan

- Order equipment during Month 1.
- Prioritize virtual appliances if physical hardware is delayed.
- Begin firewall policy development before hardware arrives.

---

## Risk 2 – Limited Security Resources

### Cause

MedDefense has only one Security Analyst and one Deputy CISO.

### Impact

Implementation tasks may compete with daily operational responsibilities.

### Contingency Plan

- Prioritize highest-risk activities first.
- Temporarily use SecurePoint Consulting for implementation support.
- Defer low-priority optimization tasks rather than delaying core controls.

---

# Roadmap Success Criteria

At the end of six months MedDefense should achieve:

- 100% MFA deployment for privileged accounts.
- Network segmentation implemented across all critical systems.
- Centralized logging operational through Wazuh.
- Immutable offsite backups tested successfully.
- More than 80% reduction in Critical vulnerabilities.
- Monthly Risk Register reviews established.
- Formal governance operating under NIST CSF 2.0.
- CIS Controls IG1 substantially implemented.
- Security awareness training completed by all employees.
- Board-approved roadmap for Year 2.

---

# Expected Outcomes

Successful completion of this roadmap will transform MedDefense from a reactive cybersecurity posture into a structured, risk-based security program aligned with NIST CSF 2.0, CIS Controls v8, and ISO/IEC 27001 principles.

The roadmap provides measurable milestones, clear ownership, defined dependencies, and realistic implementation timelines that enable continuous improvement while maximizing risk reduction within the approved **$120,000** annual cybersecurity budget.
