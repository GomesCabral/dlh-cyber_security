# 11. Control Selection

## Risk: RISK-001 – Ransomware on Billing Server

**Selected Control:** Network Segmentation (Server VLANs) + Immutable Offsite Backups

**CIS Control Mapping:**
- CIS Control 12.2 – Secure Network Architecture
- CIS Control 11.4 – Isolated Recovery Data

**NIST CSF Mapping:**
- PR.IR – Technology Infrastructure Resilience
- PR.DS – Data Security

**Control Type:** Preventive / Corrective

**Control Category:** Technical

**Implementation Cost:** $58,000 ($40,000 Segmentation + $18,000 Backups)

**Expected Risk Reduction:** Approximately 75% reduction in ransomware impact (ALE reduction ≈ $225,000/year)

**Dependencies:**
- Asset Inventory (CIS 1)
- Network documentation
- Backup validation

---

## Risk: RISK-002 – Patient Data Breach

**Selected Control:** Multi-Factor Authentication (MFA) + Enterprise SIEM

**CIS Control Mapping:**
- CIS Control 6.3 – MFA
- CIS Control 8.2 – Collect Audit Logs

**NIST CSF Mapping:**
- PR.AA – Identity Management
- DE.CM – Continuous Monitoring

**Control Type:** Preventive / Detective

**Control Category:** Technical

**Implementation Cost:** $33,000 ($8,000 MFA + $25,000 SIEM)

**Expected Risk Reduction:** Approximately 65% reduction in unauthorized access and data exfiltration.

**Dependencies:**
- Identity Management
- Centralized Logging

---

## Risk: RISK-003 – VPN Compromise

**Selected Control:** MFA for VPN + FortiGate Patch Management

**CIS Control Mapping:**
- CIS Control 6.4 – MFA for Remote Access
- CIS Control 7.3 – Automated Patch Management

**NIST CSF Mapping:**
- PR.AA
- PR.PS

**Control Type:** Preventive

**Control Category:** Technical

**Implementation Cost:** $8,000

**Expected Risk Reduction:** Approximately 80% reduction in VPN compromise likelihood.

**Dependencies:**
- VPN inventory
- Patch management process

---

## Risk: RISK-004 – Flat Network Lateral Movement

**Selected Control:** Network Segmentation

**CIS Control Mapping:**
- CIS Control 12.2 – Secure Network Architecture

**NIST CSF Mapping:**
- PR.IR

**Control Type:** Preventive

**Control Category:** Technical

**Implementation Cost:** $40,000

**Expected Risk Reduction:** Approximately 70% reduction in lateral movement opportunities.

**Dependencies:**
- Asset Inventory
- Network diagrams
- Firewall rule review

---

## Risk: RISK-005 – Medical Device Compromise

**Selected Control:** Medical Device Network Isolation

**CIS Control Mapping:**
- CIS Control 12.2
- CIS Control 13.1 – Network Monitoring

**NIST CSF Mapping:**
- PR.IR
- DE.CM

**Control Type:** Preventive

**Control Category:** Technical / Operational

**Implementation Cost:** $28,000

**Expected Risk Reduction:** Approximately 60% reduction in patient safety cyber risk.

**Dependencies:**
- Network Segmentation
- Medical device inventory

---

## Risk: RISK-006 – Windows XP MRI Workstation

**Selected Control:** Compensating Controls (Isolated VLAN + Strict Firewall Rules + Restricted Access)

**CIS Control Mapping:**
- CIS Control 4 – Secure Configuration
- CIS Control 12 – Network Infrastructure Management

**NIST CSF Mapping:**
- PR.PS
- PR.IR

**Control Type:** Compensating

**Control Category:** Technical / Operational

**Implementation Cost:** $6,000

**Expected Risk Reduction:** Approximately 50% reduction in exploitation risk.

**Dependencies:**
- Network Segmentation

---

## Risk: RISK-007 – Insider Data Leakage

**Selected Control:** Security Awareness Training + Quarterly Access Reviews

**CIS Control Mapping:**
- CIS Control 14
- CIS Control 5

**NIST CSF Mapping:**
- PR.AT
- PR.AA

**Control Type:** Preventive

**Control Category:** Administrative

**Implementation Cost:** $12,000

**Expected Risk Reduction:** Approximately 40% reduction in insider incidents.

**Dependencies:**
- HR participation
- Account inventory

---

## Risk: RISK-008 – Backup Compromise

**Selected Control:** Immutable Cloud Backup Replication

**CIS Control Mapping:**
- CIS Control 11.4

**NIST CSF Mapping:**
- RC.RP

**Control Type:** Corrective

**Control Category:** Technical

**Implementation Cost:** $18,000

**Expected Risk Reduction:** Approximately 85% reduction in recovery costs.

**Dependencies:**
- Existing backup infrastructure
- Recovery testing

---

## Risk: RISK-009 – Regulatory Non-Compliance

**Selected Control:** Formal Vulnerability Management Program + Quarterly Compliance Reviews

**CIS Control Mapping:**
- CIS Control 7
- CIS Control 17

**NIST CSF Mapping:**
- GV.RM
- ID.RA

**Control Type:** Administrative

**Control Category:** Administrative

**Implementation Cost:** $10,000

**Expected Risk Reduction:** Approximately 60% reduction in compliance exposure.

**Dependencies:**
- Risk Register
- Vulnerability scanning process

---

## Risk: RISK-010 – Lack of Security Monitoring

**Selected Control:** Enterprise SIEM (Wazuh)

**CIS Control Mapping:**
- CIS Control 8
- CIS Control 13

**NIST CSF Mapping:**
- DE.CM
- DE.AE

**Control Type:** Detective

**Control Category:** Technical

**Implementation Cost:** $25,000

**Expected Risk Reduction:** Approximately 65% reduction in attacker dwell time.

**Dependencies:**
- Centralized logging
- Time synchronization (NTP)

---

# Control Dependency Map

```
Asset Inventory (CIS 1)
        │
        ▼
Network Documentation
        │
        ▼
Network Segmentation (CIS 12)
        │
        ├──────────────► Medical Device Isolation
        │
        ├──────────────► Windows XP Isolation
        │
        └──────────────► Firewall Rule Optimization

Identity Management
        │
        ▼
MFA Deployment
        │
        ▼
VPN Protection

Centralized Logging
        │
        ▼
Enterprise SIEM
        │
        ▼
Continuous Monitoring
        │
        ▼
Incident Detection

Backup Infrastructure
        │
        ▼
Immutable Backups
        │
        ▼
Disaster Recovery

Security Awareness
        │
        ▼
Access Reviews
        │
        ▼
Reduced Insider Risk

Risk Register
        │
        ▼
Vulnerability Management
        │
        ▼
Compliance Reviews
```

---

# Control Implementation Priority

| Priority | Control |
|----------|---------|
| 1 | Asset Inventory & Network Documentation |
| 2 | MFA Deployment |
| 3 | Network Segmentation |
| 4 | Immutable Backups |
| 5 | Enterprise SIEM |
| 6 | VPN Hardening |
| 7 | Medical Device Isolation |
| 8 | Windows XP Compensating Controls |
| 9 | Security Awareness Training |
| 10 | Compliance & Vulnerability Management |

---

# Summary

The selected controls map every mitigated risk to both **CIS Controls v8** and **NIST CSF 2.0**, ensuring technical effectiveness, governance traceability and audit readiness. The dependency map demonstrates that foundational controls such as **Asset Inventory**, **Network Segmentation**, **MFA** and **Centralized Logging** must be implemented first because they enable several higher-level security capabilities. This implementation order also aligns with the cost-benefit analysis and the $120,000 security budget established in previous tasks.
