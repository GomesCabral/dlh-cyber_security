# 8. Budget Allocation

## Part 1 - The Selection

### Funded Controls

The following controls are **funded** because they maximize risk reduction while remaining within the available budget.

| Control | Annual Cost | Reason |
|---|---:|---|
| MFA Deployment | $8,000 | Highest ROI and protects VPN and administrative accounts. |
| Enterprise SIEM (Wazuh) | $25,000 | Improves visibility and reduces attacker dwell time. |
| Offsite Immutable Backups | $18,000 | Minimizes ransomware recovery costs. |
| Network Segmentation | $40,000 | Prevents lateral movement across the flat network. |
| Dedicated Firewall for Westside Clinic | $15,000 | Secures the remote clinic connection. |

**Total spend:** $106,000

**Budget:** $120,000

**Budget numeric:** 120000

**Budget remaining:** $14,000

---

### Deferred Controls

The following controls are **deferred** because the current budget is limited.

| Control | Annual Cost | Opportunity Cost |
|---|---:|---:|
| Sophos Intercept X (EDR Upgrade) | $32,000 | $700,000 ALE remains. |
| Medical Device Network Isolation | $28,000 | $90,000 ALE remains. |
| 24/7 Managed SOC | $150,000 | $170,000 ALE remains. |

---

### Rejected Controls

The following controls are **rejected** for this budget cycle only.

**Reject:** None permanently.

No control is permanently rejected because every proposed control provides measurable security value.

---

## Part 2 - Opportunity Cost

By **deferring** the Sophos Intercept X upgrade, MedDefense accepts approximately **$700,000** of annual risk exposure.

By **deferring** Medical Device Network Isolation, MedDefense accepts approximately **$90,000** of annual risk exposure.

By **deferring** a 24/7 Managed SOC, MedDefense accepts approximately **$170,000** of annual risk exposure.

---

## Part 3 - Alternative Allocation

### Alternative Allocation

| Control | Cost |
|---|---:|
| MFA Deployment | $8,000 |
| Enterprise SIEM | $25,000 |
| Offsite Immutable Backups | $18,000 |
| Network Segmentation | $40,000 |
| Medical Device Network Isolation | $28,000 |

**Alternative total spend:** $119,000

---

### Comparison

Primary recommendation:

- Cost: $106,000
- Budget remaining: $14,000
- Higher overall ALE reduction
- Leaves contingency funds for emergency remediation

Alternative recommendation:

- Cost: $119,000
- Budget remaining: $1,000
- Better protection for medical devices
- Less flexibility for unexpected incidents

The primary recommendation maximizes total risk reduction while staying comfortably below the $120,000 annual budget. The alternative allocation improves medical device protection but leaves almost no remaining budget for emergency security work.
