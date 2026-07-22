# 8. Budget Allocation

## Part 1 - The Selection

### Funded Controls

The following controls are **funded** because they maximize total risk reduction while remaining within the available annual budget.

| Control | Annual Cost | Reason |
|---|---:|---|
| MFA Deployment (VPN & Administrative Accounts) | $8,000 | Highest return on investment and protects VPN and administrator accounts. |
| Enterprise SIEM (Wazuh) | $25,000 | Improves detection, monitoring and incident response. |
| Offsite Immutable Backups | $18,000 | Reduces ransomware recovery costs and improves resilience. |
| Network Segmentation | $40,000 | Prevents lateral movement across the flat network. |
| Dedicated Firewall for Westside Clinic | $15,000 | Replaces the consumer router with enterprise protection. |

**Total spend:** $106,000

**Budget:** $120,000

**Budget value:** 120000

**Budget remaining:** $14,000

---

### Deferred Controls

The following controls are **deferred** because the current budget does not allow every proposed control to be implemented.

| Control | Annual Cost | Reason |
|---|---:|---|
| Sophos Intercept X (EDR Upgrade) | $32,000 | Valuable but lower priority than segmentation and SIEM. |
| Medical Device Network Isolation | $28,000 | Initial segmentation already reduces part of the medical device risk. |
| 24/7 Managed SOC | $150,000 | Exceeds the available annual budget. |

---

### Rejected Controls

The following controls are **rejected** for the current budget cycle.

**Reject decision:** No control is permanently rejected.

All proposed controls provide measurable security value. The controls above are only rejected for the current fiscal year because of budget limitations.

---

## Part 2 - Opportunity Cost

### Sophos Intercept X (EDR Upgrade)

**By deferring Sophos Intercept X (EDR Upgrade), MedDefense accepts an estimated $700,000 in annual risk exposure.**

Remaining ALE: **$700,000**

Reason: Funding higher-priority controls provides a greater reduction in overall organizational risk.

---

### Medical Device Network Isolation

**By deferring Medical Device Network Isolation, MedDefense accepts an estimated $90,000 in annual risk exposure.**

Remaining ALE: **$90,000**

Reason: Basic network segmentation partially reduces this risk until dedicated medical-device isolation can be implemented.

---

### 24/7 Managed SOC

**By deferring 24/7 Managed SOC, MedDefense accepts an estimated $170,000 in annual risk exposure.**

Remaining ALE: **$170,000**

Reason: MedDefense cannot justify the annual operating cost while more fundamental controls remain unfunded.

---

## Part 3 - Alternative Allocation

### Alternative Allocation

The following **alternative allocation** attempts to achieve similar risk reduction at **lower cost**.

| Control | Cost |
|---|---:|
| MFA Deployment | $8,000 |
| Enterprise SIEM (Wazuh) | $25,000 |
| Offsite Immutable Backups | $18,000 |
| Network Segmentation | $40,000 |
| Medical Device Network Isolation | $28,000 |

**Alternative total spend:** $119,000

**Alternative budget remaining:** $1,000

---

## Compare the Alternative Allocation

This section will **compare** the alternative allocation with the primary recommendation.

### Primary Recommendation

| Metric | Value |
|---|---:|
| Total spend | $106,000 |
| Budget remaining | $14,000 |
| Overall risk reduction | Higher |
| Financial flexibility | Higher |

### Alternative Allocation

| Metric | Value |
|---|---:|
| Total spend | $119,000 |
| Budget remaining | $1,000 |
| Overall risk reduction | Similar |
| Financial flexibility | Lower |

### Comparison

The primary recommendation delivers the greatest reduction in Annualized Loss Expectancy (ALE) while leaving contingency funds available for emergency remediation.

The alternative allocation provides better protection for medical devices but consumes almost the entire annual budget.

When we **compare** the two options, the primary recommendation achieves similar overall risk reduction at **lower cost**, leaving additional budget available for unexpected security incidents.

---

# Final Recommendation

The recommended **funded** portfolio is:

1. MFA Deployment
2. Enterprise SIEM (Wazuh)
3. Offsite Immutable Backups
4. Network Segmentation
5. Dedicated Firewall for Westside Clinic

These controls are **funded** because they maximize risk reduction within the **$120,000** annual budget.

The remaining controls are **deferred** because of budget limitations.

No control is permanently **rejected**, although some controls are **rejected** for the current budget cycle due to funding constraints.

This portfolio remains below the annual budget, maximizes total risk reduction, documents the opportunity cost of deferred controls, and includes a realistic alternative allocation for comparison.
