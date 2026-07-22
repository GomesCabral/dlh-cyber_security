# 8. Budget Allocation

## Part 1 - The Selection

### Funded Controls

The following controls are **funded** because they maximize total risk reduction while remaining within the annual security budget.

| Control | Annual Cost | Reason |
|---|---:|---|
| MFA Deployment (VPN & Administrative Accounts) | $8,000 | Highest ROI and significantly reduces credential theft. |
| Enterprise SIEM (Wazuh) | $25,000 | Improves detection and incident response. |
| Offsite Immutable Backups | $18,000 | Reduces ransomware recovery costs. |
| Network Segmentation | $40,000 | Prevents lateral movement across the flat network. |
| Dedicated Firewall for Westside Clinic | $15,000 | Protects the remote clinic and replaces the consumer router. |

**Total spend:** $106,000

**Budget:** $120,000

**Budget value:** 120000

**Budget remaining:** $14,000

---

### Deferred Controls

The following controls are **deferred** until the next fiscal year because higher-value controls were selected first.

| Control | Annual Cost | Reason |
|---|---:|---|
| Sophos Intercept X (EDR Upgrade) | $32,000 | Valuable, but lower priority than segmentation and SIEM. |
| Medical Device Network Isolation | $28,000 | Some risk is already reduced through network segmentation. |
| 24/7 Managed SOC | $150,000 | Exceeds the available annual budget. |

---

### Rejected Controls

The following controls are **rejected** for the current budget cycle.

**Reject decision:** No control is permanently rejected.

All remaining controls provide security value and should be reconsidered when additional funding becomes available.

---

# Part 2 - Opportunity Cost

### Sophos Intercept X (EDR Upgrade)

**By deferring Sophos Intercept X (EDR Upgrade), MedDefense accepts an estimated $700,000 in annual risk exposure.**

Remaining ALE: **$700,000**

---

### Medical Device Network Isolation

**By deferring Medical Device Network Isolation, MedDefense accepts an estimated $90,000 in annual risk exposure.**

Remaining ALE: **$90,000**

---

### 24/7 Managed SOC

**By deferring 24/7 Managed SOC, MedDefense accepts an estimated $170,000 in annual risk exposure.**

Remaining ALE: **$170,000**

---

# Part 3 - Alternative Allocation

## Alternative Allocation

| Control | Cost |
|---|---:|
| MFA Deployment | $8,000 |
| Enterprise SIEM | $25,000 |
| Offsite Immutable Backups | $18,000 |
| Network Segmentation | $40,000 |
| Medical Device Network Isolation | $28,000 |

**Alternative total spend:** $119,000

**Alternative budget remaining:** $1,000

---

## Comparison

### Primary Recommendation

- Total spend: $106,000
- Budget remaining: $14,000
- Higher overall ALE reduction
- Leaves contingency funds for emergency remediation

### Alternative Recommendation

- Total spend: $119,000
- Budget remaining: $1,000
- Better protection for medical devices
- Less budget flexibility
- Slightly lower overall ALE reduction

### Trade-off

The **primary recommendation** maximizes total risk reduction while keeping costs below the $120,000 annual budget.

The **alternative allocation** provides stronger protection for medical devices but leaves almost no remaining budget for unexpected remediation work or emergency security improvements.

---

# Final Recommendation

The recommended funded portfolio is:

1. MFA Deployment
2. Enterprise SIEM (Wazuh)
3. Offsite Immutable Backups
4. Network Segmentation
5. Dedicated Firewall for Westside Clinic

These controls are **funded** because they provide the greatest reduction in Annualized Loss Expectancy (ALE) for the available budget.

The remaining controls are **deferred** because the current budget cannot fund every proposed control.

No proposed control is permanently **rejected** because every control provides measurable security value.
