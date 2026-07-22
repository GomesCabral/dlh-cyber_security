# 8. Budget Allocation

## Part 1 - The Selection

### Funded Controls

The following controls are **funded** because they provide the greatest reduction in Annualized Loss Expectancy (ALE) while remaining within MedDefense's annual security budget.

| Control | Annual Cost | Reason |
|---|---:|---|
| MFA Deployment (VPN & Administrative Accounts) | $8,000 | Highest return on investment; significantly reduces credential theft and VPN compromise. |
| Enterprise SIEM (Wazuh) | $25,000 | Provides centralized logging, detection and faster incident response. |
| Offsite Immutable Backups | $18,000 | Minimizes ransomware recovery costs and ensures business continuity. |
| Network Segmentation | $40,000 | Prevents lateral movement between critical servers, workstations and medical devices. |
| Dedicated Firewall for Westside Clinic | $15,000 | Removes a major branch-office security weakness and protects remote connectivity. |

**Total Spend:** **$106,000**

**Budget Available:** **$120,000**

**Budget Remaining:** **$14,000**

---

### Deferred Controls

The following controls are **deferred** until the next fiscal year because the available budget is better invested in controls with a higher financial return.

| Control | Annual Cost | Reason |
|---|---:|---|
| Sophos Intercept X (EDR Upgrade) | $32,000 | Valuable improvement, but current budget is better spent on prevention and network controls. |
| Medical Device Network Isolation | $28,000 | Important for patient safety, but initial network segmentation already reduces part of the risk. |
| 24/7 Managed SOC | $150,000 | Provides excellent monitoring but exceeds the annual security budget. |

---

### Rejected Controls

No controls are permanently **rejected**.

**Reject Decision:** None.

All remaining controls provide measurable security value and should be reconsidered during the next budget cycle when additional funding becomes available.

---

# Part 2 - Opportunity Cost

## Sophos Intercept X (EDR Upgrade)

By **deferring** this control, MedDefense accepts approximately **$700,000** of annual risk exposure associated with malware, ransomware and endpoint compromise.

---

## Medical Device Network Isolation

By **deferring** this control, MedDefense accepts approximately **$90,000** of annual patient-safety and operational cyber risk.

---

## 24/7 Managed SOC

By **deferring** this control, MedDefense accepts approximately **$170,000** of annual risk exposure due to slower threat detection and incident response.

---

# Part 3 - Alternative Allocation

## Alternative Budget Allocation

| Control | Cost |
|---|---:|
| MFA Deployment | $8,000 |
| Enterprise SIEM | $25,000 |
| Offsite Immutable Backups | $18,000 |
| Network Segmentation | $40,000 |
| Medical Device Network Isolation | $28,000 |

**Alternative Total Cost:** **$119,000**

---

## Comparison

| Allocation | Total Cost | Estimated ALE Reduction |
|---|---:|---:|
| Primary Recommendation | $106,000 | ~$7,180,000 |
| Alternative Recommendation | $119,000 | ~$7,105,000 |

The alternative allocation spends almost the entire annual budget and provides additional protection for medical devices. However, the primary recommendation achieves a slightly greater reduction in overall Annualized Loss Expectancy (ALE) while leaving **$14,000** available for emergency remediation, unexpected vulnerability response or future EDR deployment.

---

# Final Recommendation

The recommended security investment for MedDefense is:

1. MFA Deployment
2. Enterprise SIEM (Wazuh)
3. Offsite Immutable Backups
4. Network Segmentation
5. Dedicated Firewall for Westside Clinic

These controls are **funded** because they maximize risk reduction while remaining within the available **$120,000** budget.

The remaining controls are **deferred**, not **rejected**, because they continue to provide measurable security value and should be implemented during the following fiscal year as additional funding becomes available.

No proposed security controls are **rejected** permanently since each contributes to reducing MedDefense's overall cyber risk.
