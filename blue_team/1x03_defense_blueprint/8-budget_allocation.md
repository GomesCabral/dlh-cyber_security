# 8. Budget Allocation

## Part 1 – The Selection

### Funded Controls

| Control | Cost | Reason |
|---|---:|---|
| MFA Deployment | $8,000 | Highest ROI, protects VPN and administrator accounts. |
| Enterprise SIEM (Wazuh) | $25,000 | Improves detection and reduces attacker dwell time. |
| Offsite Immutable Backups | $18,000 | Critical for ransomware recovery. |
| Network Segmentation | $40,000 | Prevents lateral movement across the flat network. |
| Dedicated Firewall for Westside Clinic | $15,000 | Eliminates an exposed branch-office weakness. |

**Total Spend:** **$106,000**

**Budget:** **$120,000**

**Budget Remaining:** **$14,000**

---

### Deferred Controls (Next Fiscal Year)

| Control | Cost | Reason |
|---|---:|---|
| Sophos Intercept X (EDR Upgrade) | $32,000 | Valuable, but core prevention and detection controls provide greater ROI this year. |
| Medical Device Network Isolation | $28,000 | Important for patient safety, but basic segmentation already reduces some of the risk. |
| 24/7 Managed SOC | $150,000 | Exceeds the available annual budget and depends on stronger monitoring foundations first. |

---

### Rejected Controls

**None.**

All remaining controls provide security value and should be reconsidered as funding becomes available.

---

## Part 2 – Opportunity Cost

### Sophos Intercept X (EDR)

By deferring this control, MedDefense accepts approximately **$700,000** in additional annual risk exposure that could have been reduced through faster malware detection and response.

### Medical Device Network Isolation

By deferring this control, MedDefense accepts approximately **$90,000** in annual patient-safety and operational cyber risk.

### 24/7 Managed SOC

By deferring this control, MedDefense accepts approximately **$170,000** in annual risk exposure due to slower detection and response capabilities.

---

## Part 3 – Alternative Allocation

### Alternative Budget

| Control | Cost |
|---|---:|
| MFA Deployment | $8,000 |
| Enterprise SIEM | $25,000 |
| Offsite Immutable Backups | $18,000 |
| Network Segmentation | $40,000 |
| Medical Device Network Isolation | $28,000 |

**Total:** **$119,000**

### Comparison

| Allocation | Total Cost | Estimated Risk Reduction |
|---|---:|---:|
| Primary Recommendation | $106,000 | ~$7,180,000 |
| Alternative Allocation | $119,000 | ~$7,105,000 |

The alternative spends almost the full budget and provides stronger protection for medical devices. However, the primary recommendation delivers a slightly higher overall reduction in Annualized Loss Expectancy (ALE) while leaving $14,000 available for contingency, emergency patching, or future EDR deployment.

---

# Final Recommendation

The recommended allocation is:

1. MFA Deployment
2. Enterprise SIEM
3. Offsite Immutable Backups
4. Network Segmentation
5. Dedicated Firewall for Westside Clinic

This combination costs **$106,000**, stays within the **$120,000** budget, and delivers the highest overall reduction in financial risk based on the cost-benefit analysis from Task 7. The remaining budget should be reserved for unexpected remediation work or used to partially fund the EDR upgrade in the following fiscal year.
