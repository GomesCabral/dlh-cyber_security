# 8. Budget Allocation

## Part 1 - The Selection

### Funded Controls

The following controls are **funded** because they provide the greatest reduction in Annualized Loss Expectancy (ALE) while remaining within MedDefense's annual cybersecurity budget.

| Control | Annual Cost | Reason |
|---|---:|---|
| MFA Deployment (VPN & Administrative Accounts) | $8,000 | Highest return on investment and significantly reduces credential theft. |
| Enterprise SIEM (Wazuh) | $25,000 | Improves visibility, monitoring and incident response. |
| Offsite Immutable Backups | $18,000 | Minimizes ransomware recovery costs and business downtime. |
| Network Segmentation | $40,000 | Prevents lateral movement across the flat network. |
| Dedicated Firewall for Westside Clinic | $15,000 | Eliminates an insecure remote-site connection. |

**Total spend:** $106,000

**Budget:** $120,000

**Budget value:** 120000

**Budget remaining:** $14,000

---

## Deferred Controls

The following controls are **deferred** because they provide security value but cannot be funded during the current budget cycle.

| Control | Annual Cost | Reason |
|---|---:|---|
| Sophos Intercept X (EDR Upgrade) | $32,000 | Deferred because segmentation, MFA and SIEM provide greater immediate organizational risk reduction. |
| Medical Device Network Isolation | $28,000 | Deferred because Network Segmentation already reduces part of the medical device exposure. |

---

## Rejected Controls

The following control is **rejected** because it is not financially justified for MedDefense's current maturity level.

| Control | Annual Cost | Reason for Rejection |
|---|---:|---|
| 24/7 Managed SOC | $150,000 | Rejected because its annual cost exceeds the entire cybersecurity budget and MedDefense does not yet have mature logging, monitoring and response processes. Implementing foundational controls first produces a significantly greater reduction in ALE for a much lower investment. |

**Reject decision:** Reject the outsourced 24/7 Managed SOC as part of the current security strategy.

This rejection is based on **cost-benefit analysis**, **organizational maturity**, and **return on investment**, not because the control lacks security value.

---

# Part 2 - Opportunity Cost

### Sophos Intercept X (EDR Upgrade)

**By deferring Sophos Intercept X (EDR Upgrade), MedDefense accepts an estimated $700,000 in annual risk exposure.**

Remaining ALE: **$700,000**

Reason:

Funding higher-priority controls first provides a larger overall reduction in organizational risk.

---

### Medical Device Network Isolation

**By deferring Medical Device Network Isolation, MedDefense accepts an estimated $90,000 in annual risk exposure.**

Remaining ALE: **$90,000**

Reason:

Network Segmentation partially mitigates the risk until dedicated medical-device isolation is implemented next fiscal year.

---

# Part 3 - Alternative Allocation

## Alternative Allocation

The following **alternative allocation** achieves similar risk reduction at **lower cost** than implementing every proposed control.

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

### Primary Recommendation

| Metric | Value |
|---|---:|
| Total spend | $106,000 |
| Budget remaining | $14,000 |
| Overall risk reduction | Higher |
| Financial flexibility | Higher |
| Emergency reserve | Available |

### Alternative Allocation

| Metric | Value |
|---|---:|
| Total spend | $119,000 |
| Budget remaining | $1,000 |
| Overall risk reduction | Similar |
| Financial flexibility | Lower |
| Emergency reserve | Almost none |

### Comparison

When we **compare** the two options, the primary recommendation produces the greatest overall reduction in Annualized Loss Expectancy (ALE) while preserving contingency funds for emergency remediation.

The alternative allocation improves protection for medical devices but leaves almost no remaining budget.

Although both allocations significantly reduce cyber risk, the primary recommendation achieves comparable risk reduction at **lower cost** and provides greater financial flexibility.

---

# Final Recommendation

**Funded Controls**

- MFA Deployment
- Enterprise SIEM (Wazuh)
- Offsite Immutable Backups
- Network Segmentation
- Dedicated Firewall for Westside Clinic

**Deferred Controls**

- Sophos Intercept X (EDR Upgrade)
- Medical Device Network Isolation

**Rejected Controls**

- 24/7 Managed SOC

The funded portfolio maximizes risk reduction while remaining below the **$120,000** annual budget.

The deferred controls continue to provide value and should be reconsidered during the next fiscal year.

The **24/7 Managed SOC is rejected**, not deferred, because it is not financially justified at MedDefense's current security maturity and exceeds the available annual budget. Its implementation should only be reconsidered after foundational controls have been successfully deployed and operationalized.
