# 8. Budget Allocation

## Part 1 - The Selection

### Funded Controls

The following controls are **funded** because they maximize overall risk reduction while remaining within MedDefense's annual cybersecurity budget.

| Control | Annual Cost | Reason |
|---|---:|---|
| MFA Deployment (VPN & Administrative Accounts) | $8,000 | Highest return on investment and significantly reduces credential theft and unauthorized remote access. |
| Enterprise SIEM (Wazuh) | $25,000 | Provides centralized logging, monitoring and faster incident detection. |
| Offsite Immutable Backups | $18,000 | Greatly reduces ransomware recovery costs and improves business continuity. |
| Network Segmentation | $40,000 | Prevents lateral movement across the flat network and protects critical assets. |
| Dedicated Firewall for Westside Clinic | $15,000 | Eliminates a major weakness at the remote clinic by replacing the consumer-grade firewall. |

**Total spend:** $106,000

**Budget:** $120,000

**Budget value:** 120000

**Budget remaining:** $14,000

---

## Deferred Controls

The following controls are **deferred** because they provide security value but cannot be funded during the current fiscal year.

| Control | Annual Cost | Reason |
|---|---:|---|
| Sophos Intercept X (EDR Upgrade) | $32,000 | Deferred because MFA, SIEM and Network Segmentation provide greater immediate reduction in organizational risk. |
| Medical Device Network Isolation | $28,000 | Deferred because Network Segmentation already reduces part of the medical-device attack surface. Dedicated isolation will be implemented during the next budget cycle. |

---

## Rejected Controls

The following control is **rejected** because it is not financially justified for MedDefense's current maturity level.

| Control | Annual Cost | Reason for Rejection |
|---|---:|---|
| 24/7 Managed SOC | $150,000 | Rejected because the annual operating cost exceeds the entire cybersecurity budget. MedDefense does not yet have mature logging, monitoring and incident response processes that would justify a managed SOC. Implementing foundational controls first provides substantially greater ALE reduction for a much lower investment. |

**Reject decision:** Reject implementation of a 24/7 outsourced Managed SOC during the current security strategy.

This rejection is based on cost-benefit analysis, organizational maturity and return on investment, not because the control lacks security value.

---

# Part 2 - Opportunity Cost

## Sophos Intercept X (EDR Upgrade)

**By deferring Sophos Intercept X (EDR Upgrade), MedDefense accepts an estimated $700,000 in annual risk exposure.**

Remaining ALE: **$700,000**

Reason:

Funding Network Segmentation, MFA and SIEM first produces a greater overall reduction in enterprise cyber risk.

---

## Medical Device Network Isolation

**By deferring Medical Device Network Isolation, MedDefense accepts an estimated $90,000 in annual risk exposure.**

Remaining ALE: **$90,000**

Reason:

Existing Network Segmentation partially mitigates medical-device exposure until dedicated isolation can be implemented next year.

---

# Part 3 - Alternative Allocation

## Alternative Allocation

Instead of funding the **Dedicated Firewall for Westside Clinic**, MedDefense could choose to fund **Medical Device Network Isolation**.

| Control | Annual Cost |
|---|---:|
| MFA Deployment | $8,000 |
| Enterprise SIEM (Wazuh) | $25,000 |
| Offsite Immutable Backups | $18,000 |
| Network Segmentation | $40,000 |
| Medical Device Network Isolation | $28,000 |

**Alternative total spend:** $119,000

**Alternative budget remaining:** $1,000

---

# Compare the Alternative Allocation

## Primary Recommendation

### Funded Controls

- MFA Deployment
- Enterprise SIEM
- Offsite Immutable Backups
- Network Segmentation
- Dedicated Firewall for Westside Clinic

### Benefits

- Secures the exposed Westside Clinic connection.
- Reduces VPN and branch-office compromise risk.
- Improves protection against ransomware.
- Preserves $14,000 for emergency remediation.
- Produces the highest overall reduction in Annualized Loss Expectancy (ALE).

### Residual Risk

- Medical devices remain only partially protected until dedicated isolation is implemented.

---

## Alternative Allocation

### Funded Controls

- MFA Deployment
- Enterprise SIEM
- Offsite Immutable Backups
- Network Segmentation
- Medical Device Network Isolation

### Benefits

- Stronger protection for infusion pumps and Philips monitoring systems.
- Reduces attacker movement into medical IoT devices.
- Improves patient safety by limiting exposure of clinical equipment.

### Residual Risk

- Westside Clinic continues operating behind its existing consumer-grade firewall.
- The remote clinic remains a weaker external entry point.
- VPN and branch-office attacks remain more likely.

---

## Comparison

When we **compare** the two allocations, the trade-off is clear.

The **primary recommendation** focuses on reducing the greatest enterprise-wide cyber risk by protecting the remote clinic, strengthening the network perimeter and preserving contingency funds for unexpected remediation.

The **alternative allocation** sacrifices the Dedicated Firewall for Westside Clinic in order to improve medical device security. This provides better protection for patient-care equipment but leaves the remote clinic exposed to external attacks and consumes almost the entire annual budget.

The alternative allocation does **not** provide equivalent protection. It prioritizes patient safety over perimeter security, while the primary recommendation prioritizes reducing the highest-likelihood attack path identified during the threat assessment.

Although both allocations significantly reduce organizational risk, the **primary recommendation remains the preferred option** because it delivers greater overall enterprise risk reduction, protects the most likely attack vector, maintains budget flexibility and better aligns with MedDefense's current threat landscape.

---

# Final Recommendation

## Funded Controls

- MFA Deployment
- Enterprise SIEM (Wazuh)
- Offsite Immutable Backups
- Network Segmentation
- Dedicated Firewall for Westside Clinic

## Deferred Controls

- Sophos Intercept X (EDR Upgrade)
- Medical Device Network Isolation

## Rejected Controls

- 24/7 Managed SOC

The selected funded portfolio remains below the **$120,000** annual budget while maximizing overall organizational risk reduction.

The deferred controls continue to provide value and should be reviewed during the next fiscal year.

The Managed SOC is **rejected** for the current security strategy because its cost exceeds the available budget and MedDefense will obtain a substantially greater return on investment by first implementing foundational security controls.
