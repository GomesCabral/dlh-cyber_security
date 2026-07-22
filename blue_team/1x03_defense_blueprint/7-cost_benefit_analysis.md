# 7. Cost-Benefit Analysis

## Control 1 – Network Segmentation
- **CIS Control:** 12 – Network Infrastructure Management
- **Annual Cost:** **$40,000**
  - VLAN implementation: $25,000
  - Switch/firewall configuration: $10,000
  - Maintenance: $5,000
- **Risk(s) Addressed:** VPN compromise, EHR breach, Billing ransomware, Medical IoT
- **ALE Reduction:** **$2,500,000**
- **Net Value:** $2,500,000 − $40,000 = **$2,460,000**
- **Verdict:** Justified
- **Recommendation:** Implement immediately because segmentation reduces lateral movement across the flat network.

---

## Control 2 – MFA for VPN and Administrative Accounts
- **CIS Control:** 6 – Access Control Management
- **Annual Cost:** **$8,000**
  - O365 E3 licensing: Included
  - Deployment/training: $8,000
- **Risk(s) Addressed:** VPN compromise, credential theft
- **ALE Reduction:** **$2,100,000**
- **Net Value:** **$2,092,000**
- **Verdict:** Justified
- **Recommendation:** Implement immediately because it is low cost with very high risk reduction.

---

## Control 3 – Enterprise SIEM (Wazuh)
- **CIS Control:** 8 & 13
- **Annual Cost:** **$25,000**
  - Server infrastructure: $5,000
  - Deployment: $15,000
  - Maintenance: $5,000
- **Risk(s) Addressed:** EHR breach, ransomware, insider threats
- **ALE Reduction:** **$1,500,000**
- **Net Value:** **$1,475,000**
- **Verdict:** Justified
- **Recommendation:** Implement to improve detection and reduce attacker dwell time.

---

## Control 4 – Offsite Immutable Backups
- **CIS Control:** 11 – Data Recovery
- **Annual Cost:** **$18,000**
- **Risk(s) Addressed:** Billing ransomware, EHR ransomware
- **ALE Reduction:** **$900,000**
- **Net Value:** **$882,000**
- **Verdict:** Justified
- **Recommendation:** Implement to ensure ransomware recovery.

---

## Control 5 – Sophos Intercept X (EDR)
- **CIS Control:** 10 – Malware Defenses
- **Annual Cost:** **$32,000**
- **Risk(s) Addressed:** Malware, ransomware, endpoint compromise
- **ALE Reduction:** **$700,000**
- **Net Value:** **$668,000**
- **Verdict:** Justified
- **Recommendation:** Upgrade all endpoints and servers.

---

## Control 6 – Dedicated Firewall for Westside Clinic
- **CIS Control:** 12 – Network Infrastructure Management
- **Annual Cost:** **$15,000**
- **Risk(s) Addressed:** Branch compromise
- **ALE Reduction:** **$180,000**
- **Net Value:** **$165,000**
- **Verdict:** Justified
- **Recommendation:** Replace the consumer router with an enterprise firewall.

---

## Control 7 – 24/7 Managed SOC
- **CIS Control:** 13 – Network Monitoring and Defense
- **Annual Cost:** **$150,000**
- **Risk(s) Addressed:** All major cyber incidents
- **ALE Reduction:** **$170,000**
- **Net Value:** **$20,000**
- **Verdict:** Marginal
- **Recommendation:** Defer until the security program matures because the cost exceeds the current budget.

---

## Control 8 – Medical Device Network Isolation
- **CIS Control:** 12 & 13
- **Annual Cost:** **$28,000**
- **Risk(s) Addressed:** Medical IoT compromise
- **ALE Reduction:** **$90,000**
- **Net Value:** **$62,000**
- **Verdict:** Justified
- **Recommendation:** Implement after core network segmentation.

---

# Cost-Benefit Summary

| Rank | Control | Annual Cost | ALE Reduction | Net Value | Verdict |
|---:|---|---:|---:|---:|---|
|1|Network Segmentation|$40,000|$2,500,000|$2,460,000|Justified|
|2|MFA Deployment|$8,000|$2,100,000|$2,092,000|Justified|
|3|Enterprise SIEM|$25,000|$1,500,000|$1,475,000|Justified|
|4|Offsite Immutable Backups|$18,000|$900,000|$882,000|Justified|
|5|EDR Upgrade|$32,000|$700,000|$668,000|Justified|
|6|Dedicated Firewall|$15,000|$180,000|$165,000|Justified|
|7|Medical Device Isolation|$28,000|$90,000|$62,000|Justified|
|8|24/7 Managed SOC|$150,000|$170,000|$20,000|Marginal|

# Budget Recommendation

**Annual Security Budget:** $120,000

Recommended controls for the first year:

- MFA Deployment ($8,000)
- Enterprise SIEM ($25,000)
- Offsite Immutable Backups ($18,000)
- Network Segmentation ($40,000)
- Dedicated Firewall ($15,000)

**Total:** **$106,000**

The remaining budget can be reserved for contingency or phased implementation of EDR. The Managed SOC should be deferred because it exceeds the annual budget and currently provides the lowest return on investment relative to its cost.

# Conclusion

Cost-benefit analysis demonstrates that security investments should be prioritized using financial impact rather than technical severity alone. Network segmentation, MFA, SIEM and immutable backups provide the highest reduction in Annualized Loss Expectancy (ALE) and therefore deliver the greatest value for MedDefense's limited cybersecurity budget.
