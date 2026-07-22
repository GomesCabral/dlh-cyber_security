# 5. The Risk Equation

## Scenario 1 – Ransomware Attack on Billing Server

**Asset:** billing-srv-01

### Asset Value (AV)

The asset value is based on business impact rather than hardware replacement.

- Billing downtime (18 days × $16,000/day): **$288,000**
- Recovery and forensic costs: **$85,000**
- HIPAA penalty (estimated): **$100,000**
- Financial records/business impact: **$100,000**

**AV = $573,000**

### Exposure Factor (EF)

A ransomware attack would severely disrupt operations but would not permanently destroy the asset.

**EF = 80% (0.8)**

### Single Loss Expectancy (SLE)

SLE = AV × EF

SLE = $573,000 × 0.8

**SLE = $458,400**

### Annualized Rate of Occurrence (ARO)

Healthcare intelligence estimates approximately one ransomware attack every 3–4 years.

**ARO = 0.29**

### Annualized Loss Expectancy (ALE)

ALE = SLE × ARO

ALE = $458,400 × 0.29

**ALE ≈ $132,936**

### Confidence

**Medium**

The largest uncertainty is the frequency of ransomware attacks (ARO).

---

# Scenario 2 – Patient Data Breach

**Asset:** EHR System

### Asset Value (AV)

- 50,000 records × $165 = **$8,250,000**
- HIPAA notification costs = **$25,000**
- Litigation exposure = **$200,000**
- Reputational loss = **$600,000**

**AV = $9,075,000**

### Exposure Factor (EF)

A successful breach triggers nearly all associated costs.

**EF = 100% (1.0)**

### Single Loss Expectancy (SLE)

SLE = $9,075,000 × 1

**SLE = $9,075,000**

### Annualized Rate of Occurrence (ARO)

Estimated once every three years.

**ARO = 0.33**

### Annualized Loss Expectancy (ALE)

ALE = $9,075,000 × 0.33

**ALE ≈ $2,994,750**

### Confidence

**High**

Most values are based on healthcare industry statistics.

---

# Scenario 3 – Negligent Insider Data Theft

**Asset:** Patient Data

### Asset Value (AV)

The average healthcare negligent insider incident costs approximately:

**AV = $120,000**

### Exposure Factor (EF)

Most of the incident cost is incurred once the event occurs.

**EF = 100% (1.0)**

### Single Loss Expectancy (SLE)

SLE = $120,000

### Annualized Rate of Occurrence (ARO)

MedDefense estimates approximately 2–3 incidents each year.

**ARO = 2.5**

### Annualized Loss Expectancy (ALE)

ALE = $120,000 × 2.5

**ALE = $300,000**

### Confidence

**High**

The incident frequency is supported by healthcare sector statistics.

---

# Scenario 4 – Medical Device Compromise

## Scenario A – Denial of Service

### Asset Value (AV)

- Seven infusion pumps = **$105,000**
- Operational disruption (5 days × $20,000) = **$100,000**

**AV = $205,000**

### Exposure Factor (EF)

Operations are severely disrupted but the devices are not permanently destroyed.

**EF = 80% (0.8)**

### Single Loss Expectancy (SLE)

SLE = $205,000 × 0.8

**SLE = $164,000**

### Annualized Rate of Occurrence (ARO)

Estimated once every ten years.

**ARO = 0.10**

### Annualized Loss Expectancy (ALE)

ALE = $164,000 × 0.10

**ALE = $16,400**

---

## Scenario B – Patient Safety Incident

### Asset Value (AV)

- Patient liability = **$5,000,000**
- FDA investigation = **$150,000**

**AV = $5,150,000**

### Exposure Factor (EF)

A successful patient safety incident would have catastrophic consequences.

**EF = 100% (1.0)**

### Single Loss Expectancy (SLE)

**SLE = $5,150,000**

### Annualized Rate of Occurrence (ARO)

Estimated once every fifty years.

**ARO = 0.02**

### Annualized Loss Expectancy (ALE)

ALE = $5,150,000 × 0.02

**ALE = $103,000**

### Confidence

**Low**

The probability of a serious patient safety incident is difficult to estimate.

---

# Scenario 5 – VPN Compromise

**Asset:** Entire MedDefense Network

### Asset Value (AV)

This scenario combines the impact of ransomware and patient data theft.

- Billing server impact = **$573,000**
- EHR breach impact = **$9,075,000**

**AV = $9,648,000**

### Exposure Factor (EF)

A VPN compromise may expose the entire environment.

**EF = 100% (1.0)**

### Single Loss Expectancy (SLE)

**SLE = $9,648,000**

### Annualized Rate of Occurrence (ARO)

Healthcare intelligence estimates approximately one successful compromise every three years.

**ARO = 0.30**

### Annualized Loss Expectancy (ALE)

ALE = $9,648,000 × 0.30

**ALE = $2,894,400**

### Confidence

**Medium**

The largest uncertainty is the likelihood that a VPN compromise would lead to a full ransomware and data exfiltration campaign.

---

# Summary Table

| Scenario | AV | EF | SLE | ARO | ALE | Confidence |
|----------|------------:|:---:|------------:|:---:|------------:|:---------:|
| Billing Server Ransomware | $573,000 | 80% | $458,400 | 0.29 | $132,936 | Medium |
| Patient Data Breach | $9,075,000 | 100% | $9,075,000 | 0.33 | $2,994,750 | High |
| Negligent Insider | $120,000 | 100% | $120,000 | 2.5 | $300,000 | High |
| Medical Device DoS | $205,000 | 80% | $164,000 | 0.10 | $16,400 | Medium |
| Medical Device Patient Safety | $5,150,000 | 100% | $5,150,000 | 0.02 | $103,000 | Low |
| VPN Compromise | $9,648,000 | 100% | $9,648,000 | 0.30 | $2,894,400 | Medium |

# Conclusion

The calculations demonstrate that not every vulnerability with the highest technical severity produces the highest financial risk. The EHR data breach and VPN compromise generate the largest Annualized Loss Expectancy (ALE) because they combine regulatory penalties, operational disruption, reputational damage and business losses. Quantitative risk analysis helps MedDefense prioritize security investments based on expected annual financial impact rather than relying only on qualitative severity ratings such as Critical or High.
