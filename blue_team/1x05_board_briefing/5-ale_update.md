# 5. The ALE Update

## Goal

Recalculate MedDefense's ransomware Annualised Loss Expectancy (ALE) using the new Crimson Tide threat intelligence and determine whether the updated risk changes previous budget and control decisions.

---

# Important Assumption

The original 1x03 ransomware calculation is reconstructed from the figures used throughout the project:

```text
Original Single Loss Expectancy (SLE): $400,000
Original Annual Rate of Occurrence (ARO): 0.30
Original Annualised Loss Expectancy (ALE): $120,000
```

If the submitted 1x03 T6 file contains a different original SLE or ARO, those original figures should replace the reconstructed values below while keeping the same calculation method.

---

# Part 1 - Original vs Updated ALE

## ALE Formula

```text
ALE = SLE × ARO
```

Where:

- **SLE (Single Loss Expectancy)** is the expected financial loss from one successful ransomware incident.
- **ARO (Annual Rate of Occurrence)** is the estimated number of successful incidents expected per year.
- **ALE (Annualised Loss Expectancy)** is the expected yearly ransomware loss.

---

## Original Ransomware ALE

### Original Inputs

```text
SLE = $400,000
ARO = 0.30
```

An ARO of `0.30` means that MedDefense originally estimated approximately one successful ransomware incident every:

```text
1 ÷ 0.30 = 3.33 years
```

### Original Calculation

```text
ALE = SLE × ARO
ALE = $400,000 × 0.30
ALE = $120,000
```

### Original Result

```text
Original ALE = $120,000 per year
```

---

## New Crimson Tide Intelligence

The advisory provides the following new evidence:

- five similar hospitals compromised in ten days;
- three hospitals located in MedDefense's geographic region;
- Hospital C, 45 miles away, remains in active containment;
- all five incidents followed the same attack chain;
- MedDefense uses the same vulnerable FortiGate version range;
- MedDefense has the same flat-network, Kerberos, database-encryption and backup weaknesses;
- the campaign is active now rather than being a general sector-level possibility.

This intelligence does not provide the total number of comparable hospitals observed, so it cannot be used to calculate a statistically precise annual probability.

For example, directly calculating:

```text
5 attacks ÷ 10 days × 365 days = 182.5 attacks per year
```

would estimate campaign frequency across an unknown population, not MedDefense's individual probability. It must therefore not be used directly as MedDefense's ARO.

---

## Updated ARO

For emergency risk decision-making, the updated ARO is set to:

```text
Updated ARO = 1.0
```

An ARO of `1.0` means that MedDefense should plan for one successful ransomware incident within the next year if the exposed conditions remain unchanged.

This is justified because:

- the threat actor is actively attacking matching hospitals;
- MedDefense is in the affected geographic region;
- MedDefense runs vulnerable FortiOS 7.0.9;
- the vulnerability is pre-authentication and internet-facing;
- the internal environment matches the attacker's observed requirements;
- there is no reliable control blocking the complete attack chain;
- the support contract delay increases the vulnerable exposure window.

The value `1.0` is a scenario-based emergency estimate, not a claim that compromise is certain.

---

## Updated Ransomware ALE

### Updated Inputs

```text
SLE = $400,000
Updated ARO = 1.0
```

### Updated Calculation

```text
Updated ALE = SLE × Updated ARO
Updated ALE = $400,000 × 1.0
Updated ALE = $400,000
```

### Updated Result

```text
Updated ALE = $400,000 per year
```

---

## Change in ALE

```text
Original ALE = $120,000
Updated ALE  = $400,000
Increase     = $280,000
```

### Percentage Increase

```text
Percentage increase = (($400,000 - $120,000) ÷ $120,000) × 100
Percentage increase = ($280,000 ÷ $120,000) × 100
Percentage increase = 233.33%
```

The updated ALE is approximately:

```text
3.33 times the original ALE
```

---

## Original vs Updated Comparison

| Measure | Original Assessment | Updated Assessment |
|---|---:|---:|
| Single Loss Expectancy | $400,000 | $400,000 |
| Annual Rate of Occurrence | 0.30 | 1.00 |
| Annualised Loss Expectancy | $120,000 | $400,000 |
| Expected frequency | Once every 3.33 years | Once per year while exposure remains |
| Threat context | General healthcare ransomware risk | Active regional campaign against matching hospitals |

---

## What Changed?

The SLE did not change because the estimated financial impact of one successful ransomware incident remains $400,000.

The ARO changed because the probability environment changed.

Before the advisory, the estimate was based on general healthcare-sector statistics. The new intelligence shows:

- active exploitation;
- geographic proximity;
- matching technologies;
- matching vulnerabilities;
- confirmed success against peer organisations.

The increased ARO raises the ALE and changes the urgency of control investment.

---

# Part 2 - Budget Impact

## Cost-Benefit Formula

A control is financially justified when the expected annual risk reduction is greater than the annualised cost of the control.

```text
Annual Risk Reduction = ALE before control - ALE after control
```

```text
Net Benefit = Annual Risk Reduction - Annual Control Cost
```

```text
ROI = (Net Benefit ÷ Control Cost) × 100
```

---

## FortiGate Support Contract Renewal

### Cost

```text
Annual support contract cost = $2,400
```

### Risk Reduction Assumption

Renewing support allows MedDefense to obtain FortiOS 7.0.14 and remove the observed initial-access vulnerability.

A patch does not remove every ransomware path, so a conservative estimate assumes that it reduces the current ransomware risk by 70%.

### Residual ALE After Patching

```text
Residual ALE = $400,000 × 30%
Residual ALE = $120,000
```

### Annual Risk Reduction

```text
Annual Risk Reduction = $400,000 - $120,000
Annual Risk Reduction = $280,000
```

### Net Benefit

```text
Net Benefit = $280,000 - $2,400
Net Benefit = $277,600
```

### ROI

```text
ROI = ($277,600 ÷ $2,400) × 100
ROI = 11,566.67%
```

### Conclusion

```text
The FortiGate support renewal has an overwhelmingly positive ROI.
```

Even if patching reduced risk by only 1%, the expected annual benefit would be:

```text
$400,000 × 1% = $4,000
```

That amount still exceeds the $2,400 contract cost.

The break-even risk reduction is:

```text
$2,400 ÷ $400,000 = 0.006
```

```text
Break-even reduction = 0.6%
```

Therefore, the contract is financially justified if it reduces ransomware risk by more than 0.6%, which is an extremely low threshold.

---

## Previously Deferred or Not-Funded Controls

The prior strategy deferred or did not fully fund controls such as:

- enterprise EDR expansion;
- 24/7 managed SOC monitoring;
- dedicated medical-device isolation;
- advanced DLP and egress monitoring;
- accelerated database encryption and key management.

The updated ALE changes the cost-benefit position of these controls.

---

## Enterprise EDR

### Previous Position

Enterprise-wide EDR was deferred or not fully funded because its cost was considered high relative to the original $120,000 ALE and other immediate priorities.

### Updated Position

**Now justified, subject to vendor pricing.**

If EDR costs $35,000 per year and reduces ransomware risk by only 20%:

```text
Risk reduction = $400,000 × 20%
Risk reduction = $80,000
```

```text
Net benefit = $80,000 - $35,000
Net benefit = $45,000
```

```text
ROI = ($45,000 ÷ $35,000) × 100
ROI = 128.57%
```

---

## 24/7 Managed SOC

### Previous Position

A 24/7 managed SOC may previously have been judged not justified or deferred because of cost.

### Updated Position

**Potentially justified and should be re-evaluated immediately.**

If a managed SOC costs $60,000 per year and reduces the probability or impact of ransomware by 25%:

```text
Risk reduction = $400,000 × 25%
Risk reduction = $100,000
```

```text
Net benefit = $100,000 - $60,000
Net benefit = $40,000
```

```text
ROI = ($40,000 ÷ $60,000) × 100
ROI = 66.67%
```

This does not prove that every SOC proposal is justified. It shows that proposals previously rejected on cost grounds should be recalculated using the new ALE.

---

## Database Encryption and HSM-Backed KMS

### Updated Position

**Now strongly justified.**

Database encryption does not prevent every exfiltration path, but it prevents attackers from simply copying and reading raw database files when keys are protected separately.

Using the project estimate of approximately $1–$2 per managed key per month, the direct key-management cost is negligible compared with a $400,000 ALE.

---

## Immutable Offsite Backups

### Updated Position

**Now mandatory and financially justified.**

The advisory confirms that backup destruction occurred in all five incidents. Immutable backups reduce:

- recovery downtime;
- ransom pressure;
- probability of permanent data loss;
- business interruption;
- patient-safety impact.

Even a control costing tens of thousands of dollars may be justified if it materially reduces the $400,000 annualised exposure.

---

# Should the Board Approve Spending Beyond $120,000?

**Yes.**

The original annual security budget of $120,000 was equal to the original ransomware ALE. The updated ransomware ALE alone is now $400,000, before considering other risks such as:

- regulatory penalties;
- patient litigation;
- operational downtime;
- ambulance diversion;
- breach notification;
- reputation damage;
- recovery consulting;
- cyber-insurance consequences.

The Board should approve emergency spending beyond the original $120,000 budget when:

1. the control directly addresses the observed Crimson Tide attack chain;
2. the expected annual risk reduction exceeds the control cost;
3. the control can be implemented without unacceptable clinical disruption;
4. the control owner and implementation timeline are defined;
5. validation criteria are established.

---

# Recommended Emergency Budget Decisions

| Control | Decision | Reason |
|---|---|---|
| FortiGate support renewal — $2,400 | **Approve immediately** | Required to patch the active initial-access vulnerability; extremely positive ROI |
| Network segmentation acceleration | **Approve** | Breaks reconnaissance, lateral movement, backup access, and ransomware spread |
| Immutable offsite backups | **Approve** | Preserves recovery capability against the exact observed campaign |
| Enterprise EDR | **Approve or urgently procure short-term coverage** | Detects credential dumping, remote execution, Rclone and ransomware behaviour |
| 24/7 managed SOC | **Re-evaluate and approve emergency service if feasible** | Active regional campaign requires continuous detection |
| Database encryption and KMS | **Accelerate** | Reduces the value of stolen raw database files |
| Kerberos AES-only migration | **Approve maintenance work** | Reduces Kerberoasting risk |
| MFA expansion | **Accelerate immediately** | Reduces abuse of stolen remote-access credentials |

---

# Board-Level Conclusion

The Crimson Tide advisory increases MedDefense's ransomware ARO from `0.30` to an emergency scenario estimate of `1.0`.

This raises the ransomware ALE from:

```text
$120,000 to $400,000 per year
```

The increase of $280,000 demonstrates that threat intelligence directly changes financial risk.

The $2,400 FortiGate support renewal has a clear positive ROI and should be approved immediately. Controls previously deferred because of cost—especially EDR, continuous monitoring, immutable backups, segmentation, database encryption and stronger key management—must be re-evaluated using the updated ALE.

The Board should approve justified emergency spending beyond the original $120,000 budget because the cost of maintaining the current exposure is now substantially greater than the cost of remediation.


