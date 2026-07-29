# 7. The Risk Register Update

## Goal

Update the MedDefense Risk Register using the new threat intelligence provided by the Crimson Tide advisory. This demonstrates that a Risk Register is a living document that must evolve whenever new intelligence changes the organisation's risk profile.

---

# Part 1 – Updated Existing Risk Entry

## Existing Risk

| Field | Updated Value |
|--------|---------------|
| Risk ID | RISK-004 |
| Risk Name | Ransomware affecting MedDefense infrastructure |
| Threat Source | Crimson Tide (CT) Ransomware-as-a-Service Affiliate |
| Asset | Entire MedDefense production environment |
| Threat Event | Successful ransomware attack resulting in data theft, encryption and operational disruption |
| Vulnerability | Flat network, vulnerable FortiGate VPN, RC4-enabled Kerberos, unencrypted databases, unencrypted backups |
| Existing Controls | Firewall, antivirus, security monitoring, backup procedures, security roadmap |
| Likelihood | **Very High** |
| Impact | Critical |
| Original ARO | 0.30 |
| Updated ARO | **1.00** |
| Single Loss Expectancy (SLE) | $400,000 |
| Updated ALE | **$400,000** |
| Risk Owner | James Chen (CISO) |
| Treatment Decision | Mitigate Immediately |

### Updated Treatment Justification

The previous mitigation strategy remains valid but must be accelerated. The Crimson Tide advisory confirms that organisations matching MedDefense's infrastructure are currently being targeted using the same vulnerabilities identified during previous assessments. Delaying remediation is no longer acceptable because the likelihood of exploitation has significantly increased.

---

## New Key Risk Indicator (KRI)

The following indicators should immediately trigger incident response:

- FortiGate SSL-VPN authentication anomalies.
- Requests to `/remote/logincheck` containing oversized payloads.
- Unexpected FortiGate CLI activity.
- Large outbound transfers to Mega.nz or other cloud-storage providers.
- Detection of `Rclone.exe`.
- Unexpected Group Policy Object creation.
- Multiple Kerberos authentication failures.
- Unexpected VPN logins outside normal business hours.

Any of these indicators may suggest Crimson Tide activity.

---

# Part 2 – New Risk Entry

## RISK-NEW-001

| Field | Value |
|--------|-------|
| Risk ID | RISK-NEW-001 |
| Risk Name | Exploitation of CVE-2023-27997 on FortiGate SSL-VPN |
| Asset | FortiGate 100F |
| Threat Source | Crimson Tide / External Threat Actor |
| Threat Event | Remote Code Execution on FortiGate appliance |
| Vulnerability | FortiOS 7.0.9 vulnerable to CVE-2023-27997 |
| Existing Controls | Firewall configuration only |
| Missing Control | Security update to FortiOS 7.0.14 |
| Likelihood | Very High |
| Impact | Critical |
| Risk Rating | Critical |
| Existing ALE Contribution | Approximately $400,000 annual ransomware exposure |
| Risk Owner | Sarah Park |
| Recommended Treatment | Patch Immediately |
| Treatment Status | Waiting for support contract renewal |
| Residual Risk | Medium after successful patch deployment |

---

## Cost-Benefit Analysis

### Annual Support Contract

```text
FortiGate Support Renewal = $2,400
```

### Estimated Annual Risk Reduction

```text
Updated ALE = $400,000
```

Even if patching reduced the ransomware risk by only **1%**:

```text
Risk Reduction = $4,000
```

Since:

```text
$4,000 > $2,400
```

the support renewal already produces a positive return on investment.

A realistic reduction of 70% produces:

```text
Annual Risk Reduction = $280,000
```

Therefore the patching cost is overwhelmingly justified.

### Treatment Decision

**Implement immediately.**

Failure to renew the support contract prevents installation of the security update and leaves the primary perimeter device exposed to an actively exploited vulnerability.

---

# Part 3 – Register Governance Test

## Does the Crimson Tide Advisory Trigger an Out-of-Cycle Risk Register Review?

**Yes.**

The governance process defined in Project 1x03 requires an immediate review whenever significant threat intelligence changes the organisation's risk exposure.

Typical review triggers include:

- Discovery of a new critical vulnerability.
- Active exploitation affecting the organisation's sector.
- Major change in likelihood or impact.
- Significant security incident.
- New regulatory or business requirements.

### Why Crimson Tide Meets the Criteria

The advisory satisfies multiple review triggers simultaneously:

- Active ransomware campaign targeting healthcare organisations.
- MedDefense operates the same vulnerable FortiGate version.
- Three affected hospitals are located within MedDefense's region.
- Hospital C is only 45 miles away.
- The advisory specifically identifies the same weaknesses previously documented by MedDefense:
  - Vulnerable FortiGate VPN.
  - Flat internal network.
  - RC4-enabled Kerberos.
  - Unencrypted databases.
  - Unencrypted backups.

These changes significantly increase the Annual Rate of Occurrence (ARO) and therefore require an immediate update of the Risk Register.

---

# Updated Risk Summary

| Risk | Previous Status | Updated Status |
|------|-----------------|----------------|
| Ransomware | High | Critical |
| FortiGate CVE-2023-27997 | Not Present | New Critical Risk |
| ARO | 0.30 | 1.00 |
| ALE | $120,000 | $400,000 |
| Treatment Priority | Phase 1 | Immediate |
| Board Action | Planned Investment | Emergency Approval Required |

---

# Final Conclusion

The Crimson Tide advisory fundamentally changes MedDefense's risk profile. The Risk Register must be updated immediately to reflect the increased likelihood of ransomware, the introduction of a specific FortiGate vulnerability risk, and the need for accelerated mitigation. The FortiGate support contract renewal is financially justified because its cost is insignificant compared with the updated Annualised Loss Expectancy. The advisory also satisfies the governance criteria for an out-of-cycle Risk Register review, demonstrating that risk management is a continuous process driven by evolving threat intelligence rather than a static annual exercise.
