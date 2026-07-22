# 16. Risk Appetite – MedDefense Health Systems

## Part 1 – Risk Appetite Statement

MedDefense Health Systems maintains a **moderate risk appetite** for operational and financial cybersecurity risks where the cost of mitigation exceeds the expected reduction in risk. However, the organization has **zero tolerance** for risks that could directly impact patient safety, violate healthcare regulations (HIPAA/GDPR), or cause prolonged loss of critical clinical services. Any risk with an inherent risk score of **20 or above (Likelihood × Impact)** or an **ALE greater than $500,000** requires approval from Executive Management and the Board before it can be accepted. All accepted risks must be documented in the Risk Register, assigned an owner, monitored continuously, and reviewed at least every six months.

---

# Part 2 – Risk Acceptance Decisions

## Risk: RISK-006 – Legacy Windows XP MRI Workstation

**Treatment Decision:** Accept

**Authority:** CEO with Board approval, based on recommendation from the Deputy CISO and IT Director.

**Justification:**

Replacing the MRI workstation would require replacing the entire MRI system before the current lease expires, costing approximately **$2.1 million**. The financial investment is not justified for the remaining 18 months of the lease, especially since compensating controls can significantly reduce the likelihood of exploitation.

**Compensating Measures:**

- Isolate the MRI workstation in a dedicated VLAN.
- Block all Internet access.
- Allow communications only with required PACS servers.
- Continuous monitoring through the SIEM.
- Quarterly security reviews.

**Review Trigger:**

- New CISA KEV vulnerability affecting Windows XP.
- Evidence of attempted compromise.
- MRI replacement project begins.
- Lease expiration.

---

## Risk: RISK-008 – Medical Device Network Isolation Delay

**Treatment Decision:** Accept

**Authority:** Deputy CISO (James Chen) with approval from Executive Management.

**Justification:**

The dedicated Medical Device Isolation project was deferred because the available budget was prioritized toward Network Segmentation, MFA, SIEM and Immutable Backups, which collectively reduce more overall organizational risk according to the ALE analysis.

**Compensating Measures:**

- Existing VLAN segmentation.
- Firewall access restrictions.
- Monthly vulnerability scans.
- Continuous log monitoring.
- Restricted administrator access.

**Review Trigger:**

- Medical device compromise.
- Budget approval for the next fiscal year.
- New critical medical-device vulnerabilities.
- Regulatory audit findings.

---

## Risk: RISK-010 – Lack of 24/7 Security Operations Center

**Treatment Decision:** Accept

**Authority:** CFO and CEO based on Board-approved security budget.

**Justification:**

The outsourced Managed SOC costs approximately **$150,000 annually**, exceeding the entire approved cybersecurity budget. The organization obtains greater financial benefit by implementing foundational preventive controls before investing in continuous managed monitoring.

**Compensating Measures:**

- Enterprise SIEM (Wazuh).
- Business-hours monitoring by the Security Analyst.
- Automated alerting.
- Incident response procedures.
- Weekly log review.

**Review Trigger:**

- Increase in security incidents.
- Security team expansion.
- Significant increase in regulatory requirements.
- Additional security funding.

---

# Part 3 – The Debate

## James Chen's Position (Mitigate)

The Windows XP MRI workstation represents an unacceptable cybersecurity risk because it runs an unsupported operating system that cannot receive security updates. Healthcare organizations remain frequent ransomware targets, and a compromise could directly affect patient care and regulatory compliance. Even with compensating controls, unsupported software always increases long-term organizational risk. Replacing or fully isolating the system should remain a high priority.

---

## Robert Kim's Position (Accept)

Replacing the MRI workstation requires replacing the entire MRI system, costing approximately **$2.1 million**, even though the equipment will naturally be replaced in only 18 months. Spending such a large amount now provides poor financial return compared with investing the same money in controls that reduce risk across the entire organization. Proper network isolation and monitoring substantially lower the likelihood of exploitation during the remaining service life. Accepting the risk temporarily is therefore a financially responsible decision.

---

## My Verdict

I agree primarily with **Robert Kim's position**, provided that strong compensating controls remain in place. Quantitative risk analysis demonstrates that replacing a $2.1 million MRI system for only 18 months of remaining service is not financially justified. By isolating the workstation, blocking unnecessary communications, continuously monitoring activity and scheduling regular reviews, MedDefense reduces the likelihood of compromise while preserving financial resources for higher-impact security improvements. This acceptance should remain temporary and automatically expire when the MRI replacement project begins or if the threat landscape significantly changes.

---

# Conclusion

Risk acceptance is not the absence of security; it is a documented governance decision supported by quantitative analysis, executive approval and continuous monitoring. MedDefense should mitigate risks that threaten patient safety or regulatory compliance whenever possible while accepting carefully selected operational risks when mitigation costs outweigh the expected reduction in Annualized Loss Expectancy (ALE). Every accepted risk must have a defined owner, compensating controls and review triggers to ensure the decision remains appropriate over time.
