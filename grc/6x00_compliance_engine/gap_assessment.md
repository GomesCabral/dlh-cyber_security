# NIST CSF 2.0 Gap Assessment: MedDefense Health Systems

**Assessment date:** 2026-11-02  
**Assessor:** Pedro Cabral  
**Framework version:** NIST CSF 2.0  
**Regulatory context:** HIPAA Security Rule, 45 CFR Part 164  
**Assessment basis:** Supplied MedDefense evidence dated primarily April 2026; current remediation closure has not been verified.  
**Scope note:** The assignment describes 22 subcategories, but its explicit assessment list contains 21. This matrix covers all 21 listed subcategories.  
**Rating method:** `Implemented` requires sufficient supplied evidence for the assessed scope; `Partial` means documented activity with material coverage or assurance gaps; `Not Implemented` means the required program/control is absent or cannot be substantiated. Severity rates the remaining gap, not the inherent risk of the activity.

## Gap Assessment Matrix

| CSF Function | Subcategory ID | Subcategory Title | Implementation Status | Evidence Reference | Gap Severity | Gap Description |
|---|---|---|---|---|---|---|
| GOVERN | GV.OC-01 | Organizational mission and risk context understood | Partial | `risk_register_updates.yaml`; `risk_treatment_plan.md` | High | Post-incident risks are recorded, but no approved organization-wide risk context, appetite or governance endorsement is evidenced. |
| GOVERN | GV.PO-01 | Cybersecurity policies established and communicated organization-wide | Not Implemented | `risk_register_updates.yaml`; `risk_treatment_plan.md` | Critical | R-004 confirms three enforceable policies are missing; approval and workforce distribution are not evidenced. |
| GOVERN | GV.SC-04 | Suppliers identified and prioritized by criticality | Not Implemented | `risk_register_updates.yaml`; `forensic_findings_summary.md` | High | R-001 documents no formal vendor tiering or supplier inventory for parties with clinical or ePHI access. |
| GOVERN | GV.SC-07 | Supplier cybersecurity risks assessed and managed | Partial | `risk_register_updates.yaml`; `risk_treatment_plan.md`; `forensic_findings_summary.md` | High | Supplier risk R-001 is tracked, but security reviews, BAA gating and subprocessor oversight are not operationally evidenced. |
| IDENTIFY | ID.AM-01 | Hardware software services and data inventoried | Partial | `endpoint_hardening_baseline.md`; `risk_register_updates.yaml` | Medium | Managed endpoint counts exist, but biomedical devices are excluded and the wider asset inventory is unproven. |
| IDENTIFY | ID.RA-01 | Vulnerabilities and threats identified and recorded | Implemented | `forensic_findings_summary.md`; `risk_register_updates.yaml` | Low | Incident-derived threats and weaknesses are recorded; evidence of routine proactive assessment remains limited. |
| IDENTIFY | ID.RA-06 | Risk responses prioritized assigned and tracked | Partial | `risk_register_updates.yaml`; `risk_treatment_plan.md` | High | Five risks have owners and target dates, but the treatment plan lacks CISO sign-off and verified closure. |
| PROTECT | PR.AA-01 | Identities and credentials managed across systems | Partial | `endpoint_hardening_baseline.md`; `forensic_findings_summary.md`; `ir_playbook_index.md` | High | Password GPO and credential-response playbooks exist, but privileged service-account misuse and proactive IAM gaps remain. |
| PROTECT | PR.AA-05 | Access permissions reviewed for least privilege | Partial | `forensic_findings_summary.md`; `endpoint_hardening_baseline.md` | Critical | `svc_epic_int` held Domain Admin privilege; no periodic access review or least-privilege attestation is supplied. |
| PROTECT | PR.AT-01 | Workforce receives security awareness and training | Partial | `security_awareness_training_status.md`; `risk_register_updates.yaml` | Critical | Only 1,460 of 2,000 workers (73%) completed training versus the 95% target; role mapping is missing. |
| PROTECT | PR.DS-01 | Data at rest appropriately protected | Partial | `endpoint_hardening_baseline.md` | High | BitLocker is confirmed on only 173 Windows endpoints; full ePHI storage encryption coverage is not evidenced. |
| PROTECT | PR.PS-01 | Secure configuration baselines established and applied | Partial | `endpoint_hardening_baseline.md` | High | Hardening covers 231/280 clinical workstations, 18/26 laptops and 3/3 Linux servers; GPO conflicts and review sign-offs remain. |
| PROTECT | PR.PS-04 | System logs generated and routinely reviewed | Partial | `sigma_detection_catalog.md`; `endpoint_hardening_baseline.md` | High | Sysmon covers 198/280 clinical endpoints; forwarding and formal weekly review evidence are incomplete. |
| DETECT | DE.CM-01 | Networks and endpoints monitored for threats | Partial | `sigma_detection_catalog.md`; `endpoint_hardening_baseline.md` | High | Active detections exist, but biomedical devices, some endpoints and required log sources are not monitored. |
| DETECT | DE.CM-06 | External service provider activity monitored continuously | Partial | `sigma_detection_catalog.md`; `forensic_findings_summary.md`; `risk_register_updates.yaml` | High | CloudTrail is absent in the disaster-recovery region, leaving external/cloud activity visibility incomplete. |
| DETECT | DE.AE-02 | Potentially adverse events analyzed and correlated | Partial | `sigma_detection_catalog.md`; `forensic_findings_summary.md` | Medium | Incident analysis and active Sigma rules exist, but draft rules and missing telemetry limit consistent analysis. |
| RESPOND | RS.MA-01 | Incident response plan activated and executed | Partial | `ir_playbook_index.md`; `forensic_findings_summary.md` | Medium | Live phishing response and tabletop exercises are documented, but vendor/cloud playbooks remain drafts and CISO approval is absent. |
| RESPOND | RS.AN-03 | Incident analysis supports response decisions | Implemented | `forensic_findings_summary.md`; `ir_playbook_index.md` | None | The Nexus/Cobalt Strike chain was analyzed with concrete forensic findings; no material gap in this incident-specific evidence is identified. |
| RESPOND | RS.CO-02 | Incident communications coordinated with stakeholders | Partial | `ir_playbook_index.md` | High | Communication testing is incomplete and no approved organization-wide escalation/notification evidence is supplied. |
| RECOVER | RC.RP-01 | Recovery plans tested and executed successfully | Partial | `recovery_validation_summary.md` | High | LIS partial restore took 41 minutes against a 30-minute RTO; AD and Epic recovery were not fully tested. |
| RECOVER | RC.CO-01 | Recovery status communicated to relevant stakeholders | Partial | `recovery_validation_summary.md`; `ir_playbook_index.md` | Medium | Clinical notification language was missing from the LIS runbook and recovery communication testing is unproven. |

## Summary

**Implementation counts:**

- Implemented: **2**
- Partial: **17**
- Not Implemented: **2**
- **Total: 21** explicitly listed subcategories

**Top 3 pre-audit priorities:**

1. **GV.PO-01 (Critical):** Draft, obtain CISO approval for and distribute enforceable Acceptable Use, Data Classification and Vendor Management policies; retain approval and acknowledgment evidence.
2. **PR.AT-01 (Critical):** Close the 540-person training shortfall, document role-based assignments and reach the 95% internal completion target with verifiable records.
3. **PR.AA-05 (Critical):** Remove or formally justify excessive service-account privilege and produce periodic access-review evidence, including approval and remediation tracking.

**Connection to upcoming governance and resilience work:**

The largest gaps concern auditable governance, workforce assurance, identity oversight, supplier risk and incomplete recovery validation. The next project deliverables should formalize and seek approval of the three missing policies, evaluate CloudVault against the new Vendor Management Policy, and assemble an OCR evidence package that distinguishes full, partial and missing proof. Resilience work must also close the LIS RTO miss, test other critical recoveries and document clinical communications. Drafting a policy or assigning a remediation owner is not evidence of approval or closure; the audit package must preserve those distinctions and request dated sign-offs, test records and other missing artifacts.

## Evidence and Assessment Limitations

- The assessment uses only the supplied local MedDefense materials. An artifact named inside a supplied document is **not** treated as separately reviewed evidence unless that file itself was provided.
- `risk_register_updates.yaml` contains R-001 through R-005. Its entries substantiate identified risks, **not** completed remediation.
- `risk_treatment_plan.md` explicitly states that CISO and Board Risk Committee approval is outstanding.
- `forensic_findings_summary.md` and `ir_playbook_index.md` substantiate incident activity but not a fully approved organization-wide response program.
- `recovery_validation_summary.md` documents a partial LIS test and references `recovery_test_record.md`; that underlying record was not supplied for independent review.
- No separate IAM access-review logs, signed policies, approved vendor inventory or training completion attestations were supplied. These omissions are reported as gaps rather than assumed controls.
- Source records are primarily from April 2026, and some treatment target dates have passed as of the assessment date. **No current closure evidence was provided**, so past-due items must be revalidated rather than marked complete.
- This is an evidence-based project gap assessment, **not** a legal determination of overall HIPAA compliance or a certification of NIST CSF conformance.
