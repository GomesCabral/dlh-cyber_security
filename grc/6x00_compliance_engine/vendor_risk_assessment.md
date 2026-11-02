# CloudVault Medical Vendor Risk Assessment

**Assessment date:** 2026-11-02  
**Vendor:** CloudVault Medical  
**Assessment owner:** IT Security and Procurement  
**Security approval:** Not granted  
**CISO sign-off:** Pending; no approval evidenced  
**Policy applied:** `vendor_management_policy.md` (proposed; CISO approval pending)  
**Classification:** Confidential

## 1. Vendor Overview

CloudVault Medical proposes clinical backup archive and disaster recovery storage services for MedDefense Health Systems. Its planned archives include Epic EHR exports, Laboratory Information System backups, PACS/RIS metadata, pharmacy backups, and recovery logs that may contain patient identifiers. CloudVault may store or process electronic protected health information (ePHI), even where archives are encrypted. Under Section 3 of `vendor_management_policy.md`, the proposed classification is **Tier A — Critical**. The proposed contract term is three years. The business owner is the Infrastructure Manager; the data owner is the Clinical Applications Manager.

**Decision at assessment:** **Do Not Approve.** Contract signature, onboarding, account provisioning, and MedDefense data transfers must remain blocked until all mandatory Tier A gates are satisfied and written approvals are recorded. Whether any data transfer has already occurred is not established by the supplied artifacts and must be verified.

**Source artifacts:** `cloudvault_security_questionnaire.md`, `cloudvault_contract_summary.md`, `cloudvault_subprocessor_list.md`, `baa_status_note.md`, `vendor_management_policy.md`.

## 2. Findings Table

Ratings mean: **Pass** = requirement evidenced; **Acceptable** = no identified mandatory-policy failure but verification or monitoring is appropriate; **Concern** = documented gap requiring remediation or validation; **Critical Concern** = mandatory Tier A gate or critical contractual condition preventing approval. Questionnaire answers are vendor-reported; an answer alone does not prove independent validation.

| Item | Finding (abbreviated response) | Risk Rating | Gap Description | Required Action |
| --- | --- | --- | --- | --- |
| 1 | SOC 2 Type II report dated 11 months ago | Acceptable | Report date meets 12-month threshold, but full report, scope, and exceptions have not been evidenced as reviewed. | Obtain the report; IT Security must validate date, scope, relevant controls, and exceptions before approval. |
| 2 | No HITRUST CSF certification | Pass | None: policy permits a current SOC 2 Type II report **or** HITRUST certification. | No HITRUST certificate required if the SOC 2 Type II report passes review under item 1. |
| 3 | AES-256 encryption at rest | Acceptable | Vendor-reported control; archive coverage and key ownership have not been independently verified. | Verify encryption coverage and MedDefense key custody in architecture and contractual evidence. |
| 4 | TLS 1.2 encryption in transit | Acceptable | Vendor-reported encryption; transfer configuration and supported protocol settings not evidenced. | Verify encrypted transfer configuration and approved data flows before activation. |
| 5 | Penetration test 22 months old; no findings summary | Critical Concern | Mandatory Tier A test must be within 12 months with critical findings and remediation status; both are missing. | Provide test results dated within 12 months, critical-finding summary, and verified remediation of all critical findings before onboarding. |
| 6 | Two subprocessors disclosed: US CDN and EU analytics | Concern | Data exposure, jurisdictions beyond broad location, contractual flow-down, privileged access, and incident obligations remain unverified. | Complete named subprocessor register with jurisdictions, data flows, safeguards, access rights, and breach-notification flow-down; obtain IT Security and Legal approval. |
| 7 | US primary site; DR location undisclosed | Critical Concern | Mandatory Tier A data-center and DR locations and data-flow jurisdiction cannot be validated. | Disclose DR country, region, operator, data types, and transfers; obtain documented Security/Legal review before any data transfer. |
| 8 | Breach notification 72 hours after internal confirmation | Critical Concern | Conflicts with 24 hours from discovery of a confirmed or suspected incident affecting MedDefense data; confirmation-only trigger delays notice. | Amend BAA and contract to require notification within 24 hours of discovery of a confirmed or suspected incident, including subprocessors. |
| 9 | Deletion within 90 days of written request | Concern | Conflicts with policy requiring return or certified destruction within 30 days of termination. | Amend agreement to 30 days from termination; require destruction certificate and subprocessor coverage, with documented legally required retention exceptions. |
| 10 | Background checks at hire only | Acceptable | No recurring-check requirement is explicitly mandated by current policy; personnel-risk controls remain unverified. | Document screening coverage and access authorization controls; evaluate any residual risk in annual review. |
| 11 | TOTP MFA for privileged accounts | Acceptable | Control is reported but deployment coverage has not been independently validated. | Obtain privileged-access and MFA configuration assurance before approval. |
| 12 | Monthly scans; quarterly critical-remediation target | Concern | Quarterly target could leave critical exposures unresolved; no scan reports, risk exceptions, or remediation proof supplied. | Obtain vulnerability reports, critical-finding aging and closure evidence; require prompt remediation and escalation of open critical issues before approval. |
| 13 | Audit permitted on 60 days' notice | Concern | Notice period may obstruct timely incident evidence requests and MedDefense's independent investigation rights. | Amend contract/BAA to permit prompt incident-related evidence access and independent investigation without a 60-day delay. |
| 14 | Willing to execute BAA; none signed | Critical Concern | An intention to sign does not satisfy the unconditional executed-BAA Tier A gate. | Legal must obtain and retain a fully executed BAA before contract approval, onboarding, or any ePHI access; no exceptions. |
| 15 | Annual PHI-handling training module | Acceptable | Training is reported, but completion and role coverage are not evidenced. | Obtain current role-based training completion evidence for relevant personnel and review annually. |

## 3. Critical Findings

### Item 5 — Outdated Penetration Test

`cloudvault_security_questionnaire.md` reports a penetration test from 22 months ago and no findings summary. Section 4.1 of `vendor_management_policy.md` requires results within 12 months and evidence of remediation status for critical findings. Without this, MedDefense cannot substantiate the current security of the backup service or determine whether exploitable weaknesses could expose ePHI. **Before approval:** CloudVault must deliver a test report dated within 12 months, a critical-findings summary, and verified closure of every critical finding; IT Security must review and accept the evidence.

### Item 7 — Undisclosed Disaster Recovery Location

`cloudvault_contract_summary.md` and `cloudvault_security_questionnaire.md` identify a US primary data center but do not disclose the disaster recovery location. Section 4.1 of `vendor_management_policy.md` requires written confirmation of data-center and DR locations and data flows. MedDefense therefore cannot complete its assessment of storage jurisdictions, data access, and subprocessor exposure; this creates material regulatory and contractual uncertainty for patient information. **Before approval:** CloudVault must disclose the DR location and operator, relevant data flows, and processing jurisdictions, and receive documented IT Security and Legal clearance.

### Item 8 — Incident Notification Deadline

`cloudvault_security_questionnaire.md` states 72 hours **after internal confirmation**, whereas Sections 5 and 7 of `vendor_management_policy.md` require notification within **24 hours of discovery of a confirmed or suspected security incident affecting MedDefense data**. The proposed term could delay MedDefense's investigation and ability to assess HIPAA breach-notification obligations. **Before approval:** Legal must obtain binding 24-hour discovery-based language in the BAA and contract, including incidents involving subprocessors, and preserve MedDefense's independent investigation rights.

### Item 14 — Missing Executed BAA

`baa_status_note.md` confirms that no Business Associate Agreement is signed; willingness to sign is not execution. Because CloudVault is a Tier A provider handling backup archives containing ePHI, Section 5 of `vendor_management_policy.md` makes the executed BAA an unconditional gate. Allowing ePHI access without the required agreement would create direct HIPAA business-associate compliance exposure. **Before approval:** Legal must secure and retain a fully executed BAA covering permitted uses, safeguards, 24-hour incident notice, subprocessors, evidence cooperation, and return or certified destruction. **No exception or provisional access is allowed.**

## 4. Recommendation

**Selected decision: DO NOT APPROVE.**

CloudVault has potentially useful controls (recently dated SOC 2 Type II assurance, AES-256, TLS 1.2, MFA), but the available evidence does not satisfy the mandatory Tier A requirements of `vendor_management_policy.md`. In particular, the BAA is unsigned, penetration testing is outdated, the DR location is unknown, and the proposed incident-notification terms conflict with MedDefense policy. The subprocessor and deletion issues also require correction. **Do not sign the contract, issue access, or transfer ePHI on the basis of this assessment.** This is a recommendation to withhold security approval, not a claim of completed CISO sign-off. The policy itself remains proposed pending CISO approval; the decision is assessed against its intended gates.

## 5. Mandatory Remediation Before Reassessment

| Condition | Acceptance Evidence | Responsible Party |
| --- | --- | --- |
| Execute BAA with required terms and no waiver | Signed BAA retained by Legal; 24-hour incident notification and subprocessor flow-down included | CloudVault / Legal |
| Refresh penetration test | Report dated within 12 months, critical findings listed, verified remediation for all critical findings | CloudVault / IT Security |
| Disclose hosting and DR locations | Written locations, operators, jurisdictions, and approved data-flow map | CloudVault / IT Security / Legal |
| Resolve subprocessors | Complete subprocessor inventory, jurisdiction and exposure analysis, contractual safeguards, and written approval | CloudVault / Legal / IT Security |
| Correct termination and incident clauses | Contract requires 30-day return or certified destruction and prompt incident evidence access | CloudVault / Legal |
| Validate remaining assurance | Reviewed SOC 2 report, questionnaire, encryption/MFA evidence, vulnerability reports, and training evidence | IT Security |
| Record formal approvals | Procurement inventory record, IT Security acceptance, Legal BAA confirmation, and CISO sign-off | Procurement / IT Security / Legal / CISO |

**Reassessment rule:** Every mandatory Tier A condition must be evidenced and accepted before the decision can change. A remediation promise, conditional contract clause, or risk acceptance cannot waive the executed-BAA requirement. Any newly discovered ePHI access must be escalated immediately for Legal and incident/privacy review.

## 6. Evidence and Limitations

- `cloudvault_security_questionnaire.md`: 15 vendor-reported responses; no independent verification package attached.
- `cloudvault_contract_summary.md`: service, ePHI exposure, proposed contract terms, and documented issues.
- `cloudvault_subprocessor_list.md`: named subprocessors and unresolved data-flow and safeguard questions.
- `baa_status_note.md`: explicitly states the BAA is not executed.
- `vendor_management_policy.md`: Tier A classification, mandatory pre-access gates, notification, monitoring, and offboarding requirements; approval remains pending.
- **Not evidenced:** signed BAA, full SOC 2 report, current penetration test, DR location, complete subprocessor contracts, final CISO approval, and whether production ePHI transfer has begun. These must not be represented as completed.
