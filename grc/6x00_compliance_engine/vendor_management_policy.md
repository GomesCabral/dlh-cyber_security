# MedDefense Health Systems Vendor Management Policy

**Policy number:** MD-SEC-VMP-001  
**Policy title:** Vendor Management Policy  
**Effective date:** Upon written CISO approval and publication  
**Review date:** Annually, within 12 months of the effective date  
**Owner:** IT Security and Procurement (joint owners)  
**Approved by:** CISO — approval pending  
**Classification:** Internal  
**Applies to:** Procurement, IT Security, Legal, business and data owners, and all third parties seeking access to MedDefense systems, networks, or data  
**Document status:** Proposed policy; not yet approved or effective

## 1. Purpose

This policy establishes mandatory security checks before MedDefense engages a third party that may access its systems, networks, or data. It also requires documented oversight throughout the relationship so that vendor access, patient information, and clinical services remain protected.

## 2. Scope and Accountability

This policy applies to all third parties, including software-as-a-service (SaaS) providers, managed service providers, cloud infrastructure and backup providers, medical device vendors with network-connected products, staffing agencies whose personnel use MedDefense IT systems, and their relevant subcontractors.

- **Procurement** must register and classify each vendor, collect required evidence, and block onboarding until the required approvals are recorded.
- **IT Security** must review technical evidence, assess security risks, validate remediation, and monitor material changes.
- **Legal** must review contracts and execute Business Associate Agreements (BAAs) where required.
- **Business and data owners** must confirm intended services, systems, data flows, and whether electronic protected health information (ePHI) may be accessed.
- **CISO** must approve Tier A security assessments and any permitted non-BAA exceptions under this policy. **No exception is permitted to the executed-BAA requirement for Tier A vendors.**

No purchase order, contract signature, or technical connection overrides the security onboarding gates in this policy.

## 3. Vendor Risk Classification

Procurement and IT Security must classify each vendor **before** granting access and record the tier, access scope, data types, business owner, reviewer, and approval decision in the vendor inventory. When criteria overlap, the highest applicable tier applies.

| Tier | Classification rule | Examples |
| --- | --- | --- |
| **Tier A — Critical** | Access to, storage or processing of ePHI, or access to clinical systems, including possible incidental ePHI exposure. | Scheduling platforms, imaging vendors, backup providers with PHI, Epic integration partners. |
| **Tier B — Standard** | Access to MedDefense internal systems or networks, with no ePHI or clinical-system exposure. | Internal IT support provider restricted to non-clinical systems. |
| **Tier C — Low** | No access to MedDefense systems, networks, or data. | Physical vendors, office suppliers, facilities contractors without IT access. |

A vendor must be reclassified immediately if its access or data exposure changes. A vendor initially described as Tier B must be treated as Tier A if ePHI exposure becomes possible.

## 4. Pre-Engagement Security Requirements

### 4.1 Tier A — Mandatory Gate Before Access

**All** items below must be collected, reviewed, and accepted **before any vendor system access or MedDefense data transfer begins**:

1. A **SOC 2 Type II report or HITRUST CSF certification** dated within the preceding **12 months**; IT Security must review scope and material exceptions.
2. A completed **MedDefense vendor security questionnaire**, reviewed by IT Security.
3. **Penetration test results dated within 12 months**, including a summary of critical findings and documented remediation status. Open critical findings require verified remediation before onboarding.
4. A complete list of **all subprocessors handling MedDefense data**, including each entity's function, data exposure, hosting or processing jurisdiction, and applicable contractual safeguards.
5. A **fully executed BAA before any ePHI access begins, without exceptions**. For Tier A vendors, the executed BAA is an unconditional onboarding requirement even if the vendor believes it will receive only encrypted information.
6. Written confirmation of intended data flows, clinical-system access, remote-support permissions, data center and disaster recovery locations, and controls for encryption and privileged access.
7. Written IT Security and Procurement assessment approval, Legal confirmation of the executed BAA, and CISO approval recorded in the vendor inventory.

**If any mandatory item is missing, expired, inadequate, or unapproved, the decision is `Onboarding blocked`.** A remediation plan does not grant provisional access. Procurement must not activate the service, and IT must not issue credentials or enable data transfers.

### 4.2 Tier B — Mandatory Gate Before Access

Procurement must record the vendor in the inventory; IT Security must review a completed security questionnaire, confirm restricted access and absence of ePHI exposure, and document a security approval. A written agreement must require confidentiality, least-privilege access, prompt incident reporting, and secure termination. If ePHI exposure is discovered or anticipated, reclassify the vendor to Tier A **before** access continues or expands.

### 4.3 Tier C — Mandatory Gate Before Engagement

Procurement must register the vendor, document that it has no MedDefense system, network, or data access, and obtain business-owner approval. No IT account or network connection may be issued under Tier C. Any new IT access requires reassessment and reclassification before it is enabled.

## 5. Business Associate Agreement Requirements

A BAA is mandatory for **every Tier A vendor** and for any other vendor whose service may incidentally expose ePHI; such a vendor must be classified Tier A before access. **No Tier A vendor may onboard or access ePHI without an executed BAA. There are no exceptions, temporary waivers, or retroactive approvals.**

Legal must ensure the BAA specifies, at minimum:

- Permitted uses and disclosures of ePHI and a prohibition on unauthorized secondary use.
- Administrative, physical, and technical safeguard obligations appropriate to the service.
- Notification to MedDefense **within 24 hours of discovery of a confirmed or suspected security incident affecting MedDefense data**, including incidents involving subprocessors; notification must not wait for the vendor to complete its investigation.
- Identification of subprocessors, advance notice and review of changes, and contractual flow-down of equivalent security and privacy obligations.
- Cooperation with MedDefense investigations, preservation of relevant evidence, and the right to request supporting records and conduct an independent investigation.
- Data return or certified destruction within **30 days** of termination, including applicable subprocessor copies, with documented exceptions only where legally required retention prevents destruction.
- Termination assistance and access revocation requirements.

A commercial agreement or a vendor's willingness to sign a BAA is **not** an executed BAA. Legal must retain the signed agreement as audit evidence.

## 6. Ongoing Monitoring and Material Changes

- **Tier A:** IT Security and Procurement must conduct and document a security review **at least annually**, including refreshed certification or assurance evidence, a current penetration test, subprocessor inventory, incident history, and outstanding remediation.
- **Tier B:** Review at least every two years and whenever access scope changes.
- **Tier C:** Reconfirm the no-access classification at contract renewal.
- **Immediate out-of-cycle review:** Ownership transfer, addition or replacement of subprocessors, data center or disaster recovery relocation, material change in data flows or access, or a significant security incident must be reported to MedDefense and assessed immediately, before any affected new access or processing begins.

IT Security must record findings, severity, accountable owner, corrective actions, due dates, and approval or suspension decisions. An unresolved Tier A mandatory requirement requires suspension or continued blocking of affected access.

## 7. Incident Notification and Investigation

Vendors must notify MedDefense IT Security **within 24 hours of discovering any confirmed or suspected security incident affecting MedDefense data**. Notification must use the contractual security incident contact and include the incident time (if known), affected systems or data, containment actions, and a contact for updates; incomplete initial facts are not grounds for delay.

The vendor must preserve logs and other relevant evidence, cooperate with MedDefense, and provide updates as new facts emerge. **MedDefense retains the right to conduct its own investigation independently of the vendor**, including requesting evidence and assessing affected patient information. The vendor must not delay or obstruct that investigation.

## 8. Vendor Offboarding and Record Retention

At contract termination or earlier access withdrawal:

1. The business owner must notify Procurement and IT Security immediately.
2. IT Security must revoke vendor accounts, remote access, API keys, tokens, and other access **within 24 hours of contract termination**, and document completion.
3. The vendor must return MedDefense data or provide **certified destruction within 30 days** of termination; Legal must document any legally required retention and the continuing safeguards for retained copies.
4. Procurement and Legal must obtain evidence of access revocation, data return or destruction, and subprocessor completion.
5. MedDefense must retain relevant policy, BAA, vendor assessment, approval, monitoring, incident, and offboarding documentation for **six years** in accordance with its HIPAA documentation retention requirements.

## 9. Enforcement and Exceptions

Procurement and IT Security must deny onboarding when required evidence or approvals are missing. Violations must be escalated to the CISO and Legal and may result in suspension of vendor access, contract remedies, or termination. Any permitted exception to a non-BAA requirement must be documented with rationale, compensating controls, an expiry date, and written CISO approval **before** access; no exception may waive the Tier A executed-BAA gate.

## 10. Review, Publication, and Acknowledgment

IT Security and Procurement must review this policy annually and after material regulatory or operational changes. The policy becomes enforceable only after documented CISO approval and publication to Procurement, IT Security, Legal, and relevant business owners; all responsible staff must acknowledge it before performing vendor onboarding activities and at least annually thereafter.

**Acknowledgment:**  
I acknowledge that I have read, understood and agree to comply with this policy.

**Employee name:** __________________________  
**Signature:** ______________________________  
**Date:** ___________________________________

## 11. Evidence Basis and Current Approval Gap

This proposed policy addresses gaps documented in the provided MedDefense materials:

- `prior_policy_inventory.md` — no current enforceable Vendor Management Policy; approval and distribution required.
- `cloudvault_contract_summary.md` — CloudVault is a prospective Tier A backup provider; its proposed terms do not satisfy multiple gates.
- `baa_status_note.md` — no executed CloudVault BAA is on file.
- `cloudvault_subprocessor_list.md` — subprocessor exposure and jurisdiction questions remain open.
- `hipaa_security_rule_crosswalk.md` — maps business associate contracts to HIPAA 164.308(b).

**Audit status:** This document is a drafted control, **not evidence of an already approved, distributed, or operational policy**. Those approvals and records must be obtained separately.
