# MedDefense Business Impact Analysis

**Version:** 1.0  
**Classification:** Confidential  
**Prepared by:** Pedro Cabral  
**Date:** 2026-11-03  
**CISO approval:** _________________________ Date: _________  
**Status:** Draft for clinical, technical and CISO validation; not yet signed

## Executive Summary

MedDefense is a 230-bed acute-care hospital operating an emergency department (ED), intensive care unit (ICU), surgery, radiology, laboratory and pharmacy around the clock. A prolonged interruption can compromise medication safety, critical laboratory notification, diagnostic imaging, vital-sign documentation and clinical decision-making. This assessment covers ten systems and sets **proposed**, not previously approved, maximum tolerable downtime (MTD), recovery time objective (RTO) and recovery point objective (RPO) targets.

The **Network Core** and **Active Directory** are foundational dependencies: their failure can prevent recovery or use of otherwise healthy clinical applications. Epic EHR, the Laboratory Information System (LIS), Pharmacy Dispensing System and Medical Device Integration Gateway present especially acute patient-safety exposure. The LIS is **Tier 1** because STAT specimen tracking and critical-value communication can degrade quickly. Manual clinical downtime procedures reduce but do not eliminate risk.

The proposed recovery targets require validation against actual backup frequency, vendor capabilities, staffing and timed restore tests. In particular, the LIS nightly export cannot substantiate the proposed one-hour RPO; this is an **open control gap**, not an achieved objective. The CISO and clinical service owners must approve or revise these targets before they become operational commitments.

## Methodology

### Sources and assessment rules

This assessment uses the following provided lab materials:

- `bia/meddefense_system_inventory.csv`: owners, users, data, operating hours, existing DR status and dependencies.
- `bia/downtime_impact_notes.md`: scenario-based 1-hour, 4-hour and 24-hour clinical consequences.
- `bia/regulatory_reference_map.md`: HIPAA Security Rule and Joint Commission reference framing.
- `backup_architecture/dependency_map_seed.md`: infrastructure dependencies and suggested recovery sequence.

The time horizons are **1 hour**, **4 hours** and **24 hours** after loss of service. Impact levels are **Low**, **Moderate**, **High** and **Critical**, based on the plausible effect on patient care with reduced night-shift staffing. These are qualitative planning assessments, not incident measurements or validated clinical risk scores.

- **MTD** is the maximum interruption before consequences become unacceptable; it is not a recovery target.
- **RTO** is the target elapsed time to restore usable service; it must be strictly less than MTD.
- **RPO** is the maximum acceptable age of recoverable data, expressed in minutes or hours.
- **Tier 1:** immediate or rapidly escalating clinical harm or indispensable recovery prerequisite.
- **Tier 2:** major clinical or operational degradation requiring accelerated restoration.
- **Tier 3:** substantial supporting-service risk with temporary alternatives.
- **Tier 4:** lower immediate patient-safety impact and longer acceptable interruption.

**Financial method:** Hourly revenue exposures below are *illustrative planning estimates in USD/hour*, not figures from the inventory or verified hospital finance data. They estimate gross billing/throughput exposed to delay, not necessarily permanently lost revenue. They must not be added across systems because a single delayed encounter may be counted multiple times. Finance must replace them with validated encounter volumes, reimbursement rates, diversion costs and actual lost-capture assumptions.

### Regulatory interpretation

The supplied regulatory map identifies **45 CFR 164.308(a)(7)(i)** (contingency plan), **164.308(a)(7)(ii)(A)** (data backup), **(B)** (disaster recovery), **(C)** (emergency mode operation), **(D)** (testing and revision), **(E)** (applications and data criticality), **164.312(c)(1)** (integrity) and **164.312(e)(1)** (transmission security). These references inform the enterprise contingency program; they are **not** claims that each system has a separate system-specific legal RTO. Joint Commission emergency management expectations are relevant to continuity of patient care, communication, role clarity and documented emergency procedures. Exact accreditation standard identifiers and incident-specific notification duties require compliance review; the provided map does not identify them.

## System Impact Assessment

### 1. Active Directory

**Owner:** Systems Administrator | **Tier:** 1 | **RTO:** 30 minutes | **RPO:** 1 hour | **MTD:** 2 hours | **Illustrative revenue exposure:** $8,000/hour

- **1 hour — High:** Cached sessions may remain active, but new clinician logins and service-account authentication fail; incoming staff may be unable to open Epic or LIS.
- **4 hours — Critical:** Shift changes and session expiry expand loss of access to Epic, LIS, PACS/RIS, pharmacy and communications, increasing delayed treatment and manual identification risk.
- **24 hours — Critical:** Broad inability to authenticate prevents normal clinical operations and reliable recovery of dependent applications.
- **Regulatory impact:** HIPAA 164.308(a)(7)(i), (ii)(B), (ii)(C), (ii)(E); Joint Commission emergency access/continuity and staff-role expectations (specific standard pending review).
- **Dependencies and cascade:** Network Core -> Active Directory -> Epic/LIS/PACS/pharmacy/email/SOC and backup access control. A secondary domain controller exists, but recovery of DC01 has not been recently tested.
- **Rationale:** Recover identity before dependent applications; verify DNS, authentication, service accounts and application login, not merely domain-controller power state.

### 2. Epic EHR

**Owner:** Clinical Applications Manager | **Tier:** 1 | **RTO:** 1 hour | **RPO:** 15 minutes | **MTD:** 3 hours | **Illustrative revenue exposure:** $20,000/hour

- **1 hour — High:** Clinicians lose order entry, allergy/medication history and recent notes; paper workflows increase verification burden.
- **4 hours — Critical:** Medication documentation, order reconciliation and care coordination become unreliable; treatment and discharge decisions are delayed.
- **24 hours — Critical:** Extensive paper backlog and delayed clinical decisions create unacceptable patient-safety and integrity risks.
- **Regulatory impact:** HIPAA 164.308(a)(7)(i), (ii)(A)-(E), 164.312(c)(1); Joint Commission patient-care continuity and emergency documentation expectations.
- **Dependencies and cascade:** Network Core + Active Directory -> Epic -> LIS result interface, pharmacy workflows and PACS/RIS orders/results; secure messaging supports clinical coordination. Vendor-hosted replication is documented, but local downtime procedures are outdated.
- **Rationale:** Prioritize safe clinical access and verified allergy, order and medication information. Proposed targets require vendor proof and tested restoration.

### 3. Laboratory Information System

**Owner:** Laboratory Systems Lead | **Tier:** 1 | **RTO:** 30 minutes | **RPO:** 1 hour | **MTD:** 2 hours | **Illustrative revenue exposure:** $6,000/hour

- **1 hour — High:** STAT requests and specimens move to phone/paper; specimen identification, analyzer association and critical-value callbacks become more error-prone.
- **4 hours — Critical:** Critical potassium/troponin results may be delayed or misrouted; ED/ICU treatment decisions face serious risk.
- **24 hours — Critical:** Unreconciled specimens and delayed results threaten patient care and traceability across shifts.
- **Regulatory impact:** HIPAA 164.308(a)(7)(i), (ii)(A)-(E), 164.312(c)(1); Joint Commission emergency continuity and critical-result communication expectations (specific standard pending review).
- **Dependencies and cascade:** Network Core + Active Directory + lab instrument feeds + Epic interface -> order intake -> specimen tracking -> result matching -> critical notification -> Epic posting. Nightly SQL export exists; no prior recovery test was documented in the inventory.
- **Rationale and gap:** A 1-hour RPO is proposed for STAT/critical results, **but nightly backup alone cannot meet it**. Implement and validate more frequent protection or formally revise the target. Recovery must verify records and critical flags, not just database creation.

### 4. PACS/RIS

**Owner:** Radiology Systems Lead | **Tier:** 2 | **RTO:** 1 hour | **RPO:** 1 hour | **MTD:** 4 hours | **Illustrative revenue exposure:** $7,000/hour

- **1 hour — High:** Imaging acquisition may continue, but prior studies, reporting and distribution slow, affecting ED, stroke, trauma and surgery.
- **4 hours — Critical:** Diagnostic comparison and urgent interpretation delays increase risk of missed treatment windows.
- **24 hours — Critical:** Imaging backlogs and unavailable history compromise acute care and clinical documentation.
- **Regulatory impact:** HIPAA 164.308(a)(7)(i), (ii)(A)-(E), 164.312(c)(1), 164.312(e)(1); Joint Commission continuity and emergency communication expectations.
- **Dependencies and cascade:** Network Core + Active Directory + modality devices + Epic order interface -> image transport/storage -> interpretation -> report delivery. Storage snapshots exist, but restore sequence is undocumented.
- **Rationale:** Validate image integrity, study availability, report delivery and GPU/rendering requirements during recovery.

### 5. Pharmacy Dispensing System

**Owner:** Pharmacy IT Lead | **Tier:** 1 | **RTO:** 30 minutes | **RPO:** 15 minutes | **MTD:** 2 hours | **Illustrative revenue exposure:** $5,000/hour

- **1 hour — High:** Manual verification slows dispensing and makes allergy, interaction and barcode checks harder.
- **4 hours — Critical:** Medication administration delays, transcription errors and controlled-substance tracking gaps threaten patients.
- **24 hours — Critical:** Sustained manual dispensing and reconciliation create unacceptable medication-safety and audit-trail exposure.
- **Regulatory impact:** HIPAA 164.308(a)(7)(i), (ii)(A)-(E), 164.312(c)(1); Joint Commission medication safety and emergency operations expectations.
- **Dependencies and cascade:** Network Core + Active Directory + Epic medication/orders data + dispensing cabinets -> pharmacist verification -> dispensing -> barcode administration -> documentation. Existing backup schedule and manual verification are inconsistently documented.
- **Rationale:** Restoration is not complete until pharmacists can validate current orders, allergy context, dispensing and controlled-substance records.

### 6. Medical Device Integration Gateway

**Owner:** Biomedical IT Lead | **Tier:** 1 | **RTO:** 30 minutes | **RPO:** 15 minutes | **MTD:** 1 hour | **Illustrative revenue exposure:** $3,000/hour

- **1 hour — Critical:** Bedside monitors continue locally, but central data feeds, automated charting and alarm routing degrade; ICU/telemetry staff may miss timely context.
- **4 hours — Critical:** Manual observation and alarm escalation strain staffing and increase risk of delayed intervention.
- **24 hours — Critical:** Prolonged loss of integrated monitoring/documentation is incompatible with normal critical-care workflows.
- **Regulatory impact:** HIPAA 164.308(a)(7)(i), (ii)(B)-(E), 164.312(c)(1), 164.312(e)(1); Joint Commission patient monitoring and emergency communication expectations.
- **Dependencies and cascade:** Network Core + segmented VLANs -> device gateway -> Epic telemetry/charting and alarm-routing workflows. Local configuration export exists; vendor backup and off-site copy are unclear.
- **Rationale:** Verify bedside monitoring independence, central alarm routing and documented manual escalation; gateway recovery must not be confused with restoration of bedside devices.

### 7. Network Core

**Owner:** Network Engineering Lead | **Tier:** 1 | **RTO:** 15 minutes | **RPO:** 24 hours (configuration state) | **MTD:** 1 hour | **Illustrative revenue exposure:** $25,000/hour

- **1 hour — Critical:** Routing, switching, WAN and VLAN failures can simultaneously interrupt Epic, LIS, identity, PACS, communications and monitoring.
- **4 hours — Critical:** Widespread clinical downtime overwhelms paper workarounds and blocks recovery traffic.
- **24 hours — Critical:** Extended loss of connectivity threatens emergency care, interdepartmental coordination and safe restoration.
- **Regulatory impact:** HIPAA 164.308(a)(7)(i), (ii)(B)-(E), 164.312(e)(1); Joint Commission emergency communications and care continuity expectations.
- **Dependencies and cascade:** Network Core -> Active Directory, clinical applications, medical-device VLANs, PACS image movement and backup replication. Configuration backups exist, but failover testing is limited.
- **Rationale:** Configuration RPO is measured as maximum age of a recoverable configuration; verify recent changes and failover separately. Recovery starts with network reachability and segmentation integrity.

### 8. Email and Secure Messaging

**Owner:** Collaboration Services Lead | **Tier:** 3 | **RTO:** 4 hours | **RPO:** 1 hour | **MTD:** 12 hours | **Illustrative revenue exposure:** $1,500/hour

- **1 hour — Moderate:** Routine coordination and alert notifications are delayed; approved phone/pager escalation can compensate.
- **4 hours — High:** Cross-team coordination and some clinical notifications slow, especially during staffing handoffs.
- **24 hours — Critical:** Sustained inability to communicate reliably affects patient transfers, leadership coordination and regulatory correspondence.
- **Regulatory impact:** HIPAA 164.308(a)(7)(i), (ii)(C)-(E), 164.312(e)(1) when ePHI is transmitted; Joint Commission emergency communication expectations.
- **Dependencies and cascade:** Network egress + identity provider + mobile access -> secure clinical messaging and escalation. Cloud service exists, but local continuity procedure is incomplete.
- **Rationale:** Test an independent emergency communication path and secure handling of any ePHI.

### 9. Backup and DR Infrastructure

**Owner:** Infrastructure Manager | **Tier:** 2 | **RTO:** 2 hours | **RPO:** 1 hour (backup catalog/metadata) | **MTD:** 8 hours | **Illustrative revenue exposure:** $2,000/hour

- **1 hour — Low:** Clinical production may remain available; however, new backup jobs and restore readiness are at risk.
- **4 hours — High:** An unrelated application outage may become unrecoverable on time because catalog, storage access or restore tools are unavailable.
- **24 hours — Critical:** Extended loss of backup capability raises the probability of unrecoverable ePHI loss following a second failure.
- **Regulatory impact:** HIPAA 164.308(a)(7)(ii)(A), (B), (D), (E), 164.312(c)(1); Joint Commission continuity evidence where relevant.
- **Dependencies and cascade:** Network Core + Active Directory/access control + backup catalog + storage + off-site replication -> ability to recover all backed-up systems. Monitoring gaps exist.
- **Rationale:** Catalog RPO is distinct from the RPO of protected clinical datasets. Validate restore access, immutable/off-site copies where available, and a recovery route when the catalog is down.

### 10. Security Operations Platform

**Owner:** SOC Manager | **Tier:** 3 | **RTO:** 4 hours | **RPO:** 1 hour (security events) | **MTD:** 12 hours | **Illustrative revenue exposure:** $1,000/hour

- **1 hour — Moderate:** SIEM visibility and centralized EDR management degrade, but endpoint controls may continue locally.
- **4 hours — High:** Analysts lose correlation and alert triage during an outage when attacker activity may be concealed.
- **24 hours — Critical:** Missing security telemetry undermines incident detection, forensic reconstruction and confidence in restored systems.
- **Regulatory impact:** HIPAA 164.308(a)(7)(i), (ii)(C)-(E), 164.312(c)(1) for integrity-related monitoring; Joint Commission relevance is indirect through continuity and incident coordination.
- **Dependencies and cascade:** Network Core + Active Directory + log sources + EDR management -> ingestion -> detection -> response. Cold restore is documented; alerting continuity has not been tested.
- **Rationale:** Preserve endpoint protection and local log buffering while central analytics are unavailable; validate event completeness after recovery.

## Dependency Map

The diagram reflects the supplied dependency seed and inventory; arrows show prerequisites or major downstream interfaces, not a fully validated topology.

```text
Network Core (Tier 1) -- recover first
|
+-- Active Directory (Tier 1) -- recover authentication second
|   |
|   +-- Epic EHR (Tier 1)
|   |   +-- LIS result interface (LIS: Tier 1)
|   |   +-- Pharmacy dispensing / medication workflow (Tier 1)
|   |   +-- PACS/RIS ordering and reporting (Tier 2)
|   |
|   +-- Email and Secure Messaging (Tier 3)
|   +-- Security Operations Platform (Tier 3)
|   +-- Backup and DR Infrastructure access (Tier 2)
|
+-- Medical Device Integration Gateway (Tier 1)
|   +-- Epic vital-sign documentation / alarm-routing workflow
|
+-- PACS/RIS image transport
+-- Backup replication and off-site connectivity
```

**Recovery sequencing:** (1) restore core network and segmentation; (2) validate Active Directory/DNS/authentication; (3) ensure backup/DR catalog and storage access; (4) restore clinical services according to immediate safety impact and dependencies, including gateway, pharmacy, Epic, LIS and PACS/RIS; (5) restore communications and security monitoring, maintaining interim alternatives throughout. Some steps may run in parallel if prerequisite services and staffing permit. Clinical incident command must determine whether any patient-safety service needs an exceptional sequence.

**Failure-chain example:** Network outage -> Active Directory unreachable -> fresh clinician login fails -> Epic order entry and LIS result posting are unavailable -> laboratory switches to paper/phone -> delayed or misassociated critical results increase patient risk. A valid LIS backup does not solve missing network, identity or interface dependencies.

## RTO / RPO / MTD Summary Table

All targets below are **proposed** and must be approved and demonstrated by testing. Every RTO is strictly below its MTD.

| System | Tier | RTO | RPO | MTD | Revenue exposure (USD/hour, illustrative) |
| --- | --- | --- | --- | --- | ---: |
| Active Directory | 1 | 30 minutes | 1 hour | 2 hours | $8,000 |
| Epic EHR | 1 | 1 hour | 15 minutes | 3 hours | $20,000 |
| Laboratory Information System | 1 | 30 minutes | 1 hour | 2 hours | $6,000 |
| PACS/RIS | 2 | 1 hour | 1 hour | 4 hours | $7,000 |
| Pharmacy Dispensing System | 1 | 30 minutes | 15 minutes | 2 hours | $5,000 |
| Medical Device Integration Gateway | 1 | 30 minutes | 15 minutes | 1 hour | $3,000 |
| Network Core | 1 | 15 minutes | 24 hours (configuration) | 1 hour | $25,000 |
| Email and Secure Messaging | 3 | 4 hours | 1 hour | 12 hours | $1,500 |
| Backup and DR Infrastructure | 2 | 2 hours | 1 hour (catalog) | 8 hours | $2,000 |
| Security Operations Platform | 3 | 4 hours | 1 hour (events) | 12 hours | $1,000 |

**Tier 4:** None assigned among these ten deliberately critical systems; the absence of a Tier 4 designation is not an omission. Noncritical business-support applications are outside the requested scope.

## Assumptions and Limitations

1. **No sign-off yet:** CISO approval and system-owner validation are pending; this document must not be represented as signed or approved.
2. **Targets are recommendations:** Source inventory provides DR status and dependencies, but not approved system-specific RTO/RPO/MTD values. Values in this BIA are reasoned proposals, not extracted facts.
3. **Financial figures are illustrative:** No revenue ledger, ED throughput, case mix, diversion cost or service-line billing evidence was supplied. Finance must validate each estimate. Exposures overlap and must not be summed.
4. **Clinical impact is scenario-based:** Consequences reflect the provided downtime notes and a 24x7 acute-care hospital. Medical leadership must validate actual harm thresholds, bedside alarm independence and feasible manual staffing.
5. **Backup feasibility is unproven:** LIS nightly export cannot meet its proposed 1-hour RPO; the source materials also describe untested restore processes and incomplete vendor/device backup details. Other targets require comparison with the backup schedule and test evidence.
6. **Dependency model is preliminary:** Confirm service accounts, DNS, interface engine, vendor connectivity, storage, cloud access, modality networks and order of recovery with system owners.
7. **Regulatory references are scoped:** HIPAA references are those in the supplied map; Joint Commission expectations are thematic, not verified standard numbers. Legal/compliance review is required before asserting specific reportable events or deadlines.
8. **Recovery time must be measured end-to-end:** A server boot or restored database file is not proof of clinical availability. Include authentication, interfaces, functional transactions, critical-result checks and authorized clinical acceptance.
9. **Reassessment triggers:** Review at least annually and after infrastructure migration, material clinical workflow change, major incident or failed recovery test; document owner, approval date and changes.
10. **Required next actions:** Validate finance assumptions; secure clinical/CISO sign-off; reconcile proposed RPOs with actual backup schedules; update downtime procedures; execute timed restoration tests; record failed objectives and corrective owners.

**Approval record:** CISO signature and date must be completed by the authorized approver after review; no approval is implied by this draft.
