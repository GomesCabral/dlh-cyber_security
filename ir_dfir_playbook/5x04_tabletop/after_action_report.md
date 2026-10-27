# After-Action Report: Nexus Supply Chain Compromise Tabletop

**Exercise date:** 2026-10-27 (designer-only simulation)  
**Report date:** 2026-10-27  
**Facilitator:** Pedro Cabral  
**Participants (simulated):** James Chen (SOC Lead), Sarah Park (IT Director / Incident Commander), Dr. Patricia Morales (Executive Sponsor), Helena Reyes (General Counsel), Marcus Webb (Communications Lead), Robert Kim (Infrastructure Lead), Clinical Director representative  
**Classification:** Internal - Exercise Use Only  
**Evidence base:** `execution_record.md` (Task 7), `evaluation_criteria.yaml` v1.0 (Task 6), `inject_schedule.yaml` v1.0, and `nexus_vendor_profile.md`.  
**Status:** Simulated after-action report; not evidence of an exercise with actual MedDefense personnel.

---

## Executive summary

This designer-led dry run tested MedDefense's response to a suspected compromise of the trusted Nexus Patient Scheduling software-update channel. Seven timed injects assessed detection and escalation, vendor coordination, business continuity and patient safety, possible ePHI exposure and HIPAA obligations, crisis communications, and executive reporting. Each of the seven organizational roles was simulated; no actual systems, vendor contacts, or patient records were used.

Of **28 pre-established pass criteria, 26 passed and 2 failed**. Five injects passed in full (INJ-01, INJ-02, INJ-04, INJ-05 and INJ-06); two failed (INJ-00 and INJ-03). At INJ-00, the SOC declared a timely incident and preserved evidence but did not independently raise the Nexus agent/update path as a potential cause. At INJ-03, leadership agreed on a time-limited partial restriction with clinical input but could not describe a cross-site process to prevent duplicate appointments during manual scheduling. Both results are provisional because the dry run identified weaknesses in how these injects elicit and measure the required behavior.

**Top recommended action:** Jointly design and rehearse a three-site, patient-safety-approved manual scheduling and reconciliation procedure, including duplicate detection and named decision authority, within 30 days. Separately, strengthen vendor-origin investigation prompts in initial SOC triage and correct the exercise's own scoring and inject references before a live run.

---

## Findings table

| ID | Inject / criterion | Capability | Gap description (observed) | Severity | Recommended action | Owner role | Deadline (days) | Validation method |
|---|---|---|---|---|---|---|---:|---|
| **F-001** | **INJ-03 / criterion 3** | **CAP-03** — business continuity decision | The clinical representative acknowledged that no cross-site duplicate-booking check had been defined for the manual scheduling fallback, despite an approved partial restriction. | **P1** | Approve a three-site manual scheduling procedure with priority triage, two-source duplicate verification, reconciliation checkpoints and clinical sign-off; rehearse with representative time-sensitive appointments. | IT Director (Sarah Park) **and** Clinical Director | **30** | Timed three-site drill using 12 sample urgent appointments, including deliberate duplicates; signed reconciliation record and clinical acceptance. |
| **F-002** | **INJ-00 / criterion 4** | **CAP-01** — supply chain detection | Initial SOC triage did not independently name the Nexus agent/update channel as a hypothesis; it surfaced only after a facilitator probe. | **P2** | Add a vendor-agent/update provenance prompt to the SOC triage checklist and a vendor-origin anomaly escalation trigger; test without a facilitator hint. | SOC Lead (James Chen) | **14** | Repeat alert-triage drill with process lineage visible; observer verifies that vendor-update hypothesis, cross-site comparison and evidence-preservation steps are stated unprompted. |

**Severity basis:** P1 = plausible direct patient-care/continuity impact requiring prioritized remediation; P2 = meaningful detection-process gap with compensating incident escalation and evidence preservation demonstrated; P3 = lower-impact improvement. These priorities are recommendations for this simulated exercise, not measured operational risk ratings.

**Criterion traceability:** F-001 is the failed third pass criterion of INJ-03; F-002 is the failed fourth pass criterion of INJ-00 in `evaluation_criteria.yaml` v1.0. No additional operational findings are inferred from the five injects that passed. Design defects are tracked separately below, not misrepresented as participant failures.

---

## P1 finding narratives

### F-001 — Manual scheduling fallback lacks cross-site duplicate prevention

**INJ-03, criterion 3 (CAP-03):** During a direct disagreement between the security team, which sought restrictions on the affected Nexus agent, and the clinical representative, who warned of risks to time-sensitive appointments, Sarah Park and Dr. Morales authorized a time-limited partial restriction and set a reassessment point. However, the clinical representative explicitly said that the paper-booking fallback had no defined process for checking duplicate appointments across the three sites. This matters because uncoordinated scheduling could lead to missed, duplicated or conflicting care arrangements while Nexus remains restricted; declaring a fallback is not the same as demonstrating a safe one. **Action:** Sarah Park and the Clinical Director must jointly approve a cross-site manual scheduling and reconciliation workflow, including urgent-case prioritization, named owners, duplicate checks against both local paper queues and available Nexus/Epic records, documented checkpoints, and restoration sign-off. **Due:** 30 days. **Closure evidence:** a timed drill involving 12 time-sensitive sample appointments with planted duplicates, a completed reconciliation log and documented clinical approval. The drill workload is a proposed validation test, not an event that occurred in the v1.0 simulation.

---

## What worked

1. **Incident command and evidence preservation (INJ-00, criteria 1–3):** James Chen opened incident `INC-NEX-001` at T+2 with a provisional SEV2 rationale; Sarah Park assumed incident command and notified Robert Kim and Dr. Morales. James and Robert requested EDR, network, agent-version and update logs before destructive containment.
2. **Vendor and legal coordination (INJ-01/02/04):** The team rejected a valid code signature as proof of a safe update, recognized the absence of independent hash pinning, assigned Robert as Nexus liaison, and requested affected versions, indicators, discovery time and scoped FHIR/service-account evidence. Helena distinguished Nexus's contractual 24-hour Business Associate notification provision from MedDefense's separate HIPAA assessment rather than asserting a breach without proof.
3. **Controlled public and executive messaging (INJ-05):** Marcus Webb identified an authorized spokesperson and produced a cautious holding statement reviewed by Legal; Dr. Morales delivered a board-quality update at T+110 with known facts, uncertainties, impacts, decisions, owners and the next checkpoint.

---

## Exercise design feedback

- **DF-01 — Invalid inject references:** Task 7 found `capability_map.yaml` v1.0 still references INJ-07 through INJ-09 even though this exercise has only INJ-00–INJ-06. **Specified change:** map CAP-06 to INJ-06, CAP-07 to INJ-05 and CAP-08 to INJ-01/INJ-05, and add an automated check that every referenced inject exists.
- **DF-02 — Vendor-origin hypothesis not fairly elicited:** INJ-00 showed only unexplained outbound traffic, making its unprompted vendor-update criterion overly demanding. **Specified change:** add the neutral EDR process-lineage fact that connections originate from `nexus-agent`, without disclosing the cause, and adjust criterion 4 to test whether participants consider vendor provenance rather than correctly guess attribution.
- **DF-03 — Manual fallback test too abstract:** INJ-03 allowed participants to describe a fallback without demonstrating a real cross-site duplicate check. **Specified change:** introduce 12 time-sensitive appointments, with two potentially appearing in both paper and Nexus queues; require a clinical owner, two-source verification, duplicate detection and a recorded reconciliation checkpoint.

**Change-control note:** These three changes were **identified and specified** in Task 7, but have **not yet been applied** to the v1.0 source YAML files. Revise the capability map, inject schedule and evaluation criteria together as v1.1, then repeat the dry run before a live exercise. Findings above reflect the unchanged v1.0 criteria and simulated observations.

---

## Reporting limitations and follow-up

This report records **simulated participant decisions**, not real MedDefense control effectiveness. The exercise inputs did not include a separate participant guide or facilitator script; the dry run used the available scenario, inject schedule and evaluation criteria. Validation deadlines run from formal acceptance of this report, not automatically from the simulation date. Finding owners and validators should record actual completion evidence before either finding is closed.
