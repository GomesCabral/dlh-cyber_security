# Exercise Execution Record: Nexus Supply Chain Compromise Tabletop

**Simulation date:** 2026-10-27  
**Simulated by:** Pedro Cabral  
**Classification:** Internal - Exercise Use Only  
**Method:** Designer-only dry run; fictional dialogue and observed results below are simulated, not evidence of a live organizational exercise.  
**Inputs:** `exercise_scenario.md`, `inject_schedule.yaml` v1.0, `evaluation_criteria.yaml`, `capability_map.yaml`, `nexus_vendor_profile.md`. Participant guide and facilitator script were not provided among the available source files; this dry run uses the scenario, inject schedule and evaluation criteria as the operational script instead.

> **Timing and assessment convention:** T+ denotes minutes after exercise start. Each pass criterion is scored individually as PASS/FAIL based only on spoken or documented simulated actions. An unspoken intention is not credited. Fail indicators and findings are drawn from the corresponding existing evaluation criteria. No real logs, vendor calls or patient records were accessed.

---

## INJ-00 (T+0 min)

**Delivery:** Facilitator reads aloud; SOC alert card  
**Capabilities:** CAP-01

**Inject delivered (verbatim from `inject_schedule.yaml`):**

> Forty-five minutes ago, the SOC flagged unusual outbound traffic from SCHED-SVR-01, the Main campus scheduling server running the Nexus agent, to an unidentified external IP. EDR shows connections recurring about every four hours. Nexus appointment services remain available; there is no confirmed malicious cause, exfiltration, or appointment tampering.

**Simulated participant responses:**

- **James Chen (SOC Lead):** “I am opening INC-NEX-001 at T+2 as provisional SEV2 because repeated outbound EDR connections from a scheduling server are unexplained; preserve EDR and flow logs. I will compare the other sites, but I have not considered the agent update channel yet.”
- **Sarah Park (IT Director):** “I will act as incident commander and notify Robert Kim and Dr. Morales now. No isolation until volatile evidence is scoped.”
- **Dr. Patricia Morales (Executive sponsor):** “I am notified; keep patient operations stable while triage establishes scope.”
- **Helena Reyes (General Counsel):** “I am on standby; I need to know if regulated patient data is implicated.”
- **Marcus Webb (Communications Lead):** “I will not issue external communications without verified facts.”
- **Robert Kim (Infrastructure Lead):** “I will export firewall/EDR and Nexus agent-version logs before changes, then map traffic across sites.”
- **Clinical Director representative:** “Scheduling is still working; please warn us before any disruption.”

**Evaluation against pre-defined pass criteria:**

- **Criterion 1 — PASS:** Within five exercise minutes, explicitly opens an incident record and states provisional severity with a reason tied to the observed EDR traffic. **Observed:** {0: 'Incident INC-NEX-001 declared at T+2, provisional SEV2 linked to EDR callbacks.', 1: 'James rejected signature as safety proof and requested versions, timestamps and IOCs.', 2: 'James expanded scope to three sites and explicitly raised severity to provisional SEV1.', 3: 'James proposed containment and the clinical director challenged patient-care impact before a joint decision.', 4: 'Helena opened a documented assessment, separating possible access from confirmed disclosure.', 5: 'Marcus identified himself as authorized spokesperson; Helena reviewed the statement.', 6: 'Clinical director owned urgent-record verification and conditional patient contact today.'}
- **Criterion 2 — PASS:** Names an incident commander and at least two notification recipients by role or name. **Observed:** {0: 'Sarah named herself incident commander and notified Robert and Dr. Morales.', 1: 'James cited certificate-only validation and lack of hash pinning; assigned provenance/dependency review.', 2: 'Robert requested written build list, IOCs, discovery time and a T+55 update from Nexus SecOps.', 3: 'Sarah and Dr. Morales recorded partial restriction with authority and T+90 review.', 4: 'Helena stated the vendor 24-hour BAA term separately and requested the discovery timestamp.', 5: 'Marcus dictated a cautious holding statement without patient identifiers or unverified claims.', 6: 'Robert and James preserved logs and planned record-by-record reconciliation without bulk sync.'}
- **Criterion 3 — PASS:** Directs preservation of EDR, network, agent-version and update logs before destructive containment. **Observed:** {0: 'James and Robert requested EDR, network, agent-version and update logs before isolation.', 1: 'Robert used the documented 24x7 Nexus SecOps channel, was named liaison and set T+30 follow-up.', 2: 'Robert kept a call/email log, accepted single liaison ownership and noted the untested joint channel.', 3: '', 4: 'James and Robert requested scoped FHIR and service-account records for demographics and insurance, not charts.', 5: 'Dr. Morales delivered the board update at T+110 with facts, unknowns, impact, decisions, owners and T+140 update.', 6: 'Sarah set clean-build and integrity gates with clinical sign-off and executive approval.'}
- **Criterion 4 — FAIL:** Requests comparison of the four-hour pattern across sites and raises the Nexus agent or vendor update channel as a hypothesis without claiming attribution. **Observed:** No participant identified the Nexus agent or vendor update channel until the facilitator explicitly prompted them.

**Inject result:** FAIL (3/4 pass criteria satisfied).

**Documented finding (from evaluation criteria):**

> Initial incident triage did not consistently establish command, severity, evidence preservation and vendor-origin investigation. Action: update the SOC escalation matrix and first-response checklist with a vendor-agent anomaly trigger, named notification roles and a preserve-before-containment prompt. Owner: SOC Lead (James Chen); due: 14 days.

**Specific observed gap:** Vendor-update provenance was not raised until prompted; owner: James Chen (SOC Lead), verify by an unprompted vendor-update hypothesis in a repeat drill within 14 days.

**Facilitator probe:** “What if the traffic is from a trusted signed Nexus agent update?”
**What it revealed:** No participant independently named the vendor update path during initial triage; the prompt exposed a detection hypothesis gap.

---

## INJ-01 (T+20 min)

**Delivery:** Facilitator reads aloud; simulated Nexus security advisory  
**Capabilities:** CAP-01, CAP-02, CAP-08

**Inject delivered (verbatim from `inject_schedule.yaml`):**

> Nexus SecOps issues an advisory: its build pipeline was accessed by an unauthorized actor three days ago, and a malicious component may have been distributed through the automatic signed nexus-agent update channel. The update is signed with Nexus Health Technologies' valid certificate. Nexus has no validated clean replacement yet and cannot confirm which customers or versions are affected. The board requests a decision-ready incident briefing in 90 minutes (due at exercise minute 110).

**Simulated participant responses:**

- **James Chen (SOC Lead):** “A valid signature does not mean this build is safe; I want deployed versions, signing timestamps and Nexus indicators. Our last vendor review flagged certificate-only validation without independent hash pinning and missing dependency inventory.”
- **Sarah Park (IT Director):** “I will freeze further automatic agent updates where safe, assign Robert as Nexus liaison and request vendor containment guidance. James owns the board briefing due at T+110.”
- **Dr. Patricia Morales (Executive sponsor):** “I want the brief to separate confirmed facts from hypotheses and include a decision request.”
- **Helena Reyes (General Counsel):** “We should request the vendor's discovery time and preserve the BAA correspondence.”
- **Marcus Webb (Communications Lead):** “I will prepare a holding statement for review but not publish it.”
- **Robert Kim (Infrastructure Lead):** “I will call Nexus SecOps at +1 512 555 0184, email soc@nexushealth.io for affected builds and IOCs, and ask for a response by T+30.”
- **Clinical Director representative:** “Do not interrupt time-sensitive appointments without a clinical fallback.”

**Evaluation against pre-defined pass criteria:**

- **Criterion 1 — PASS:** States that a valid Nexus code signature does not establish that the signed update is safe; requests deployed agent versions, timestamps and available indicators. **Observed:** {0: 'Incident INC-NEX-001 declared at T+2, provisional SEV2 linked to EDR callbacks.', 1: 'James rejected signature as safety proof and requested versions, timestamps and IOCs.', 2: 'James expanded scope to three sites and explicitly raised severity to provisional SEV1.', 3: 'James proposed containment and the clinical director challenged patient-care impact before a joint decision.', 4: 'Helena opened a documented assessment, separating possible access from confirmed disclosure.', 5: 'Marcus identified himself as authorized spokesperson; Helena reviewed the statement.', 6: 'Clinical director owned urgent-record verification and conditional patient contact today.'}
- **Criterion 2 — PASS:** References the vendor review limitation (certificate-only validation without independent hash pinning) and assigns investigation of update provenance and dependency risk. **Observed:** {0: 'Sarah named herself incident commander and notified Robert and Dr. Morales.', 1: 'James cited certificate-only validation and lack of hash pinning; assigned provenance/dependency review.', 2: 'Robert requested written build list, IOCs, discovery time and a T+55 update from Nexus SecOps.', 3: 'Sarah and Dr. Morales recorded partial restriction with authority and T+90 review.', 4: 'Helena stated the vendor 24-hour BAA term separately and requested the discovery timestamp.', 5: 'Marcus dictated a cautious holding statement without patient identifiers or unverified claims.', 6: 'Robert and James preserved logs and planned record-by-record reconciliation without bulk sync.'}
- **Criterion 3 — PASS:** Names a Nexus SecOps contact through the documented 24x7 channel, a MedDefense liaison, a written request for affected versions and containment guidance, and a timed follow-up. **Observed:** {0: 'James and Robert requested EDR, network, agent-version and update logs before isolation.', 1: 'Robert used the documented 24x7 Nexus SecOps channel, was named liaison and set T+30 follow-up.', 2: 'Robert kept a call/email log, accepted single liaison ownership and noted the untested joint channel.', 3: '', 4: 'James and Robert requested scoped FHIR and service-account records for demographics and insurance, not charts.', 5: 'Dr. Morales delivered the board update at T+110 with facts, unknowns, impact, decisions, owners and T+140 update.', 6: 'Sarah set clean-build and integrity gates with clinical sign-off and executive approval.'}
- **Criterion 4 — PASS:** Assigns an owner to deliver the board brief by exercise minute 110, explicitly covering unknowns. **Observed:** {0: 'No vendor-origin hypothesis raised.', 1: 'Sarah assigned James the T+110 board briefing with unknowns.', 2: 'James and Helena requested FHIR, svc-nexus-prod and endpoint evidence; no theft was asserted.', 3: 'Robert defined egress restrictions and monitoring; Helena rejected reliance on unverified SLA, and restoration required validation.', 4: 'Helena owned the assessment with T+100 evidence and T+115 decision checkpoints.', 5: 'Marcus acknowledged pending Nexus coordination without making it a veto.', 6: 'Helena owned unresolved change provenance; Robert owned missing change logs; T+180 and 24-hour checkpoints set.'}

**Inject result:** PASS (4/4 pass criteria satisfied).

**Facilitator probe:** “Can a valid code-signing certificate guarantee a clean update?”
**What it revealed:** The team challenged signing trust and referenced the prior lack of independent hash pinning.

---

## INJ-02 (T+40 min)

**Delivery:** Facilitator reads aloud; simulated vendor call and SOC correlation  
**Capabilities:** CAP-02, CAP-04

**Inject delivered (verbatim from `inject_schedule.yaml`):**

> Nexus confirms that the affected signed release was delivered to SCHED-SVR-01 and says other customer installations may be exposed. The SOC now finds matching four-hour outbound connection patterns on Nexus agent systems at West Campus and North Site; their hostnames have not yet been validated. Nexus cannot say whether patient demographics, insurance data, or appointment records were accessed through the HL7 FHIR R4 integration and svc-nexus-prod account. The vendor asks MedDefense to keep the integration online while it investigates.

**Simulated participant responses:**

- **James Chen (SOC Lead):** “The matching pattern at all three sites expands the suspected scope; I raise this to provisional SEV1 and request FHIR audit logs and svc-nexus-prod token events. No PHI theft is confirmed.”
- **Sarah Park (IT Director):** “I will coordinate the three-site evidence inventory and keep the incident record current.”
- **Dr. Patricia Morales (Executive sponsor):** “I need an operational impact summary before authorizing disruptive controls.”
- **Helena Reyes (General Counsel):** “I will lead provisional ePHI scoping, with demographics and insurance data as potential categories; no clinical chart access is established.”
- **Marcus Webb (Communications Lead):** “I will track what is verified and what remains unknown for future statements.”
- **Robert Kim (Infrastructure Lead):** “I have asked Nexus SecOps for written affected-version lists, discovery time and a T+55 update. I will record this call and email in the liaison log; our joint communication route has not been exercised recently.”
- **Clinical Director representative:** “Please assess how a three-site outage would affect today’s patients.”

**Evaluation against pre-defined pass criteria:**

- **Criterion 1 — PASS:** Records that matching four-hour patterns on additional Nexus agent hosts increase the potential scope and explicitly reassesses severity and affected sites. **Observed:** {0: 'Incident INC-NEX-001 declared at T+2, provisional SEV2 linked to EDR callbacks.', 1: 'James rejected signature as safety proof and requested versions, timestamps and IOCs.', 2: 'James expanded scope to three sites and explicitly raised severity to provisional SEV1.', 3: 'James proposed containment and the clinical director challenged patient-care impact before a joint decision.', 4: 'Helena opened a documented assessment, separating possible access from confirmed disclosure.', 5: 'Marcus identified himself as authorized spokesperson; Helena reviewed the statement.', 6: 'Clinical director owned urgent-record verification and conditional patient contact today.'}
- **Criterion 2 — PASS:** Escalates to Nexus SecOps or CISO with a written, time-bound request for affected versions, scope, IOCs, discovery timestamp and next update. **Observed:** {0: 'Sarah named herself incident commander and notified Robert and Dr. Morales.', 1: 'James cited certificate-only validation and lack of hash pinning; assigned provenance/dependency review.', 2: 'Robert requested written build list, IOCs, discovery time and a T+55 update from Nexus SecOps.', 3: 'Sarah and Dr. Morales recorded partial restriction with authority and T+90 review.', 4: 'Helena stated the vendor 24-hour BAA term separately and requested the discovery timestamp.', 5: 'Marcus dictated a cautious holding statement without patient identifiers or unverified claims.', 6: 'Robert and James preserved logs and planned record-by-record reconciliation without bulk sync.'}
- **Criterion 3 — PASS:** Assigns a single vendor liaison and records contact attempt, response, owner and next contact time; acknowledges that the joint communications route was not previously tested. **Observed:** {0: 'James and Robert requested EDR, network, agent-version and update logs before isolation.', 1: 'Robert used the documented 24x7 Nexus SecOps channel, was named liaison and set T+30 follow-up.', 2: 'Robert kept a call/email log, accepted single liaison ownership and noted the untested joint channel.', 3: '', 4: 'James and Robert requested scoped FHIR and service-account records for demographics and insurance, not charts.', 5: 'Dr. Morales delivered the board update at T+110 with facts, unknowns, impact, decisions, owners and T+140 update.', 6: 'Sarah set clean-build and integrity gates with clinical sign-off and executive approval.'}
- **Criterion 4 — PASS:** Orders preservation and correlation of FHIR access/audit records, OAuth2 svc-nexus-prod activity and endpoint telemetry; states a provisional exposure window without claiming confirmed PHI theft. **Observed:** {0: 'No vendor-origin hypothesis raised.', 1: 'Sarah assigned James the T+110 board briefing with unknowns.', 2: 'James and Helena requested FHIR, svc-nexus-prod and endpoint evidence; no theft was asserted.', 3: 'Robert defined egress restrictions and monitoring; Helena rejected reliance on unverified SLA, and restoration required validation.', 4: 'Helena owned the assessment with T+100 evidence and T+115 decision checkpoints.', 5: 'Marcus acknowledged pending Nexus coordination without making it a veto.', 6: 'Helena owned unresolved change provenance; Robert owned missing change logs; T+180 and 24-hour checkpoints set.'}

**Inject result:** PASS (4/4 pass criteria satisfied).

**Facilitator probe:** “Who has proof that the vendor advice is safe for our three sites?”
**What it revealed:** The team demanded written evidence and a named vendor escalation path instead of accepting reassurance.

---

## INJ-03 (T+60 min)

**Delivery:** Facilitator reads aloud; simulated security-versus-clinical escalation  
**Capabilities:** CAP-03

**Inject delivered (verbatim from `inject_schedule.yaml`):**

> Security recommends isolating the Nexus agent hosts and suspending the inbound Nexus-to-Epic scheduling feed. The clinical director objects: three sites rely on Nexus for outpatient scheduling, pre-registration and eligibility checks, representing about 3,500 patient interactions each week. A same-day clinic has time-sensitive appointments; switching to manual booking may create delays or duplicate bookings. No approved recovery-time SLA or fully tested manual fallback has been produced.

**Simulated participant responses:**

- **James Chen (SOC Lead):** “I recommend restricting compromised agent execution and inbound feeds; I will monitor for new callbacks and retain evidence.”
- **Sarah Park (IT Director):** “I propose a two-hour partial isolation with network controls, subject to clinical sign-off; I will be the technical decision owner and reassess at T+90.”
- **Dr. Patricia Morales (Executive sponsor):** “I approve the temporary restriction jointly with the clinical director, accepting documented delays rather than uncontrolled compromise.”
- **Helena Reyes (General Counsel):** “Record the risk acceptance and ensure we do not rely on an unverified SLA.”
- **Marcus Webb (Communications Lead):** “I will prepare patient-facing language if appointment changes become necessary.”
- **Robert Kim (Infrastructure Lead):** “I can block agent egress and untrusted updates while keeping an audited emergency booking route; restore only after a clean build and validation.”
- **Clinical Director representative:** “I object to a blanket shutdown because urgent appointments are at risk. I agree to a partial restriction, but our paper-booking plan does not yet specify how duplicate bookings will be checked across all sites.”

**Evaluation against pre-defined pass criteria:**

- **Criterion 1 — PASS:** Security and clinical representatives each state their operational concerns before an isolation, partial restriction or temporary-operation decision is recorded. **Observed:** {0: 'Incident INC-NEX-001 declared at T+2, provisional SEV2 linked to EDR callbacks.', 1: 'James rejected signature as safety proof and requested versions, timestamps and IOCs.', 2: 'James expanded scope to three sites and explicitly raised severity to provisional SEV1.', 3: 'James proposed containment and the clinical director challenged patient-care impact before a joint decision.', 4: 'Helena opened a documented assessment, separating possible access from confirmed disclosure.', 5: 'Marcus identified himself as authorized spokesperson; Helena reviewed the statement.', 6: 'Clinical director owned urgent-record verification and conditional patient contact today.'}
- **Criterion 2 — PASS:** Names the person with decision authority and records a time-limited choice, risk acceptance and a specific reassessment time. **Observed:** {0: 'Sarah named herself incident commander and notified Robert and Dr. Morales.', 1: 'James cited certificate-only validation and lack of hash pinning; assigned provenance/dependency review.', 2: 'Robert requested written build list, IOCs, discovery time and a T+55 update from Nexus SecOps.', 3: 'Sarah and Dr. Morales recorded partial restriction with authority and T+90 review.', 4: 'Helena stated the vendor 24-hour BAA term separately and requested the discovery timestamp.', 5: 'Marcus dictated a cautious holding statement without patient identifiers or unverified claims.', 6: 'Robert and James preserved logs and planned record-by-record reconciliation without bulk sync.'}
- **Criterion 3 — FAIL:** Identifies how critical appointments will be prioritized and how manual scheduling, duplicate booking prevention and reconciliation will operate across all three sites. **Observed:** The clinical representative explicitly stated that no cross-site duplicate-booking check was defined.
- **Criterion 4 — PASS:** Defines monitoring and conditions for further containment or restoration; requests verification of any assumed SLA or fallback rather than inventing it. **Observed:** {0: 'No vendor-origin hypothesis raised.', 1: 'Sarah assigned James the T+110 board briefing with unknowns.', 2: 'James and Helena requested FHIR, svc-nexus-prod and endpoint evidence; no theft was asserted.', 3: 'Robert defined egress restrictions and monitoring; Helena rejected reliance on unverified SLA, and restoration required validation.', 4: 'Helena owned the assessment with T+100 evidence and T+115 decision checkpoints.', 5: 'Marcus acknowledged pending Nexus coordination without making it a veto.', 6: 'Helena owned unresolved change provenance; Robert owned missing change logs; T+180 and 24-hour checkpoints set.'}

**Inject result:** FAIL (3/4 pass criteria satisfied).

**Documented finding (from evaluation criteria):**

> No accountable, patient-safety-informed containment decision or workable scheduling fallback was demonstrated. Action: approve a joint IT/clinical isolation authority matrix, rehearse manual appointment prioritization and reconciliation, and validate vendor recovery commitments. Owner: IT Director (Sarah Park) and Clinical Director; due: 30 days.

**Specific observed gap:** No cross-site duplicate-booking workflow was described; owners: Sarah Park and Clinical Director, verify by a timed three-site manual-booking reconciliation drill within 30 days.

**Facilitator probe:** “How will staff prevent duplicate bookings during a partial outage at all three sites?”
**What it revealed:** The clinical representative acknowledged there was no defined cross-site duplicate-check workflow; the fallback was incomplete.

---

## INJ-04 (T+80 min)

**Delivery:** Facilitator reads aloud; simulated vendor privacy notice  
**Capabilities:** CAP-04, CAP-05

**Inject delivered (verbatim from `inject_schedule.yaml`):**

> Nexus reports that an attacker may have queried patient demographic and insurance records during the compromise window, but has not confirmed acquisition or disclosure. Its legal team says the investigation is ongoing and will not yet label the event a breach. The Nexus BAA requires notification to MedDefense within 24 hours of Nexus discovering a breach; the vendor has not supplied a reliable discovery timestamp or affected patient count. MedDefense's own HIPAA notification posture remains open.

**Simulated participant responses:**

- **James Chen (SOC Lead):** “I will preserve FHIR access records and the service-principal audit trail and estimate a provisional window without assuming exfiltration.”
- **Sarah Park (IT Director):** “I will keep the affected systems restricted pending the privacy and clinical decisions.”
- **Dr. Patricia Morales (Executive sponsor):** “I want a written decision checkpoint today, not an unsupported public breach declaration.”
- **Helena Reyes (General Counsel):** “I am opening a documented HIPAA breach-risk assessment. Nexus's BAA requires vendor-to-MedDefense notification within 24 hours of discovery of a breach; that is not automatically our patient-notification deadline. Request their discovery timestamp and affected records by T+100; reassess at T+115.”
- **Marcus Webb (Communications Lead):** “I will hold public language until Legal approves it, while drafting an uncertainty-aware response.”
- **Robert Kim (Infrastructure Lead):** “I will request Nexus and Epic audit exports for demographics, insurance queries and appointment access, not assume clinical-chart exposure.”
- **Clinical Director representative:** “I will identify patients requiring continuity checks, but not assume their records were altered.”

**Evaluation against pre-defined pass criteria:**

- **Criterion 1 — PASS:** Legal/Privacy explicitly starts and assigns a documented HIPAA breach-risk assessment and distinguishes suspected access from confirmed acquisition or disclosure. **Observed:** {0: 'Incident INC-NEX-001 declared at T+2, provisional SEV2 linked to EDR callbacks.', 1: 'James rejected signature as safety proof and requested versions, timestamps and IOCs.', 2: 'James expanded scope to three sites and explicitly raised severity to provisional SEV1.', 3: 'James proposed containment and the clinical director challenged patient-care impact before a joint decision.', 4: 'Helena opened a documented assessment, separating possible access from confirmed disclosure.', 5: 'Marcus identified himself as authorized spokesperson; Helena reviewed the statement.', 6: 'Clinical director owned urgent-record verification and conditional patient contact today.'}
- **Criterion 2 — PASS:** States the Nexus BAA obligation to notify MedDefense within 24 hours of discovery of a breach, separately from MedDefense notification determinations; requests the vendor discovery timestamp. **Observed:** {0: 'Sarah named herself incident commander and notified Robert and Dr. Morales.', 1: 'James cited certificate-only validation and lack of hash pinning; assigned provenance/dependency review.', 2: 'Robert requested written build list, IOCs, discovery time and a T+55 update from Nexus SecOps.', 3: 'Sarah and Dr. Morales recorded partial restriction with authority and T+90 review.', 4: 'Helena stated the vendor 24-hour BAA term separately and requested the discovery timestamp.', 5: 'Marcus dictated a cautious holding statement without patient identifiers or unverified claims.', 6: 'Robert and James preserved logs and planned record-by-record reconciliation without bulk sync.'}
- **Criterion 3 — PASS:** Requests a bounded ePHI population, demographics/insurance categories, FHIR access evidence and affected records, without asserting unsupported clinical-chart exposure. **Observed:** {0: 'James and Robert requested EDR, network, agent-version and update logs before isolation.', 1: 'Robert used the documented 24x7 Nexus SecOps channel, was named liaison and set T+30 follow-up.', 2: 'Robert kept a call/email log, accepted single liaison ownership and noted the untested joint channel.', 3: '', 4: 'James and Robert requested scoped FHIR and service-account records for demographics and insurance, not charts.', 5: 'Dr. Morales delivered the board update at T+110 with facts, unknowns, impact, decisions, owners and T+140 update.', 6: 'Sarah set clean-build and integrity gates with clinical sign-off and executive approval.'}
- **Criterion 4 — PASS:** Records an owner, next evidence deadline, notification decision checkpoint and reasons for any current uncertainty. **Observed:** {0: 'No vendor-origin hypothesis raised.', 1: 'Sarah assigned James the T+110 board briefing with unknowns.', 2: 'James and Helena requested FHIR, svc-nexus-prod and endpoint evidence; no theft was asserted.', 3: 'Robert defined egress restrictions and monitoring; Helena rejected reliance on unverified SLA, and restoration required validation.', 4: 'Helena owned the assessment with T+100 evidence and T+115 decision checkpoints.', 5: 'Marcus acknowledged pending Nexus coordination without making it a veto.', 6: 'Helena owned unresolved change provenance; Robert owned missing change logs; T+180 and 24-hour checkpoints set.'}

**Inject result:** PASS (4/4 pass criteria satisfied).

**Facilitator probe:** “Does the 24-hour BAA clause automatically set MedDefense patient-notification timing?”
**What it revealed:** Legal distinguished the vendor contractual duty from the covered entity’s separate breach assessment.

---

## INJ-05 (T+110 min)

**Delivery:** Facilitator reads aloud; simulated media email and board request  
**Capabilities:** CAP-07, CAP-08

**Inject delivered (verbatim from `inject_schedule.yaml`):**

> A local reporter asks whether MedDefense's scheduling provider has been hacked and whether patient information is exposed. Social media posts claim appointments are being cancelled. The board is now waiting for the 90-minute status briefing requested at minute 20. Nexus has not approved a joint public statement and the exposure scope is unresolved.

**Simulated participant responses:**

- **James Chen (SOC Lead):** “My T+110 board brief says three sites show suspicious agent activity, PHI scope is unknown, and investigation continues; I will circulate the incident timeline.”
- **Sarah Park (IT Director):** “We have partially restricted the integration, with clinical approval, and are checking urgent appointment operations. The next technical checkpoint is T+140.”
- **Dr. Patricia Morales (Executive sponsor):** “I am delivering the brief now: confirmed agent warning and three-site indicators, possible patient impact, unconfirmed PHI access, vendor investigation, restriction decision, owners and next update at T+140.”
- **Helena Reyes (General Counsel):** “I approve the holding statement after confirming it does not assert a breach or name patients. HIPAA assessment remains open.”
- **Marcus Webb (Communications Lead):** “I am the authorized spokesperson. My holding statement is: 'We are investigating a security concern involving an appointment technology provider; we are assessing service and data impacts and will share verified updates.' Nexus coordination is pending, but that does not prevent our own approved statement.”
- **Robert Kim (Infrastructure Lead):** “I will provide operational status and current containment evidence to the board.”
- **Clinical Director representative:** “We have not confirmed the social-media claims of cancelled appointments; priority clinics are being checked.”

**Evaluation against pre-defined pass criteria:**

- **Criterion 1 — PASS:** Names an authorized spokesperson and routes the media request for Legal/Privacy review before any external statement. **Observed:** {0: 'Incident INC-NEX-001 declared at T+2, provisional SEV2 linked to EDR callbacks.', 1: 'James rejected signature as safety proof and requested versions, timestamps and IOCs.', 2: 'James expanded scope to three sites and explicitly raised severity to provisional SEV1.', 3: 'James proposed containment and the clinical director challenged patient-care impact before a joint decision.', 4: 'Helena opened a documented assessment, separating possible access from confirmed disclosure.', 5: 'Marcus identified himself as authorized spokesperson; Helena reviewed the statement.', 6: 'Clinical director owned urgent-record verification and conditional patient contact today.'}
- **Criterion 2 — PASS:** Produces or dictates a holding statement separating confirmed operational facts from unverified PHI and appointment claims, without patient identifiers. **Observed:** {0: 'Sarah named herself incident commander and notified Robert and Dr. Morales.', 1: 'James cited certificate-only validation and lack of hash pinning; assigned provenance/dependency review.', 2: 'Robert requested written build list, IOCs, discovery time and a T+55 update from Nexus SecOps.', 3: 'Sarah and Dr. Morales recorded partial restriction with authority and T+90 review.', 4: 'Helena stated the vendor 24-hour BAA term separately and requested the discovery timestamp.', 5: 'Marcus dictated a cautious holding statement without patient identifiers or unverified claims.', 6: 'Robert and James preserved logs and planned record-by-record reconciliation without bulk sync.'}
- **Criterion 3 — PASS:** Delivers the requested board update by exercise minute 110 with confirmed facts, unknowns, patient and operational impact, vendor status, containment decision, HIPAA posture, owners and next update time. **Observed:** {0: 'James and Robert requested EDR, network, agent-version and update logs before isolation.', 1: 'Robert used the documented 24x7 Nexus SecOps channel, was named liaison and set T+30 follow-up.', 2: 'Robert kept a call/email log, accepted single liaison ownership and noted the untested joint channel.', 3: '', 4: 'James and Robert requested scoped FHIR and service-account records for demographics and insurance, not charts.', 5: 'Dr. Morales delivered the board update at T+110 with facts, unknowns, impact, decisions, owners and T+140 update.', 6: 'Sarah set clean-build and integrity gates with clinical sign-off and executive approval.'}
- **Criterion 4 — PASS:** Documents whether Nexus coordination is pending and does not make vendor approval a prerequisite for all time-critical MedDefense communications. **Observed:** {0: 'No vendor-origin hypothesis raised.', 1: 'Sarah assigned James the T+110 board briefing with unknowns.', 2: 'James and Helena requested FHIR, svc-nexus-prod and endpoint evidence; no theft was asserted.', 3: 'Robert defined egress restrictions and monitoring; Helena rejected reliance on unverified SLA, and restoration required validation.', 4: 'Helena owned the assessment with T+100 evidence and T+115 decision checkpoints.', 5: 'Marcus acknowledged pending Nexus coordination without making it a veto.', 6: 'Helena owned unresolved change provenance; Robert owned missing change logs; T+180 and 24-hour checkpoints set.'}

**Inject result:** PASS (4/4 pass criteria satisfied).

**Facilitator probe:** “If Nexus will not approve a statement, can you still brief the board and respond?”
**What it revealed:** Communications demonstrated a controlled, independently authorized holding statement and an on-time board brief.

---

## INJ-06 (T+120 min)

**Delivery:** Facilitator reads aloud; simulated clinical reconciliation finding  
**Capabilities:** CAP-03, CAP-06

**Inject delivered (verbatim from `inject_schedule.yaml`):**

> Clinical staff identify several time-sensitive appointments whose Nexus status differs from the corresponding Epic record. It is not yet known whether the discrepancies are malicious changes, synchronization delays, or ordinary workflow errors. Nexus says it may need another 24 hours to provide a reliable change log. The clinical director asks whether the affected patients should be contacted today and whether Nexus can safely be restored. No verified clean agent build or complete integrity baseline is available before the exercise ends.

**Simulated participant responses:**

- **James Chen (SOC Lead):** “Preserve Nexus and Epic change/audit logs; do not bulk-resynchronize or declare this resolved. We need a validated clean agent, checked access controls and record-integrity evidence before restoration.”
- **Sarah Park (IT Director):** “I will not restore until James validates the build and the clinical director signs off on reconciled critical records; Dr. Morales is final risk approver. Review at T+180.”
- **Dr. Patricia Morales (Executive sponsor):** “This remains open. I authorize priority patient verification now and require a written unresolved-issues register before close.”
- **Helena Reyes (General Counsel):** “We cannot yet determine whether these discrepancies constitute unauthorized modifications or change our notification posture; I own that legal question, with Nexus logs requested by tomorrow at 12:00.”
- **Marcus Webb (Communications Lead):** “I will prepare targeted patient-contact language only for confirmed operational discrepancies, subject to clinical and Legal review.”
- **Robert Kim (Infrastructure Lead):** “I will preserve both systems' audit logs and reconcile records one by one. I own the missing Nexus change-log request and will check again in 24 hours.”
- **Clinical Director representative:** “I own immediate verification of time-sensitive appointments and will contact affected patients today if the discrepancies threaten care. We will cross-check Epic and paper records before changing any bookings.”

**Evaluation against pre-defined pass criteria:**

- **Criterion 1 — PASS:** Names a clinical owner and orders immediate verification and prioritization of time-sensitive discrepant appointments, including a patient contact decision with a documented rationale. **Observed:** {0: 'Incident INC-NEX-001 declared at T+2, provisional SEV2 linked to EDR callbacks.', 1: 'James rejected signature as safety proof and requested versions, timestamps and IOCs.', 2: 'James expanded scope to three sites and explicitly raised severity to provisional SEV1.', 3: 'James proposed containment and the clinical director challenged patient-care impact before a joint decision.', 4: 'Helena opened a documented assessment, separating possible access from confirmed disclosure.', 5: 'Marcus identified himself as authorized spokesperson; Helena reviewed the statement.', 6: 'Clinical director owned urgent-record verification and conditional patient contact today.'}
- **Criterion 2 — PASS:** Preserves Nexus and Epic audit/change logs and describes record-by-record reconciliation without unverified bulk synchronization. **Observed:** {0: 'Sarah named herself incident commander and notified Robert and Dr. Morales.', 1: 'James cited certificate-only validation and lack of hash pinning; assigned provenance/dependency review.', 2: 'Robert requested written build list, IOCs, discovery time and a T+55 update from Nexus SecOps.', 3: 'Sarah and Dr. Morales recorded partial restriction with authority and T+90 review.', 4: 'Helena stated the vendor 24-hour BAA term separately and requested the discovery timestamp.', 5: 'Marcus dictated a cautious holding statement without patient identifiers or unverified claims.', 6: 'Robert and James preserved logs and planned record-by-record reconciliation without bulk sync.'}
- **Criterion 3 — PASS:** Records explicit criteria and approval authority for any service restoration, including clean agent validation, integrity checks and clinical sign-off. **Observed:** {0: 'James and Robert requested EDR, network, agent-version and update logs before isolation.', 1: 'Robert used the documented 24x7 Nexus SecOps channel, was named liaison and set T+30 follow-up.', 2: 'Robert kept a call/email log, accepted single liaison ownership and noted the untested joint channel.', 3: '', 4: 'James and Robert requested scoped FHIR and service-account records for demographics and insurance, not charts.', 5: 'Dr. Morales delivered the board update at T+110 with facts, unknowns, impact, decisions, owners and T+140 update.', 6: 'Sarah set clean-build and integrity gates with clinical sign-off and executive approval.'}
- **Criterion 4 — PASS:** Lists at least two unresolved questions (such as whether changes were malicious and which records are affected), each with an owner, evidence request and next checkpoint. **Observed:** {0: 'No vendor-origin hypothesis raised.', 1: 'Sarah assigned James the T+110 board briefing with unknowns.', 2: 'James and Helena requested FHIR, svc-nexus-prod and endpoint evidence; no theft was asserted.', 3: 'Robert defined egress restrictions and monitoring; Helena rejected reliance on unverified SLA, and restoration required validation.', 4: 'Helena owned the assessment with T+100 evidence and T+115 decision checkpoints.', 5: 'Marcus acknowledged pending Nexus coordination without making it a veto.', 6: 'Helena owned unresolved change provenance; Robert owned missing change logs; T+180 and 24-hour checkpoints set.'}

**Inject result:** PASS (4/4 pass criteria satisfied).

**Facilitator probe:** “Which two facts cannot be resolved today, and who will pursue each?”
**What it revealed:** The team named unresolved change provenance and affected-record scope with owners and follow-up times.

---

## Simulation outcome

- **Coverage:** 7/7 injects delivered in sequence; 7 participant roles voiced at each inject; 28 pass criteria assessed.
- **Criterion-level result:** 26 PASS; 2 FAIL. Inject-level result: 5 PASS; 2 FAIL (INJ-00 and INJ-03).
- **Findings requiring validation:** (1) vendor-origin detection hypothesis absent during initial triage; (2) manual fallback lacks a cross-site duplicate-booking check. These are **simulated design-test observations**, not verified MedDefense deficiencies.
- **Open questions at end:** malicious modification versus synchronization error (Helena/James; evidence review T+180); precise affected appointment population (Clinical Director/Robert; reconcile priority cases today); validated clean Nexus agent availability (Sarah/Robert; vendor follow-up within 24 hours). No claim of full resolution is made.

## Design feedback — defects found and changes specified

### DF-01 — Capability-to-inject references do not match the seven-inject schedule

**Observed design defect:** `capability_map.yaml` v1.0 refers to INJ-07, INJ-08 and INJ-09, which do not exist in the seven-inject schedule. This would prevent a reliable trace from CAP-06/07/08 to evaluation evidence.

**Specific change:** Update CAP-06 `tested_by_inject` to `[INJ-06]`; CAP-07 to `[INJ-05]`; CAP-08 to `[INJ-01, INJ-05]`. Keep CAP-01–CAP-05 references unchanged. Add a CI check rejecting references to undefined inject IDs. **Status:** design correction specified here; source `capability_map.yaml` requires a separate edit before the live exercise.

### DF-02 — First inject cannot fairly test vendor-origin hypothesis without a probe

**Observed design defect:** At T+0, participants receive only an unknown outbound IP and recurring connections. The vendor update path is plausible but not in the visible alert; a strict criterion requiring vendor-origin suspicion can score an otherwise sound triage as FAIL. The simulation demonstrated this sensitivity.

**Specific change:** Amend INJ-00 situation with a neutral, observable fact: `EDR process lineage associates the connections with nexus-agent; no update history has yet been checked.` Do **not** disclose malicious provenance. Revise INJ-00 criterion 4 to require participants to consider the named process/vendor update hypothesis, without demanding correct attribution. **Status:** proposed textual patch; not silently applied to the existing schedule or evaluation file.

### DF-03 — Continuity evaluation needs a measurable manual fallback test

**Observed design defect:** INJ-03 asks participants to describe manual booking and duplicate prevention, but does not provide a concrete operational trigger or sample workload. The team could announce a generic fallback without proving cross-site reconciliation; the dry run exposed this gap.

**Specific change:** Add to INJ-03: `The clinical director requests a written process for 12 time-sensitive appointments spread across all three sites; two may appear on both the paper queue and Nexus.` Update criterion 3 to require a named clinical owner, a two-source verification step, duplicate detection, and a documented reconciliation checkpoint before appointments are confirmed. **Status:** proposed textual patch; source files remain unchanged until a controlled revision.

### Design change control

These three corrections are the exact changes to implement in a **v1.1** revision of `capability_map.yaml`, `inject_schedule.yaml` and `evaluation_criteria.yaml` before a live session. This execution record preserves the **verbatim v1.0 injects and v1.0 scoring** to maintain an auditable dry-run baseline; it does not pretend the upstream documents were already modified.

## Limitations

- The Nexus profile is fictional, and vendor responses, incident times and participant statements above are scripted simulation data.
- No separate participant guide or facilitator script was available in the provided materials, so their contents were not invented or quoted.
- An actual tabletop should be observed independently and should replace these simulated results with contemporaneous evidence.
