# Tabletop Exercise: Nexus Supply Chain Compromise

**Date:** 26 October 2026  
**Classification:** Internal - Exercise Use Only  
**Facilitator:** Pedro Cabral  
**Scenario version:** 1.0  
**Exercise type:** Discussion-based incident response tabletop

## Organization background

MedDefense provides healthcare services across three sites: West Campus, Main, and North Site. Its patient scheduling and pre-registration workflows depend on Nexus Patient Scheduling, which supports approximately 3,500 patient-facing interactions each week. MedDefense handles electronic protected health information (ePHI) and must assess applicable HIPAA security and breach-notification obligations when an incident may affect patient information.

## Vendor background

Nexus Patient Scheduling is a cloud-hosted, multi-tenant SaaS platform operated by Nexus Health Technologies, Inc., based in Austin, Texas. MedDefense has used Nexus since August 2023 for outpatient appointments, pre-registration, and insurance eligibility checks across all three sites. Nexus processes patient demographics, appointment information, and insurance information; it does not perform clinical charting. **Staff-rostering access has not been established in the available vendor profile and must be verified rather than assumed.**

Nexus exchanges information with MedDefense's Epic environment through a certified HL7 FHIR R4 integration over HTTPS. MedDefense sends scheduling requests, demographic details, and eligibility queries; Nexus returns confirmed appointments, wait-list notifications, and schedule updates. The integration uses OAuth2 client credentials associated with the `svc-nexus-prod` service principal, with a site-to-site IPsec connection for inbound Nexus traffic. Nexus also distributes automatically installed, digitally signed updates to an on-premises `nexus-agent`; the documented Main campus scheduling server is `SCHED-SVR-01`.

A Business Associate Agreement (BAA) is in force. It requires Nexus to notify MedDefense within **24 hours of discovering a breach**, provide an annual SOC 2 Type II report, and return or destroy protected health information upon termination. **Specific service-level agreement (SLA) uptime, recovery, and escalation commitments are not supplied in the vendor profile**; the response team must obtain and verify them before relying on contractual recovery targets.

The most recent documented vendor risk review identified residual concerns involving the signed-update verification approach, missing third-party dependency inventory for the on-premises agent, and an incident communication process that had not been tested in a joint exercise. These are pre-existing vendor-risk observations, **not proof of the cause of today's alert**.

## Opening situation

It is the morning of the exercise. **Forty-five minutes ago**, the MedDefense Security Operations Center (SOC) flagged unusual outbound traffic from the Main campus scheduling server, `SCHED-SVR-01`, to an unknown external IP address. Endpoint Detection and Response (EDR) telemetry shows that the outbound connections appear to recur at approximately **four-hour intervals**.

The server supports workflows that affect patient appointments across the organization. Nexus distributes signed software updates automatically, but at this stage the SOC has **not established whether an update, a vendor-side incident, or another cause** explains the traffic. The significance of the destination IP and the purpose of the connections are unknown.

There is a potential patient-safety concern: if appointment records have been modified, cancelled, or misrouted during an unknown compromise window, patients could miss clinically important care. **No alteration of appointment records has been confirmed at exercise start.**

The incident also raises a possible legal and contractual question. Nexus is a HIPAA Business Associate; if its systems or MedDefense's integration have exposed ePHI, MedDefense may need to assess its own breach-notification obligations. **Neither a reportable breach nor the start of any notification deadline has been established at this point.**

## Known facts at exercise start

1. **SOC alert:** An alert was raised 45 minutes before the exercise for unusual outbound traffic from `SCHED-SVR-01` at Main campus to an unidentified external IP address.
2. **Host identification:** `SCHED-SVR-01` is the documented Main campus scheduling server running the on-premises Nexus agent. Nexus supports West Campus, Main, and North Site; **the names and alert status of any other Nexus agent hosts have not yet been verified**.
3. **EDR observation:** Endpoint telemetry indicates periodic outbound connections at roughly four-hour intervals. The destination's ownership, purpose, and trustworthiness have not been determined.
4. **Investigation status:** There is no confirmed root cause, evidence of data exfiltration, verified appointment manipulation, or established scope of compromise available to participants at the start.

## Decisions requiring discussion

The exercise begins with unresolved questions, not predetermined answers:

- **Trust versus continuity:** Should MedDefense isolate `SCHED-SVR-01` or restrict Nexus connectivity immediately, potentially interrupting patient scheduling, or continue operations while gathering evidence? Who can authorize that decision and what safeguards protect patients?
- **Vendor trust versus independent verification:** Does the fact that Nexus updates are digitally signed justify continuing to trust the update channel, or should the organization independently validate recent changes before allowing further updates?
- **Legal urgency versus incomplete evidence:** When should Legal and the Privacy team begin assessing HIPAA and BAA obligations, and what information must be obtained from Nexus before determining whether notification is required?

Participants should explain their decisions, identify who has authority to act, specify what evidence they need, and describe how they will protect patients while facts remain uncertain. Further developments will be introduced by the facilitator during the exercise.

---

*End of participant briefing. Additional scenario developments and facilitator-only information are intentionally excluded.*
