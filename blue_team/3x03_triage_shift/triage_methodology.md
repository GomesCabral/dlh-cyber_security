# MedDefense SOC Triage Methodology

## Classification Taxonomy

- `true_positive`: the rule correctly identified malicious activity; example: rule 001 detects repeated SSH failures from a hostile IP.
- `false_positive`: the match does not represent the intended threat; example: rule 003 flags approved maintenance because its parent process was not allow-listed.
- `benign`: the behavior occurred as detected, but verified context makes it authorized and harmless; example: rule 002 detects an approved on-call administrator after hours.
- `escalated`: available evidence indicates or reasonably suggests a threat requiring Tier 2 investigation, containment, or broader correlation; example: rule 004 detects previously unseen reconnaissance tools on a clinical workstation.

## Priority Ordering Rule

Work alerts by descending `priority_score`; break ties using the earliest `event_summary.timestamp`. Override the queue when evidence shows active compromise, patient-safety risk, access to regulated data, a malicious IOC, continuing lateral movement, or a critical asset under attack. Document every override in the ticket justification.

## Evidence Requirement

Every classification requires a valid `event_ref` and corresponding enriched event. Record relevant `timestamp`, `hostname`, `user`, `canonical_label`, and `event_category`, plus applicable `src_ip`, `dst_ip`, `process_name`, `parent_process_name`, `command_line`, `event_id`, `outcome`, network zones, and asset criticality. A `true_positive` requires a malicious indicator or unauthorized behavior. A `false_positive` requires evidence that the predicate mismatched its threat. A `benign` decision requires verified authorization or baseline-consistent activity. `escalated` requires suspicious evidence plus the question or impact Tier 2 must investigate.

## Escalation Criteria

- `(ioc.reputation == "malicious")`
- `(asset_criticality == "critical" AND behavior_is_unauthorized == true)`
- `(patient_data_access == true AND authorization_verified == false)`
- `(successful_access_after_failures == true AND source_changed == true)`
- `(lateral_movement == true OR persistence_detected == true)`
- `(multiple_related_alerts == true AND attack_progression == true)`
- `(containment_required == true OR Tier1_confidence_insufficient == true)`

## SLA

- Critical (`priority_score >= 20`): 15 minutes.
- High (`10â€“19.999`): 30 minutes.
- Medium (`5â€“9.999`): 60 minutes.
- Low (`1â€“4.999`): same shift.

SLA time starts when the alert becomes available and stops when it is classified or escalated with sufficient documentation.

## Documentation Standard

Each ticket must contain:

- [ ] Deterministic `ticket_id` and source `alert_id`.
- [ ] Valid `classification`.
- [ ] Specific `justification`; except for `benign`, name at least one decisive field and value.
- [ ] One or more `evidence_refs`.
- [ ] Relevant `ioc_hits` and copied `attack_techniques`.
- [ ] `recommended_action`: `close`, `escalate_tier2`, `monitor`, or `tune_rule`.
- [ ] `analyst_time_seconds` and ISO 8601 UTC `created_at`.

Chat

New Conversation

🤓 Explain a complex thing

Explain Artificial Intelligence so that I can explain it to my six-year-old child.


🧠 Get suggestions and create new ideas

Please give me the best 10 travel ideas around the world


💭 Translate, summarize, fix grammar and more…

Translate "I love you" French



AITOPIA
Hello, how can I help you today?




AITOPIA

10
Upgrade




# MedDefense SOC Triage Methodology

## Classification Taxonomy

- `true_positive`: the rule correctly identified malicious activity; example: rule 001 detects repeated SSH failures from a hostile IP.
- `false_positive`: the match does not represent the intended threat; example: rule 003 flags approved maintenance because its parent process was not allow-listed.
- `benign`: the behavior occurred as detected, but verified context makes it authorized and harmless; example: rule 002 detects an approved on-call administrator after hours.
- `escalated`: available evidence indicates or reasonably suggests a threat requiring Tier 2 investigation, containment, or broader correlation; example: rule 004 detects previously unseen reconnaissance tools on a clinical workstation.

## Priority Ordering Rule

Work alerts by descending `priority_score`; break ties using the earliest `event_summary.timestamp`. Override the queue when evidence shows active compromise, patient-safety risk, access to regulated data, a malicious IOC, continuing lateral movement, or a critical asset under attack. Document every override in the ticket justification.

## Evidence Requirement

Every classification requires a valid `event_ref` and corresponding enriched event. Record relevant `timestamp`, `hostname`, `user`, `canonical_label`, and `event_category`, plus applicable `src_ip`, `dst_ip`, `process_name`, `parent_process_name`, `command_line`, `event_id`, `outcome`, network zones, and asset criticality. A `true_positive` requires a malicious indicator or unauthorized behavior. A `false_positive` requires evidence that the predicate mismatched its threat. A `benign` decision requires verified authorization or baseline-consistent activity. `escalated` requires suspicious evidence plus the question or impact Tier 2 must investigate.

## Escalation Criteria

- `(ioc.reputation == "malicious")`
- `(asset_criticality == "critical" AND behavior_is_unauthorized == true)`
- `(patient_data_access == true AND authorization_verified == false)`
- `(successful_access_after_failures == true AND source_changed == true)`
- `(lateral_movement == true OR persistence_detected == true)`
- `(multiple_related_alerts == true AND attack_progression == true)`
- `(containment_required == true OR Tier1_confidence_insufficient == true)`

## SLA

- Critical (`priority_score >= 20`): 15 minutes.
- High (`10â€“19.999`): 30 minutes.
- Medium (`5â€“9.999`): 60 minutes.
- Low (`1â€“4.999`): same shift.

SLA time starts when the alert becomes available and stops when it is classified or escalated with sufficient documentation.

## Documentation Standard

Each ticket must contain:

- [ ] Deterministic `ticket_id` and source `alert_id`.
- [ ] Valid `classification`.
- [ ] Specific `justification`; except for `benign`, name at least one decisive field and value.
- [ ] One or more `evidence_refs`.
- [ ] Relevant `ioc_hits` and copied `attack_techniques`.
- [ ] `recommended_action`: `close`, `escalate_tier2`, `monitor`, or `tune_rule`.
- [ ] `analyst_time_seconds` and ISO 8601 UTC `created_at`.
