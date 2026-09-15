# MedDefense Tool-Agnostic Investigation Playbook v1

## Purpose

Provide a repeatable Tier 1 investigation workflow independent of SIEM vendor or interface. Produce evidence-backed findings that Tier 2 can verify without repeating the investigation.

## Scope

Use this playbook for authentication anomalies, suspicious processes, lateral movement, network egress, and alerts requiring asset, IOC, or baseline context. It covers validation, scoping, correlation, ATT&CK mapping, and findings. It excludes malware reverse engineering, containment execution, legal conclusions, and threat-actor attribution.

## Inputs

The analyst must have access to this locked set:

- Enriched events with timestamps and event references.
- Asset inventory with role, owner, criticality, and data classification.
- Behavioral and temporal baseline package.
- Detection catalog, including rule logic and ATT&CK mappings.
- Triage package containing related alerts, tickets, and prior decisions.
- IOC context with indicator value, type, source, confidence, and expiry.

## Workflow Steps

| # | Objective | CLI action | Export/dashboard action |
|---:|---|---|---|
| 1 | Record the starting point | Read the alert or manifest; save start time, entities, rule, and window. | Open the alert or export; record index, query, time filter, and result count. |
| 2 | Translate fields | Map alert fields to the normalized schema before querying. | Use the field mapping to locate equivalent indexed fields. |
| 3 | Scope evidence | Filter enriched events by time and primary entities with `jq`; count results. | Set the index and UTC window; apply entity filters; record hits. |
| 4 | Build a timeline | Sort records by timestamp; retain references and key fields. | Sort by `@timestamp`; expand relevant documents; retain `_id` values. |
| 5 | Correlate activity | Pivot on host, user, source, destination, process, and adjacent event IDs. | Add filters or queries for the same pivots; inspect related documents. |
| 6 | Add context | Join asset, baseline, detection, triage, and IOC artifacts; note missing context. | Inspect indexed labels first; record each external inventory or IOC fallback. |
| 7 | Decide | Test the hypothesis against contrary evidence; assign ATT&CK and confidence. | Review the timeline; separate observed facts from inference. |
| 8 | Document and exit | Write and validate the locked JSON finding; record time and actions. | Include click path, fields, document IDs, fallbacks, time, and finding. |

## Field Name Translation Table

| Normalized field | Wazuh field |
|---|---|
| `timestamp` | `@timestamp` |
| `hostname` | `agent.name` |
| `src_ip` | `source.ip` |
| `src_port` | `source.port` |
| `dst_ip` | `destination.ip` |
| `dst_port` | `destination.port` |
| `user` | `user.name` |
| `event_id` | `winlog.event_id` |
| `event_ref` | `_id` |
| `raw_message` | `full_log` |

## Query Decomposition Rule

Decompose every query into **filter**, **aggregation**, and **time window**. The filter selects entities or events; aggregation counts, groups, or orders them; the window limits when evidence qualifies.

| Language | Filter | Aggregation | Time window |
|---|---|---|---|
| `jq` | `select(.hostname == $host)` | Array, `group_by`, `length`, or `sort_by` | Compare ISO timestamps inside `select` |
| Sigma | `detection.selection` and `condition` | Use correlation or downstream backend capability | `timeframe` for correlated detections |
| KQL | `agent.name:"host" AND winlog.event_id:10` | Use dashboard visualization or result count | Dashboard UTC time picker |
| Lucene | `agent.name:"host" AND winlog.event_id:10` | Use dashboard visualization or result count | Dashboard UTC time picker or timestamp range |

Preserve all three components when translating. Confirm field types before assuming comparisons are equivalent.

## Finding Schema

- `finding_id`: deterministic `scenario_id_interface` value.
- `scenario_id`: `anchor`, `scenario_a`, `scenario_b`, or `scenario_c`.
- `interface`: `cli` or `wazuh_export`.
- `investigation_start`, `investigation_end`, `created_at`: ISO 8601 UTC.
- `time_to_first_answer_seconds`: non-negative integer.
- `actions`: ordered list, maximum 20 entries.
- `fields_touched`: inspected field-name list.
- `event_refs`: source event-reference list.
- `attack_techniques`: ATT&CK technique-ID list.
- `hypothesis`: maximum two sentences.
- `confidence`: `low`, `medium`, or `high`.

## Exit Criteria

An investigation is complete when the UTC scope, entities, and ordered timeline are recorded; required context is checked or marked unavailable; event references are preserved; ambiguity is documented; ATT&CK and confidence are justified; and the valid finding records actions and time. Escalate privileged access, PHI exposure, medical-device risk, successful compromise, or unresolved high-risk ambiguity beyond Tier 1 authority.

## Known Pitfalls

- NDJSON must be processed per object; treating `enriched_events.json` as one JSON array breaks filters.
- SSH source addresses may exist only in `raw_message`, so `src_ip` alone can miss events.
- Wazuh field names differ from normalized names; using `hostname` instead of `agent.name` can return zero hits.
- `agent.labels` may omit `data_classification`, requiring an explicit asset-inventory fallback.
- Mixing firewall flows and IDS alerts can create false beacon intervals.
- Event ID 3 can describe unrelated traffic, so process, destination, port, and timestamp must be correlated together.
- Dashboard traces can disagree with documents; trust event records and note discrepancies.
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




Ask me anything...




Powered by AITOPIA 
Chat
Ask
Search
Write
Image
ChatFile
Vision
Store
Full Page
