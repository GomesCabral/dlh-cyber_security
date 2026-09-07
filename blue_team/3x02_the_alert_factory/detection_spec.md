# MedDefense Detection Engineering Specification

## Purpose

This specification defines the inputs, authoring rules, execution, measurement, ranking, and outputs of the MedDefense detection layer. It is the operating contract for engineers who maintain the vendor-neutral Sigma catalog and the alerts supplied to 3x03.

## Inputs

- `$HANDOFF_DIR`, default `~/3x00_handoff/evidence_handoff/`: `data/normalized_events.json`, `context/asset_inventory.json`, and `schema/event_schema.json`.
- `$BASELINE_PKG`, default `~/3x01_package/baseline_package/`: baseline summaries, process baselines, anomaly results, and labeled ground truth.
- `$ASSETS_DIR`, default `~/3x02_assets/`: `risk_register.json` and `attack_taxonomy.json`.
- `$CATALOG_DIR`, normally `~/3x02_package/detection_catalog/`: packaged rules, metrics, specification, and triage outputs.
- Project-local dependencies: `rules/sigma/`, `fp_baseline.json`, `rule_quality.json`, `attack_coverage.json`, and `rule_prioritization.json`.

Inputs are read-only evidence or configuration. Scripts must resolve dependencies through these environment variables and must not query a SIEM, API, or network service.

## Rule Authoring Standard

Rules are YAML and must declare `title`, UUIDv4 `id`, `status`, `description`, `logsource`, `detection`, `condition`, `falsepositives`, `level`, and `tags`. Detection logic must be a precise predicate over normalized fields; free-text matching is permitted only when no stable structured field exists.

Files use `NNN_short_name.yml`, with an incrementing three-digit identifier. Levels are `informational`, `low`, `medium`, `high`, or `critical`. Every rule requires at least one `attack.tXXXX` technique tag; tactic tags provide context but do not replace technique mapping. Tuned variants retain the rule identity and supersede originals during execution.

## Execution Model

`3-sigma_runner.sh` parses Sigma YAML and evaluates it against flat JSON or NDJSON evidence. It supports validation, count-only output, explicit time windows, Boolean selections, and grouped count/timeframe aggregation.

The runner may compute documented primitives such as `hour_of_day` and `baseline_seen` before evaluating a rule. Cross-source detections may preprocess records into correlation primitives when raw Sigma cannot express joins or state reliably. Dataset timestamps determine the first seven-day clean baseline and eighth-day evaluation windows; boundaries are never hardcoded. Window start is inclusive and window end is treated consistently by all scripts.

## Quality Thresholds

Every shipped rule must contain measured `tp_count`, `fp_count`, `precision`, `recall`, and `f1`. The catalog gate is precision at least `0.70`, recall at least `0.50`, F1 at least `0.70`, and no more than `10` false positives in the seven-day clean baseline. A rule that fails any gate is tuned, explicitly accepted with documented risk, or excluded; missing measurements always reject the rule.

## Tuning Protocol

First reproduce baseline false positives and inspect their fields, users, hosts, schedules, and asset roles. Add the narrowest justified structured condition or allow-list, document the associated legitimate scenario, and preserve the original threat behavior. Re-run the tuned rule against both windows, compare TP, FP, precision, recall, and F1 with the original, and ship only when noise decreases without unacceptable recall loss. Tuned rules require reviewer approval and regression evidence.

## Risk Ranking Model

For each rule, `risk_score` is the sum of `likelihood Ã— impact` for risk-register scenarios whose ATT&CK techniques intersect the rule's technique tags. `priority_score = risk_score Ã— f1`; when F1 is zero, the multiplier floor is `0.1` so unmeasured coverage remains visible. Rules with no intersecting risk scenario are reported as `ORPHAN` and receive zero priority.

## Outputs

`alert_queue.json` is an ordered JSON array. Each alert contains deterministic `alert_id`, `generated_at`, rule identity and level, `priority_score`, `event_ref`, flattened `event_summary`, `asset_context`, ATT&CK techniques, `status: new`, and `evidence_hash`. Alerts are deduplicated within 60 seconds on `(rule_id, hostname, user)` and sorted by descending priority, then ascending event time. `alert_queue_schema.json` locks the field-level contract consumed by 3x03; incompatible schema changes require coordination and versioning before release.

## Failure Modes

- Missing or unreadable dependency: the script exits before evaluation and names the path.
- Malformed YAML or absent required field: dry-run reports a parsing or validation error.
- JSON array/NDJSON mismatch: parsing fails, produces zero events, or exhausts memory if a large stream is loaded whole.
- Inconsistent `event_ref`: runner matches cannot be found in normalized evidence, preventing evidence hashing and alert creation.
- Incorrect window boundaries: known malicious events appear as baseline false positives or evaluation TP counts remain zero.
- Missing ATT&CK/risk mapping: a useful rule appears in the `ORPHAN` section with zero priority.

## Reviewer Checklist

- Validate YAML, UUIDv4, filename, required fields, level, and ATT&CK technique tags.
- Confirm `logsource`, field names, types, Boolean logic, grouping key, threshold, and timeframe against the schema.
- Verify documented computed fields and preprocessing behavior.
- Run baseline and evaluation tests; review TP, FP, FN, precision, recall, F1, and event references.
- Confirm realistic false positives, tuning regression results, risk scenarios, and priority score.
- Validate deterministic output, deduplication, evidence hashes, asset enrichment, and queue schema before merge.

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

