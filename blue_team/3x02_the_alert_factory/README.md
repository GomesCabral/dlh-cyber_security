# 3x02 — The Alert Factory

## Project purpose

This project builds a vendor-neutral detection catalog for MedDefense Health
Systems. Rules will be written in Sigma, evaluated against the normalized 3x00
evidence, measured using the 3x01 labeled evidence and prioritized using the
organization's risk register.

The project follows the detection engineering cycle:

1. Define the behavior to detect.
2. Express it as precise conditions against known event fields.
3. Test it against labeled evidence.
4. Measure true positives and false positives.
5. Tune it without removing the targeted malicious behavior.
6. Ship only rules that meet the quality threshold.

## Environment

```bash
source ~/m3_env.sh
export ASSETS_DIR="$HOME/3x02_assets"
cd ~/bt/blue_team/3x02_the_alert_factory
```

Expected dependencies:

```text
$HANDOFF_DIR/data/enriched_events.json
$HANDOFF_DIR/schema/event_schema.json
$BASELINE_PKG/baselines/baseline_summary.json
$ASSETS_DIR/risk_register.json
$ASSETS_DIR/attack_taxonomy.json
```

## Task 0 — Detection Type Analysis

### SOC objective

Task 0 determines which detection approaches each data source can support
before rules are written. This prevents choosing a rule type that the available
telemetry or historical baseline cannot support.

### Four detection types

| Type | Core question | Example |
|---|---|---|
| Signature | Does this event match a known indicator or exact pattern? | A Suricata SID associated with known malware |
| Anomaly | Is this event statistically different from the baseline? | A login at a time when the account is normally inactive |
| Behavioral | Does this activity resemble attacker behavior? | PowerShell launching an encoded command |
| Correlation | Do related events become suspicious when combined? | Repeated failures followed by a successful login |

Memory aid: **signature knows an indicator; anomaly knows normal; behavioral
knows a suspicious action; correlation knows the relationship between events.**

### Script

`0-detection_matrix.sh` reads:

- `enriched_events.json` for actual records and fields;
- `event_schema.json` to validate the documented event structure;
- `baseline_summary.json` to confirm the availability of historical behavior.

For each `source_type`, it calculates:

- `record_count`: number of records from the source;
- `stable_fields`: fields present and non-null in at least 95% of its records;
- `high_cardinality_fields`: fields whose distinct-value count is greater than
  half of the source's record count;
- supported detection types, their machine-readable rationale and reasonable
  MITRE ATT&CK tactics.

High-cardinality fields such as an event UUID are generally useful for
identification but poor for grouping. Stable fields are strong candidates for
rule predicates because the detection will not silently fail on most records.

### Run

```bash
chmod +x 0-detection_matrix.sh
./0-detection_matrix.sh
```

The defaults are used when the variables are absent:

```text
HANDOFF_DIR=~/3x00_handoff/evidence_handoff
BASELINE_PKG=~/3x01_package/baseline_package
```

### Validate

```bash
shellcheck 0-detection_matrix.sh
bash -n 0-detection_matrix.sh
python3 -m json.tool detection_matrix.json >/dev/null
jq '.[] | {source_type, supported_detection_types}' \
  detection_matrix.json
```

Idempotence check:

```bash
sha256sum detection_matrix.json
./0-detection_matrix.sh >/dev/null
sha256sum detection_matrix.json
```

Both hashes must be identical. The generated `matrix_id` is deterministic and
does not use the execution time, so repeated runs against identical evidence
produce identical output.

### SOC interpretation

- Windows and Linux endpoint data can support all four types because it exposes
  identities, processes, actions and timestamps and has historical baselines.
- Suricata alerts are primarily signature detections, but they gain context and
  confidence when correlated with endpoint or flow events.
- Firewall telemetry supports anomaly and correlation rules based on traffic
  volume, direction, zones and related host activity.
- PCAP flow metadata is appropriate for traffic anomalies and behavioral
  patterns. Without payload or IDS enrichment, it should not be treated as a
  reliable signature source.
