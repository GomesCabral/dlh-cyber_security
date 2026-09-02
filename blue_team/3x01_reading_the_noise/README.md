# 3x01 — Reading the Noise

This project builds reproducible behavioral baselines and detects deviations in
the MedDefense evidence handoff. It runs locally on Ubuntu 22.04 LTS and does
not query a SIEM, API, or network service.

## Requirements

- Ubuntu 22.04 LTS
- Bash
- `jq`
- `shellcheck`
- A completed 3x00 `evidence_handoff/`

## Lab paths

Project scripts:

```text
/home/student/bt/3x01
```

Input and output paths after loading the lab environment:

```text
HANDOFF_DIR=/home/student/3x00_handoff/evidence_handoff
BASELINE_PKG=/home/student/3x01_package/baseline_package
```

Load and verify the environment:

```bash
cd ~/bt/3x01
source ~/m3_env.sh
printf 'HANDOFF_DIR=%s\nBASELINE_PKG=%s\n' "$HANDOFF_DIR" "$BASELINE_PKG"
```

If `HANDOFF_DIR` is unset, scripts use
`~/3x00_handoff/evidence_handoff`. No script contains a hardcoded student home
directory.

## Current dataset

`$HANDOFF_DIR/data/enriched_events.json` is approximately 416 MB and contains
339,893 events:

| Source type | Records |
| --- | ---: |
| Linux | 135,831 |
| Windows | 122,569 |
| Firewall | 67,420 |
| Suricata | 9,977 |
| PCAP | 4,096 |

## Task progress

| Task | Artifacts | Status |
| --- | --- | --- |
| 2 — Reusable Query Toolkit | `2-query_toolkit.sh` | Complete |
| 3 — Event Type Taxonomy | `3-event_taxonomy.sh`, `event_taxonomy.json`, `labeled_events.json` | Complete |
| 4 — Authentication Baseline | `4-baseline_auth.sh`, `baseline_auth.json` | Complete |
| 5 — Process Execution Baseline | `5-baseline_process.sh`, `baseline_process.json` | Complete |
| 9 — Cross-Source Baseline Summary | `9-baseline_summary.sh`, `baseline_summary.json` | Complete |
| 10 — Authentication Anomalies | `10-anomalies_auth.sh`, `anomalies_auth.json` | Complete |

## Task 2 — Reusable Query Toolkit

`2-query_toolkit.sh` is a CLI analytics layer over the enriched dataset. It
supports JSON arrays and NDJSON and provides `filter`, `top`, `distinct`,
`count`, `window`, and `help` subcommands.

Prepare and validate it:

```bash
cd ~/bt/3x01
source ~/m3_env.sh
chmod +x 2-query_toolkit.sh
shellcheck 2-query_toolkit.sh
bash -n 2-query_toolkit.sh
./2-query_toolkit.sh help
./2-query_toolkit.sh count
```

The unfiltered count for the current handoff should be `339893`.

Examples using the fields observed in the MedDefense handoff:

```bash
# Windows authentication events on the primary domain controller
./2-query_toolkit.sh count \
  --source windows \
  --host srv-dc-01 \
  --category authentication

# Windows events in a half-open time range
./2-query_toolkit.sh filter \
  --source windows \
  --from 2026-03-18T00:00:00Z \
  --to 2026-03-19T00:00:00Z

# Ten most common process names
./2-query_toolkit.sh top --field process_name --limit 10

# Unique destination IP addresses contacted by the EHR server
./2-query_toolkit.sh distinct --field dst_ip --host srv-ehr-01

# Hourly event volume
./2-query_toolkit.sh window --field timestamp --bucket hour
```

`filter` emits compact NDJSON, `count` emits one integer, and `distinct` emits
one sorted value per line. `top` uses `value<TAB>count`; `window` uses
`bucket<TAB>count`. Filters can be combined in any order. `--from` is inclusive
and `--to` is exclusive, preventing double-counting between adjacent windows.

The toolkit recognizes `source_type`, `hostname`, `event_category`, and
`timestamp`. A `--field` value may also be a dotted path such as
`details.LogonType`.

### SOC use

The toolkit provides a common local query layer for later baseline and anomaly
scripts. An analyst can find normal processes, network destinations,
authentication volume, and hourly activity without a SIEM. Centralizing this
logic also prevents separate detection scripts from interpreting the same
evidence differently.

## Task 3 — Event Type Taxonomy

`3-event_taxonomy.sh` maps source-specific events to consistent analytical
labels. It writes 47 deterministic rules to `event_taxonomy.json` and adds a
`canonical_label` field to every event in `labeled_events.json`.

Run it:

```bash
cd ~/bt/3x01
source ~/m3_env.sh
chmod +x 3-event_taxonomy.sh
shellcheck 3-event_taxonomy.sh
bash -n 3-event_taxonomy.sh
./3-event_taxonomy.sh
```

Expected summary format:

```text
taxonomy rules         : 47
records labeled        : <N>
records unlabeled      : <N>
canonical label distribution (top 10):
  <label>                    <N>
event_taxonomy.json written
labeled_events.json written
```

Validate the results:

```bash
jq empty event_taxonomy.json && echo "event_taxonomy.json valid"
jq -c . labeled_events.json >/dev/null && echo "labeled_events.json valid"
wc -l labeled_events.json
```

Because the output is NDJSON with one record per input event, the current
handoff should produce `339893 labeled_events.json`.

Inspect the complete distribution:

```bash
jq -r '.canonical_label' labeled_events.json |
sort |
uniq -c |
sort -nr
```

The first matching rule wins. Specific outcomes such as account lockouts and
blocked network traffic are evaluated before broader rules. When the available
fields do not justify a label, the event receives `unlabeled` instead of being
classified by guesswork.

| Source-specific evidence | Canonical label |
| --- | --- |
| Windows Event ID 4624 | `login_success` |
| Windows Event ID 4625 | `login_failure` |
| Windows Event ID 4634 or 4647 | `logout` |
| Windows Event ID 4740 | `account_lockout` |
| Windows Event ID 4672 | `privilege_escalation` |
| Windows Event ID 4688 | `process_start` |
| Windows Event ID 4689 | `process_stop` |
| Firewall action `BLOCK` | `network_blocked` |
| Suricata network alert | `network_alert` |

### SOC use

A SOC may receive equivalent behavior from Windows Event Logs, Linux audit
events, firewall logs, Suricata, and PCAP-derived flows. The taxonomy converts
these source-specific representations into shared labels such as
`login_failure` and `network_blocked`. Downstream baseline and anomaly scripts
can therefore correlate behavior across sources while `event_taxonomy.json`
provides an auditable explanation of every classification.

## Task 4 — Authentication Baseline

`4-baseline_auth.sh` reads `labeled_events.json`, derives the dataset start at
runtime, and analyzes the first seven days as the clean baseline. Set
`BASELINE_DAYS` to a positive integer to use a shorter test window.

Run and validate it:

```bash
cd ~/bt/3x01
source ~/m3_env.sh
chmod +x 4-baseline_auth.sh
shellcheck 4-baseline_auth.sh
bash -n 4-baseline_auth.sh
./4-baseline_auth.sh
jq empty baseline_auth.json
```

Test an override without editing the script:

```bash
BASELINE_DAYS=2 ./4-baseline_auth.sh
```

The output contains the half-open baseline window `[start, end)`, five
authentication-related counts per host, per-user success/failure totals, known
accounts, business-hours and off-hours hourly averages, and the largest rolling
60-minute failure burst associated with one source IP.

Business hours are 06:00–17:59 UTC and off-hours are 18:00–05:59 UTC. Each
average divides the applicable event count by 12 hours per baseline day. The
failure burst uses a rolling interval, so a burst crossing a clock-hour boundary
is still counted correctly.

### SOC use

This baseline records who normally authenticates to each host, which accounts
are known, when authentication normally occurs, and the largest normal failure
burst. Task 10 can compare day 8 with these values to detect new accounts,
unusual hosts, off-hours access, abnormal failure rates, password spraying, or
brute-force activity. The baseline provides evidence for a threshold rather
than relying on an arbitrary number embedded in a detection script.

## Reproducibility and resource use

- Input evidence is read-only.
- Outputs are replaced atomically rather than appended.
- Repeating a script with unchanged input produces identical output.
- Ordering is deterministic where it affects output.
- Aggregations stream through `jq`, `sort`, `uniq`, and `awk`; they do not use
  `jq -s` against the 416 MB dataset.
- Every project file ends with a newline.

## Task 5 — Process Execution Baseline

`5-baseline_process.sh` creates the authoritative list of processes observed on
each host during the clean baseline window. It uses the same runtime-derived
`[start, end)` window as Task 4 and supports the `BASELINE_DAYS` override.

Run and validate it:

```bash
cd ~/bt/3x01
source ~/m3_env.sh
chmod +x 5-baseline_process.sh
shellcheck 5-baseline_process.sh
bash -n 5-baseline_process.sh
./5-baseline_process.sh
jq empty baseline_process.json
```

Inspect the main results:

```bash
jq '{
  window,
  hosts: (.per_host | length),
  global_top: .global_top[:10],
  rare_processes: (.rare_processes | length),
  parent_child_pairs: ([.parent_child_pairs[] | length] | add // 0)
}' baseline_process.json
```

For each host, the output records the process name, execution count, first and
last timestamps, and distinct users. `global_top` contains at most 50 entries.
A process is rare when it appears on only one host or has fewer than five total
executions in the baseline. Parent-child relationships use process names when
available and a `pid:<number>` fallback when the source only recorded the
parent PID.

### SOC use

The per-host scope is essential: a process such as `python3` can be expected on
an analyst workstation but suspicious on a clinical server. Later anomaly
tasks can compare day 8 to this baseline to identify first-seen processes,
unusual execution frequency, unexpected users, or new parent-child chains such
as a web server spawning a shell. Rare baseline processes remain visible for
review instead of being incorrectly treated as common activity.

## Task 9 — Cross-Source Baseline Summary

`9-baseline_summary.sh` combines `baseline_auth.json`,
`baseline_process.json`, `baseline_network.json`, `baseline_file.json`, and
`temporal_profile.json` into the single `baseline_summary.json` contract used by
the anomaly detection block.

Tasks 4–8 must have completed successfully before running Task 9. The script
validates that all five documents contain the same baseline window and stops
with a non-zero exit status if any input is missing, invalid, or inconsistent.

Run and validate it:

```bash
cd ~/bt/3x01
source ~/m3_env.sh
chmod +x 9-baseline_summary.sh
shellcheck 9-baseline_summary.sh
bash -n 9-baseline_summary.sh
./9-baseline_summary.sh
jq empty baseline_summary.json
```

Inspect the contract without printing all nested baselines:

```bash
jq '{
  version,
  generated_at,
  baseline_window,
  evaluation_window,
  hosts: (.host_inventory | length),
  sections: (keys),
  thresholds
}' baseline_summary.json
```

`host_inventory` is the sorted union of hosts present in the five baseline
documents. The evaluation window begins exactly where the baseline ends and is
24 hours long. `generated_at` is set deterministically to the evaluation-window
end so repeated execution against unchanged inputs produces byte-identical
output.

Each threshold has a numeric `value` and a short `comment`. The one-hour failure
threshold is calculated from the maximum observed baseline burst; process and
port penalties are centralized scoring weights. Downstream scripts must read
these values from `baseline_summary.json` rather than embedding their own
copies.

### SOC use

This file is the Tier 1 analyst's single reference contract. An anomaly detector
can load one document to decide whether an account, process, destination, file
access pattern, or time profile is expected. Window validation prevents a
dangerous comparison in which baselines built from different date ranges are
silently combined.

## Task 10 — Authentication Anomalies

`10-anomalies_auth.sh` scans only the evaluation window defined in
`baseline_summary.json`. It detects unknown accounts, rolling one-hour failure
bursts, off-hours logins by business-hours-only users, and privilege escalation
surges on hosts whose baseline count was zero.

Task 10 requires the updated Task 4 per-user time counters and the updated Task
9 privilege surge threshold. Regenerate the dependency chain before running it:

```bash
cd ~/bt/3x01
source ~/m3_env.sh
unset BASELINE_DAYS
./4-baseline_auth.sh
./9-baseline_summary.sh
chmod +x 10-anomalies_auth.sh
shellcheck 10-anomalies_auth.sh
bash -n 10-anomalies_auth.sh
./10-anomalies_auth.sh
jq empty anomalies_auth.json
```

Inspect the counts and highest-severity results:

```bash
jq 'group_by(.anomaly_type) | map({
  anomaly_type: .[0].anomaly_type,
  count: length
})' anomalies_auth.json

jq '[.[] | select(.severity == "high")]' anomalies_auth.json
```

Failure detection uses the baseline maximum multiplied by
`thresholds.failure_rate_multiplier` and a rolling interval, not a fixed clock
bucket. A privilege surge is emitted once per affected host, and a failure
burst once per source IP at its largest observed window. Event references use a
source ID when available and a stable source/event/line reference otherwise.

### SOC use

These findings are investigation leads rather than automatic proof of
compromise. Tier 1 should first review high-severity unknown accounts, failure
bursts, and privilege surges, then confirm whether off-hours access has an
approved operational explanation. Every finding records the observed value and
the baseline value that caused it, making the alert explainable and repeatable.

