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

## Reproducibility and resource use

- Input evidence is read-only.
- Outputs are replaced atomically rather than appended.
- Repeating a script with unchanged input produces identical output.
- Ordering is deterministic where it affects output.
- Aggregations stream through `jq`, `sort`, `uniq`, and `awk`; they do not use
  `jq -s` against the 416 MB dataset.
- Every project file ends with a newline.


