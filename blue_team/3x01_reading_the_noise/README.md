# 3x01 — Reading the Noise

This project builds reproducible behavioral baselines and detects deviations in
the MedDefense evidence handoff. It runs locally on Ubuntu 22.04 LTS and does
not query a SIEM, API, or network service.

## Requirements

- Ubuntu 22.04 LTS
- Bash
- `jq`
- `shellcheck` (for validation)
- A completed 3x00 `evidence_handoff/`

Load the lab environment before running the scripts:

```bash
source ~/m3_env.sh
printf 'HANDOFF_DIR=%s\nBASELINE_PKG=%s\n' "$HANDOFF_DIR" "$BASELINE_PKG"
```

If `HANDOFF_DIR` is unset, scripts use
`~/3x00_handoff/evidence_handoff`. No script contains a hardcoded student home
directory.

## Task progress

| Task | Artifact | Status |
| --- | --- | --- |
| 2 — Reusable Query Toolkit | `2-query_toolkit.sh` | Complete |

## Task 2 — Reusable Query Toolkit

`2-query_toolkit.sh` is a small command-line analytics layer over
`$HANDOFF_DIR/data/enriched_events.json`. It accepts either a JSON array or
newline-delimited JSON and keeps all analysis local.

Make it executable and validate it:

```bash
chmod +x 2-query_toolkit.sh
shellcheck 2-query_toolkit.sh
./2-query_toolkit.sh help
```

Examples:

```bash
# Number of authentication events for DC01
./2-query_toolkit.sh count --host DC01 --category authentication

# Authentication events in a half-open time range: from inclusive, to exclusive
./2-query_toolkit.sh filter \
  --source windows \
  --from 2026-08-01T00:00:00Z \
  --to 2026-08-02T00:00:00Z

# Ten most common process names; dotted paths address nested fields
./2-query_toolkit.sh top --field process.name --limit 10

# Unique destination IP addresses for one host
./2-query_toolkit.sh distinct --field destination.ip --host billing-srv-01

# Hourly event volume based on the timestamp field
./2-query_toolkit.sh window --field timestamp --bucket hour
```

The `top` output is tab-separated as `value<TAB>count`. The `window` output is
tab-separated as `bucket<TAB>count`. `filter` emits compact NDJSON, `distinct`
emits one sorted value per line, and `count` emits one integer.

Filters can be combined in any order. `--from` is inclusive and `--to` is
exclusive, which prevents double-counting when adjacent windows are queried.
The toolkit recognizes common enriched-event aliases for source, host,
category, and timestamp; `--field` also supports dotted JSON paths.

### SOC use

In a SOC, this toolkit provides the common query layer used by later baseline
and anomaly scripts. An analyst can quickly establish normal values—for
example, usual processes, destination IPs, and hourly authentication volume—and
then apply exactly the same filters to an evaluation window. Centralizing this
logic prevents different detection scripts from interpreting the same evidence
in inconsistent ways and makes results reproducible during incident review.

## Reproducibility rules

- Inputs are read-only.
- Results are deterministically sorted where ordering matters.
- Repeating a command with unchanged input produces identical output.
- All generated project files end with a newline.

