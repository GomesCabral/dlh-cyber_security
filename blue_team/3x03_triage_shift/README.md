# MedDefense 3x03 — Triage Shift

This project simulates a SOC Tier 1 shift using the alert queue produced by the
3x02 detection catalog. All triage is performed locally against JSON evidence;
no SIEM, API, or network service is queried.

## Objectives

- Assess and prioritize an alert queue before opening individual tickets.
- Separate true positives, false positives, and benign activity using evidence.
- Enrich alerts with asset, baseline, network-zone, and IOC context.
- Produce structured tickets, escalation records, tuning feedback, and a
  reproducible `triage_package/` for Tier 2 and compliance.

## Environment

```bash
source ~/m3_env.sh
export ASSETS_DIR="$HOME/3x03_assets"
```

Required variables and defaults:

| Variable | Default dependency |
|---|---|
| `CATALOG_DIR` | `~/3x02_package/detection_catalog` |
| `HANDOFF_DIR` | `~/3x00_handoff/evidence_handoff` |
| `BASELINE_PKG` | `~/3x01_package/baseline_package` |
| `ASSETS_DIR` | Must be set to `~/3x03_assets` |
| `TRIAGE_PKG` | `~/3x03_package/triage_package` |

`m3_env.sh` assigns a different default to `ASSETS_DIR`, so it must be
overridden for every new 3x03 shell session.

## Project status

| Task | Deliverable | Status |
|---:|---|---|
| 0 | `0-queue_assessment.sh`, `queue_assessment.json` | Script implemented; lab output pending |
| 1–11 | Pending task instructions | Not started |

## Task 0 — Queue assessment

`0-queue_assessment.sh` validates each alert against the locked queue schema and
creates the analyst's initial shift briefing. It summarizes priority bands,
rules, hosts, ATT&CK tactics, queue time span, and the three targets with the
highest cumulative priority.

Run it from the project root:

```bash
source ~/m3_env.sh
export ASSETS_DIR="$HOME/3x03_assets"
./0-queue_assessment.sh
```

Validate the generated artifact:

```bash
python3 -m json.tool queue_assessment.json >/dev/null
jq '{queue_size, validation_errors, by_priority_band, top_targets}' \
  queue_assessment.json
```

The script is idempotent: the same queue and schema produce the same JSON. It
writes through a temporary file and replaces the previous assessment only after
processing succeeds.

## SOC essentials

A Tier 1 analyst should assess the whole queue before investigating the first
alert. Priority score indicates what should be reviewed first; alert count shows
workload; cumulative host score reveals concentrated risk; schema validation
prevents broken alerts from entering the triage workflow.

Priority bands used by Task 0:

| Band | Priority score |
|---|---:|
| Critical | `>= 20` |
| High | `10–19.999...` |
| Medium | `5–9.999...` |
| Low | `1–4.999...` |

An alert with a high score is not automatically a confirmed incident. It is a
decision about investigation order; classification still requires evidence and
context.


