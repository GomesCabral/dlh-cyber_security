# Cross-Platform Detection and SIEM Evaluation

## Project Overview

This project evaluates the same security investigations through two different
interfaces:

1. A command-line investigation pipeline built with `jq`, `sigma-cli`, and the
   evidence packages produced in projects 3x00 through 3x03.
2. Pre-exported Wazuh evidence containing search results, dashboard workflow
   traces, and field mappings generated from the same source dataset.

The objective is to demonstrate that the investigation process is independent
of a specific SIEM product. The evidence, scenarios, and MITRE ATT&CK
techniques remain the same; only the interaction model changes

## Learning Objectives

By completing this project, the analyst will be able to:

- Investigate the same incident through CLI and Wazuh export workflows.
- Compare investigation speed, actions, and fields across interfaces.
- Translate Sigma detections into native Wazuh XML rules.
- Compare `jq`, Sigma, KQL, and Lucene query approaches.
- Produce structured findings using a locked JSON schema.
- Build a tool-agnostic incident investigation playbook.
- Produce an evidence-based SIEM vendor evaluation brief.

## Environment

- Operating system: Ubuntu 22.04 LTS
- User: `student`
- Base directory: `/home/student`
- Project directory: `/home/student/bt/3x04_cross_platform_detection`

### Required tools

| Tool | Minimum/required version | Lab version |
|---|---:|---:|
| `jq` | 1.6+ | 1.6 |
| `yq` | Mike Farah release | 4.44.1 |
| `python3` | 3.10+ | 3.10.12 |
| `sigma-cli` | Required | 3.0.2 (`sigma` executable) |
| `xmllint` | Required | 20913 |
| `curl` | Required | 7.81.0 |

The installed Sigma CLI package exposes the command `sigma` instead of
`sigma-cli`. The verification script supports either executable while reporting
the tool as `sigma-cli`.

## Environment Variables

| Variable | Default path |
|---|---|
| `HANDOFF_DIR` | `~/3x00_handoff/evidence_handoff` |
| `BASELINE_PKG` | `~/3x01_package/baseline_package` |
| `CATALOG_DIR` | `~/3x02_package/detection_catalog` |
| `TRIAGE_PKG` | `~/3x03_package/triage_package` |
| `ASSETS_DIR` | `~/3x04_assets` |
| `WAZUH_EXPORTS` | `~/3x04_assets/wazuh_exports` |

Load the lab environment before running project scripts:

```bash
source ~/m3_env.sh
```

## Upstream Dependencies

The project consumes artifacts created by the previous Blue Team projects:

- 3x00: normalized and enriched security events.
- 3x01: behavioral and temporal baselines.
- 3x02: Sigma detection catalog.
- 3x03: triage findings and escalation package.
- 3x04 assets: scenarios and pre-exported Wazuh evidence.

The required enriched event dataset is available through:

```text
/home/student/3x00_handoff/evidence_handoff/data/enriched_events.json
```

In the current lab, this path is a symbolic link to:

```text
/home/student/enriched_events.json
```

The dataset uses NDJSON format: each line contains one complete JSON event.

## Project Structure

```text
3x04_cross_platform_detection/
├── 0-tool_check.sh
└── README.md
```

This structure will be expanded as each task is completed.

## Task Progress

| Task | Description | Status |
|---:|---|---|
| 0 | CLI Toolkit Verification | In progress — final anchor check pending |
| 1+ | Remaining cross-platform investigation tasks | Not started |

## Task 0: CLI Toolkit Verification

### Goal

Verify every CLI tool, environment variable, upstream package, Wazuh export,
and anchor event required by the project before beginning the timed
investigations.

### File

```text
0-tool_check.sh
```

### Checks performed

The script:

1. Confirms that `jq`, `yq`, `python3`, Sigma CLI, `xmllint`, and `curl` are
   available on `PATH` and prints their versions.
2. Confirms that all five upstream package directories exist.
3. Confirms that `enriched_events.json` exists and is not empty.
4. Counts the YAML rules in the Sigma detection catalog.
5. Confirms that the required Wazuh field mapping, index metadata, four search
   result files, and four dashboard trace files exist and contain valid JSON.
6. Extracts the anchor target and time window from `anchor_event.json`.
7. Confirms that an enriched event matches the anchor target host or target IP
   within the required UTC time window.
8. Returns a non-zero exit status if any check fails.

### Anchor scenario

| Field | Value |
|---|---|
| Anchor ID | `ANCHOR-001` |
| Rule | `001_ssh_brute_force` |
| Target host | `db-patient-01` |
| Target IP | `10.1.2.10` |
| Target port | `22` |
| Window start | `2026-03-25T01:15:00Z` |
| Window end | `2026-03-25T01:47:00Z` |
| Scenario | SSH brute-force cluster followed by a successful root login |

The verification supports both host-oriented authentication records and
network-oriented firewall records. An event matches when its timestamp is
inside the anchor window and its host or destination IP corresponds to the
anchor target.

### Usage

```bash
cd ~/bt/3x04_cross_platform_detection
source ~/m3_env.sh
chmod +x 0-tool_check.sh
./0-tool_check.sh
```

Validate the script syntax before execution:

```bash
bash -n 0-tool_check.sh
```

If ShellCheck is installed:

```bash
shellcheck 0-tool_check.sh
```

Check the exit status:

```bash
echo $?
```

An exit status of `0` means every required check passed. Any other value means
that one or more required tools, directories, files, or anchor events could not
be validated.

### Verified result

The current environment contains:

- All six required command-line tools.
- All five upstream directories.
- A non-empty enriched event handoff.
- Four available Sigma rules.
- The Wazuh field mapping and index metadata.
- Four Wazuh search result exports.
- Four Wazuh dashboard workflow traces.
- Events for `db-patient-01` inside the anchor investigation window.

## Troubleshooting Notes

### Sigma executable name

The `sigma-cli` Python package is installed, but its command is:

```bash
sigma version
```

The verification script checks for `sigma-cli` first and falls back to
`sigma`.

### Missing enriched event handoff

If the handoff directory exists but the dataset is stored directly under the
student home directory, restore the expected path without duplicating the
large file:

```bash
mkdir -p ~/3x00_handoff/evidence_handoff/data
ln -sfn ~/enriched_events.json \
  ~/3x00_handoff/evidence_handoff/data/enriched_events.json
```

### Empty Sigma catalog

The script expects Sigma rules under:

```text
$CATALOG_DIR/rules/sigma/
```

If the package directory is empty, restore the YAML rules generated during
project 3x02 before running the verification again.

## Finding Schema

Every structured finding produced later in the project must contain:

- `finding_id`
- `scenario_id`
- `interface`
- `investigation_start`
- `investigation_end`
- `time_to_first_answer_seconds`
- `actions`
- `fields_touched`
- `event_refs`
- `attack_techniques`
- `hypothesis`
- `confidence`
- `created_at`

The allowed interfaces are `cli` and `wazuh_export`. The allowed scenario IDs
are `anchor`, `scenario_a`, `scenario_b`, and `scenario_c`.

## Final Deliverables

The completed project will contain:

1. Six structured findings covering three scenarios and two interfaces.
2. Three Sigma rules translated into valid native Wazuh XML.
3. A comparison table covering `jq`, Sigma, KQL, and Lucene.
4. A tool-agnostic investigation playbook.
5. A bounded SIEM vendor evaluation brief.
6. A complete `tool_evaluation/` package and manifest.

## Author

Pedro Cabral

Cybersecurity Academy — Defensive Security / SOC Track
