# Locking the Gates

## Project Overview

This project hardens the Linux infrastructure used by MedDefense Health
Systems. The primary systems are `billing-srv-01`, `web-srv-01` and
`log-srv-01`.

Every hardening action is automated through an idempotent Bash script.
Structured assessment and validation results are stored as JSON.

## Threat Context

The project addresses Linux security weaknesses identified during the
MedDefense assessment, including:

- Finding 009: SSH password authentication enabled
- Finding 011: Ubuntu 18.04 without Extended Security Maintenance
- Finding 026: Outdated kernel with known vulnerabilities
- Crimson Tide activity involving exposed and misconfigured services

## Tasks

### Task 0 — Baseline Snapshot

The `0-baseline_snapshot.sh` script captures the security state of the
system before hardening, including:

- System identification
- Running services
- Open ports and listening sockets
- SUID and SGID binaries
- World-writable files
- Security-relevant sysctl parameters
- Effective SSH configuration
- Active user accounts
- Sudo group membership

The structured result is written to:

```text
0-baseline_snapshot.json

```

---

### Task 1 - MedDefense CIS Control Profile

**Script**

1-cis_profile.sh

**Output**

cis_profile.json

**Purpose**

Builds a threat-driven CIS control profile for MedDefense Linux servers. The profile selects the controls that will be implemented during the remaining hardening tasks instead of blindly applying the complete CIS Benchmark.

**Coverage**

- SSH hardening
- Kernel hardening
- PAM
- Firewall
- Filesystem permissions
- Audit logging
- Log retention
- Service minimization

**Statistics**

- Total Controls: 15
- Critical: 5
- High: 7
- Medium: 3

---

### Task 2 - Lynis Audit Parser

**Script**

`2-lynis_parse.sh`

**Output**

`lynis_findings.json`

**Purpose**

Runs after a Lynis security audit and converts the Lynis key-value report into structured JSON that can be reused by automated security workflows.

**Data Extracted**

- Lynis hardening index
- Warnings
- Suggestions
- Manual checks
- Lynis test IDs
- Finding messages

**Usage**

```bash
sudo lynis audit system
./2-lynis_parse.sh /var/log/lynis-report.dat | jq '.' > lynis_findings.json

---

### Task 3 - Evidence-Based Remediation Queue

**Script**

`3-remediation_queue.sh`

**Inputs**

- `cis_profile.json`
- `lynis_findings.json`

**Outputs**

- `gap_analysis.json`
- `remediation_queue.json`

**Purpose**

Correlates the MedDefense CIS control profile with Lynis audit findings in
order to identify security gaps and create a prioritized remediation queue.

Each CIS control is assigned one of four states:

- compliant
- non_compliant
- partially_compliant
- not_assessed

Non-compliant and partially compliant controls are mapped to the hardening
script responsible for remediation and assigned a risk-based priority score.

**Usage**

```bash
./3-remediation_queue.sh

---
