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
