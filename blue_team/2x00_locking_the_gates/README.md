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

### Task 4 - SSH Lockdown

**Script**

`4-ssh_hardening.sh`

**Purpose**

Hardens the OpenSSH server against credential-based initial access and
lateral movement. The configuration specifically addresses MedDefense
Finding 009 and the SSH lateral movement observed during the Crimson Tide
hospital compromises.

**Hardening Controls**

- Root SSH login disabled
- Password authentication disabled
- Empty passwords prohibited
- X11 forwarding disabled
- Authentication attempts limited to three
- Idle SSH sessions restricted
- SSH access restricted to approved administrators
- SSH Protocol 2 required
- Login grace time limited to 60 seconds
- Authorized-use login banner enabled

**Safety Controls**

The script:

- preserves `/etc/ssh/sshd_config.bak`
- validates changes using `sshd -t`
- restores the previous configuration if validation fails
- restarts SSH only after successful validation

**Validation**

```bash
sudo sshd -t
sudo sshd -T
systemctl status ssh

---

### Task 5 - The Kernel Shield

**Script**

`5-sysctl_hardening.sh`

**Purpose**

Hardens the Linux network stack and kernel memory protections against
pivoting, traffic manipulation, denial-of-service and memory exploitation.

**Controls Applied**

- IP forwarding disabled
- ICMP redirects rejected
- ICMP redirect transmission disabled
- Source routing rejected
- Martian packet logging enabled
- TCP SYN cookies enabled
- Broadcast ICMP echo requests ignored
- IPv6 disabled for the IPv4-only server profile
- Full ASLR enabled
- SUID core dumps disabled
- Kernel message access restricted
- Kernel pointer disclosure restricted

**Safety and Idempotency**

The script:

- preserves `/etc/sysctl.conf.bak`;
- replaces a managed configuration block rather than duplicating it;
- applies settings with `sysctl -p`;
- verifies every value through `/proc/sys`;
- restores the previous configuration if application or validation fails.

**Usage**

```bash
sudo ./5-sysctl_hardening.sh

---

### Task 6 - The Permission Sweep

**Script**

`6-filesystem_hardening.sh`

**Structured Output**

`6-filesystem_hardening.json`

**Purpose**

Audits and remediates filesystem permissions that may enable local
privilege escalation, persistence or privileged script modification.

**Controls Applied**

- SUID binaries compared with an Ubuntu 22.04 whitelist
- Unexpected SUID bits removed
- SGID binaries compared with an approved whitelist
- Unexpected SGID bits removed
- Unsafe world-writable permissions removed
- `/tmp`, `/var/tmp` and `/dev/shm` protected with:
  - `noexec`
  - `nosuid`
  - `nodev`
- Cron access restricted through `/etc/cron.allow`

**Safe Audit Mode**

```bash
sudo AUDIT_ONLY=1 ./6-filesystem_hardening.sh

---

### Task 7 - The Service Minimizer

**Script**

`7-service_minimization.sh`

**Purpose**

Reduces the Linux service attack surface by comparing enabled services
against a MedDefense billing-server allowlist.

The control addresses CIS service minimization and reduces opportunities
for initial access through unnecessary or misconfigured daemons.

**Required Services**

- SSH
- Apache
- MySQL
- UFW
- auditd
- AppArmor
- cron
- rsyslog
- systemd-timesyncd

**Safe Audit Mode**

```bash
sudo AUDIT_ONLY=1 ./7-service_minimization.sh

---

### Task 8 - The PAM Fortress

**Script**

`8-pam_hardening.sh`

**Purpose**

Hardens Linux authentication through PAM to reduce password-based attacks,
credential reuse and repeated authentication attempts.

The controls address credential abuse observed during the Crimson Tide
attack chain.

**Password Quality**

- Minimum length: 14 characters
- At least one digit
- At least one uppercase character
- At least one lowercase character
- At least one special character
- Maximum repeated characters: 3
- Username-based passwords rejected

**Account Lockout**

- Failed attempts: 5
- Failure interval: 900 seconds
- Lockout duration: 900 seconds

**Password History**

- Previous 12 passwords cannot be reused

**Safe Audit Mode**

```bash
sudo AUDIT_ONLY=1 ./8-pam_hardening.sh

---


