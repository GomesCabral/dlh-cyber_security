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

### Task 9 - The AppArmor Enforcer

**Script**

`9-apparmor_config.sh`

**Purpose**

Applies Mandatory Access Control to network-exposed services and limits
the impact of successful exploitation by restricting filesystem access.

The control reduces the blast radius of compromises such as the previous
Apache crypto-miner incident.

**Controls**

- Verify AppArmor kernel support
- Verify AppArmor service status
- Review loaded profiles
- Enforce Apache profile
- Enforce MySQL profile
- Create a custom MedDefense billing application profile
- Restrict application filesystem access
- Identify unconfined network-exposed processes

**Safe Audit Mode**

```bash
sudo AUDIT_ONLY=1 ./9-apparmor_config.sh

---

### Task 10 - The Audit Engine

**Script**

`10-auditd_config.sh`

**Purpose**

Deploys Linux kernel audit telemetry for security-critical activity and
creates the primary Linux audit trail required for future SOC monitoring.

The controls improve visibility into attacker behavior that previously
allowed malicious activity to remain undetected for several days.

**Audit Coverage**

- Identity files
- PAM configuration
- SSH configuration
- Privilege escalation
- sudoers changes
- Suspicious download tools
- Netcat execution
- MySQL data
- Apache configuration
- Startup and persistence mechanisms

**Audit Keys**

- `identity`
- `pam_config`
- `sshd_config`
- `priv_esc`
- `sudoers`
- `suspicious_download`
- `suspicious_netcat`
- `meddefense_db`
- `meddefense_web`
- `startup_scripts`

**Safe Audit Mode**

```bash
sudo AUDIT_ONLY=1 ./10-auditd_config.sh

---

### Task 11 - Audit Telemetry Coverage Test

**Script**

`11-audit_coverage_test.sh`

**Output**

`audit_validation.json`

**Purpose**

Validates that Linux audit telemetry captures the security events required
by the MedDefense SOC.

The test generates controlled and non-destructive events and verifies their
presence using `ausearch`.

**Coverage Tests**

1. Privileged command execution through sudo
2. Access to `/etc/shadow`
3. Execution of curl or wget
4. Read/metadata access to SSH configuration
5. Controlled write to a monitored temporary path
6. Controlled cron configuration action

**Safety**

Temporary audit rules and test files are automatically removed when the
script exits. No test accounts or executable cron jobs are created.

**Usage**

```bash
sudo ./11-audit_coverage_test.sh

---

### Task 12 - The Log Architect

**Script**

`12-log_config.sh`

**Purpose**

Configures structured system and authentication logging, retention and
access permissions so Linux security telemetry remains available for SOC
analysis and future SIEM export.

**Logging Sources**

- Authentication and PAM events -> `/var/log/auth.log`
- General system events -> `/var/log/syslog`

**Retention**

- `auth.log`: 90 daily rotations
- `syslog`: 60 daily rotations
- Rotated logs compressed

**Permissions**

- Owner: `root`
- Group: `adm`
- Mode: `640`

**Validation**

The script generates controlled `logger` events and confirms they reach
the expected files.

**Safe Audit Mode**

```bash
sudo AUDIT_ONLY=1 ./12-log_config.sh

---

### Task 13 - The Firewall Baseline

**Script**

`13-firewall_baseline.sh`

**Purpose**

Implements a default-deny host firewall policy that limits network access
to only the services required by the MedDefense billing server.

**Firewall Policy**

- Default inbound: deny
- Default outbound: allow
- SSH (`22/tcp`): management network only
- HTTP (`80/tcp`): allowed
- HTTPS (`443/tcp`): allowed
- MySQL (`3306/tcp`): application network only
- Denied connections logged

**Trusted Networks**

- Management: `10.10.1.0/24`
- Application: `10.10.2.0/24`

**Safe Audit Mode**

```bash
sudo AUDIT_ONLY=1 ./13-firewall_baseline.sh

---

### Task 14 - Production Hardening Orchestrator

**Script**

`14-hardening_orchestrator.sh`

**Outputs**

- `hardening_run.json`
- `hardening_improvement.json`
- `lynis_before.json`
- `lynis_after.json`

**Purpose**

Coordinates the complete MedDefense Linux hardening workflow in dependency
order and records measurable evidence of execution and security improvement.

**Workflow**

1. Baseline snapshot
2. Pre-hardening Lynis assessment
3. SSH hardening
4. Kernel/sysctl hardening
5. Filesystem hardening
6. Service minimization
7. PAM hardening
8. AppArmor confinement
9. auditd configuration
10. Audit coverage validation
11. Log configuration
12. Firewall baseline
13. Final validation

**Safety**

The orchestrator performs all prerequisite checks before modifying the
system and stops immediately if any hardening step returns a non-zero exit
code.

**Evidence**

Each executed step records:

- start time
- finish time
- execution duration
- exit code
- completion status

The workflow also compares the pre-hardening and post-hardening Lynis
hardening indexes.

**Usage**

```bash
sudo ./14-hardening_orchestrator.sh

---

### Task 15 - The Post-Hardening Validator

**Script**

`15-validation.sh`

**Purpose**

Provides independent, read-only validation of the MedDefense Linux
hardening baseline implemented by Tasks 4-13.

The validator detects configuration drift without modifying the system.

**Controls Validated**

- SSH hardening
- Kernel and sysctl security parameters
- Filesystem and mount protections
- Required service state
- PAM password and account lockout policy
- AppArmor enforcement
- auditd service and audit rules
- Audit telemetry coverage
- rsyslog configuration
- Log retention and permissions
- UFW firewall policy and network restrictions

**Operation**

For every control, the script:

1. Reads the actual system state.
2. Compares it with the expected MedDefense baseline.
3. Reports `PASS` or `FAIL`.

**Usage**

```bash
sudo ./15-validation.sh

---

### Task 16 - Lynis Improvement Diff

**Script**

`16-lynis_diff.sh`

**Inputs**

- `lynis_findings.json`
- `lynis_post_findings.json`

The script can generate the post-hardening report automatically when it is
not already available.

**Output**

`hardening_improvement.json`

**Purpose**

Compares the pre-hardening and post-hardening Lynis assessments to provide
measurable evidence of security improvement and identify residual or newly
introduced risk.

**Comparison Categories**

- Resolved findings
- Remaining findings
- New findings

**Metrics**

- Before Lynis hardening index
- After Lynis hardening index
- Score delta
- Resolved finding count
- Remaining finding count
- New finding count
- Residual risk summary

**Usage**

```bash
sudo ./16-lynis_diff.sh

---

