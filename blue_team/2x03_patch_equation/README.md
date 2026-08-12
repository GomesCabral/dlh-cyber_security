# 2x03 — Patch Equation

## Project objective

This 20-task project builds a practical Linux patch-management pipeline. The workflow is:

```text
measure exposure
→ understand patch impact
→ snapshot state
→ patch safely
→ validate
→ detect drift
→ recover / rollback
→ produce structured evidence
```

The README will be updated as each task is completed.

---

# Task 0 — The Vulnerability Inventory

## What is being asked

The first task is **measurement only**. Before applying a patch, we need to know exactly:

- what packages are installed;
- what packages have newer candidate versions;
- which candidate versions come from the security repository;
- which CVEs are associated with those security updates;
- the highest CVSS score affecting each package;
- whether any CVE is flagged in the supplied CISA KEV snapshot.

The script is:

```text
0-vuln_inventory.sh
```

and it produces:

```text
vulnerability_inventory.json
```

## Real-world use

This is the inventory stage of vulnerability management. An advisory saying “OpenSSH is vulnerable” is not enough to decide that a server is exposed. A security engineer needs evidence of the **installed version**, the **patched candidate**, the **repository pocket**, the related **CVEs**, and the risk context.

This allows later tasks to answer questions such as:

```text
Which systems are vulnerable?
Which vulnerability should be patched first?
Is exploitation known in the wild?
Which service might break if we patch?
```

## Native tooling used

Installed packages:

```bash
dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n'
```

Available upgrades:

```bash
apt list --upgradable
```

Candidate/repository information:

```bash
apt-cache policy PACKAGE
```

Security changelog:

```bash
apt-get changelog PACKAGE
```

JSON processing:

```bash
jq
```

If the online changelog is unavailable, the script performs a best-effort search for local Ubuntu Advantage/USN information under:

```text
/usr/share/ubuntu-advantage-tools
```

## Repository pockets

Typical Ubuntu pockets are:

```text
-release
-updates
-security
-backports
```

For Task 0, only upgrades whose candidate is identified as coming from a **security pocket** are added to the vulnerable-package list.

## CVE enrichment

The companion file:

```text
cve_feed.json
```

provides the CVSS and CISA KEV information for the exercise.

A CVE missing from the feed does **not** stop the script. Unknown enrichment defaults to a CVSS of `0`, severity `unknown`, and `in_cisa_kev: false`.

Severity classification:

```text
9.0–10.0  critical
7.0–8.9   high
4.0–6.9   medium
0.1–3.9   low
0          unknown
```

## Output structure

Each vulnerable package contains:

```json
{
  "package": "linux-image-generic",
  "installed_version": "5.15.0-91.101",
  "candidate_version": "5.15.0-97.107",
  "source_pocket": "jammy-security",
  "cves": ["CVE-2024-1086"],
  "max_cvss": 7.8,
  "severity": "high",
  "in_cisa_kev": true
}
```

The report also contains summary metadata.

## Running Task 0

Project directory:

```bash
cd ~/dlh-cyber_security/blue_team/2x03_patch_equation
```

Place these files there:

```text
0-vuln_inventory.sh
cve_feed.json
```

Make the script executable:

```bash
chmod +x 0-vuln_inventory.sh
```

Run:

```bash
sudo ./0-vuln_inventory.sh
```

The script does **not** install or upgrade anything.

## Reading the result

Complete report:

```bash
jq . vulnerability_inventory.json
```

Only CISA KEV packages:

```bash
jq '.packages[] | select(.in_cisa_kev == true)' vulnerability_inventory.json
```

Critical packages:

```bash
jq '.packages[] | select(.severity == "critical")' vulnerability_inventory.json
```

High or critical:

```bash
jq '.packages[] | select(.severity == "high" or .severity == "critical")' vulnerability_inventory.json
```

Count vulnerable packages:

```bash
jq '.packages | length' vulnerability_inventory.json
```

Validate JSON:

```bash
jq empty vulnerability_inventory.json
```

No output means valid JSON.

## Important principle

Task 0 separates **measurement** from **change**:

```text
measure → understand → patch
```

not:

```text
patch first → investigate problems later
```

That is especially important on production systems where an unattended package upgrade can break a critical service.

---

# Task 1 — The Service Dependency Map

## What is being asked

Knowing that a package is outdated is not enough to plan a safe patch. Task 1 answers the follow-up question: **if this package is patched, what breaks?**

For every active service on the host, we need to know:

- which executable the service actually runs;
- which package owns that executable;
- which shared libraries that executable links against, and which packages own each of those libraries;
- how critical the service is to the business;
- whether patching any of those packages will require restarting the service.

The script is:

```text
1-service_deps.sh
```

and it produces:

```text
service_dependency_map.json
```

## Real-world use

A patch to `libssl3` does not touch `libssl3` in isolation — it touches every service that links against it at runtime: `openssh-server`, `apache2`, `postgresql`, `curl`, and anything else sharing that library. A running process keeps the old version of a shared library mapped in memory until it is restarted, even after the on-disk package has been upgraded.

This map turns Task 0's package-level findings into service-level operational impact, so a patch rollout can answer:

```text
Which services will need a restart after this patch?
Which of those services are business-critical?
Does a library patch touch more services than expected?
```

## Native tooling used

Active service units:

```bash
systemctl list-units --type=service --state=active --no-legend --plain
```

Executable resolution:

```bash
systemctl show -p ExecStart --value UNIT
# fallback:
systemctl show -p MainPID --value UNIT
readlink -f /proc/PID/exe
```

Owning package for an executable or library:

```bash
dpkg -S REAL_PATH
```

> `dpkg -S` only matches **canonical, symlink-resolved** paths. Every path is passed through `readlink -f` before the lookup — most executables under `/usr/sbin` and most libraries under `/usr/lib/x86_64-linux-gnu` are symlinks, and skipping this step causes silent, wrong "unknown package" results.

Dynamic library dependencies:

```bash
ldd EXEC_PATH
```

Optional cross-check:

```bash
needrestart -b
```

JSON processing:

```bash
jq
```

## Criticality tagging

The companion file:

```text
service_criticality.json
```

maps a systemd unit name to one of `critical`, `high`, `medium`, `low`. Any active service **not** listed in the file defaults to `low`.

## Output structure

The report is **NDJSON** — one JSON object per line, not a single array — so it can be streamed, greped, or piped into `jq` line by line. Each service entry contains:

```json
{
  "service": "apache2.service",
  "exec_path": "/usr/sbin/apache2",
  "owning_package": "apache2",
  "linked_packages": ["apache2", "libc6", "libssl3"],
  "criticality": "high",
  "restart_required_on_patch": true,
  "needrestart_flagged": false
}
```

Field notes:

- `linked_packages` is the union of the executable's own owning package plus every package that owns a linked shared library, deduplicated.
- `restart_required_on_patch` is `true` whenever the service has at least one resolved package dependency — patching any of those packages requires restarting the process to load the new code.
- `needrestart_flagged` is an informational cross-check against `needrestart -b`, when that tool is available on the host. It reflects services `needrestart` currently flags as already running stale code, and does not override `restart_required_on_patch`.
- A service whose executable, package, or libraries cannot be resolved is still emitted with best-effort fields (e.g. `owning_package: "unknown"`, `linked_packages: []`) instead of aborting the run — one unresolved service must not sink the rest of the inventory.

## Running Task 1

Project directory:

```bash
cd ~/dlh-cyber_security/blue_team/2x03_patch_equation
```

Place these files there:

```text
1-service_deps.sh
service_criticality.json
```

Make the script executable:

```bash
chmod +x 1-service_deps.sh
```

Run:

```bash
sudo ./1-service_deps.sh
```

The script only reads system and package state — it does not install, upgrade, or restart anything.

## Reading the result

Complete report:

```bash
jq . service_dependency_map.json
```

Only critical services:

```bash
jq 'select(.criticality == "critical")' service_dependency_map.json
```

Services that will need a restart after any patch:

```bash
jq 'select(.restart_required_on_patch == true)' service_dependency_map.json
```

Every service depending on a given package (e.g. `libssl3`):

```bash
jq 'select(.linked_packages[] == "libssl3")' service_dependency_map.json
```

Count active services mapped:

```bash
jq -s 'length' service_dependency_map.json
```

Validate JSON (line by line, since the file is NDJSON):

```bash
jq empty service_dependency_map.json
```

No output means every line is valid JSON.

## Important principle

Task 1 turns a package-level patch decision into a service-level operational one:

```text
package to patch → services affected → criticality → restart plan
```

not:

```text
patch the package → find out what broke → explain it after the incident
```

Cross-referencing Task 0's `vulnerability_inventory.json` against this map is what tells you, before you patch anything, exactly which critical services are on the blast radius of a given CVE fix.

---

# Task 3 — The Patch Plan

## What is being asked

Task 0 tells you **what is vulnerable**. Task 1 tells you **what depends on what**. Task 3 is the join between them: a single, prioritized, ordered list of what to patch first, and exactly which services each patch will disturb.

For every vulnerable package found in Task 0, we need to know:

- a priority **score**, combining CVSS severity, known-exploited status, the criticality of any service it touches, and the breadth of its impact;
- the **rank** that score produces against every other vulnerable package;
- the **bucket** that rank falls into (`emergency`, `urgent`, `scheduled`);
- exactly which **services** will be disturbed by patching it;
- whether it **requires a restart**, or a full **reboot** (kernel/systemd only);
- the **rollback target** — the version currently installed, in case the patch needs to be reversed.

The script is:

```text
3-patch_plan.sh
```

and it produces:

```text
patch_plan.json
```

## Real-world use

A vulnerability scanner gives you a list. It does not give you an *order*. Two packages can both be "high severity" and still deserve very different urgency: one is a known-exploited kernel bug affecting the whole host, the other is a medium-CVSS library used by a single low-criticality cron job. This task turns a flat list of vulnerabilities into an actual rollout plan:

```text
What do we patch first?
What goes down when we patch it?
Does anything require a reboot, not just a service restart?
If this patch breaks something, what version do we roll back to?
```

## How the score is computed

```text
score = CVSS_WEIGHT       * max_cvss
      + KEV_WEIGHT        * (1 if in_cisa_kev else 0)
      + CRITICALITY_WEIGHT * max(criticality of affected services)
      + EXPOSURE_WEIGHT    * exposure_rank
```

Weights are constants defined at the top of the script:

```text
CVSS_WEIGHT        = 0.6
KEV_WEIGHT         = 1.5
CRITICALITY_WEIGHT = 0.3
EXPOSURE_WEIGHT     = 0.4
```

Criticality is mapped to a number: `critical=4 high=3 medium=2 low=1 none=0`.

`exposure_rank` is derived **only** from the two input files — the breadth of impact recorded in Task 0 and Task 1 — never from live system/network state (e.g. open sockets). This is deliberate: the task requires that *the same inputs always produce the same plan*, and querying live state would break that guarantee between runs.

```text
0  → package is not linked to any active service
1  → 1–2 services affected
2  → 3+ services affected
3  → kernel-wide or systemd-wide (affects the whole host)
```

Bucket thresholds:

```text
score >= 7        emergency
4 <= score < 7     urgent
score < 4          scheduled
```

## Kernel and systemd special case

A kernel or `systemd` patch cannot be mapped to a specific set of services the way a library like `libssl3` can — it affects the whole host. These packages are detected by name (`linux-image-*`, `linux-modules-*`, `linux-generic`, `linux-virtual`, `linux-kvm`, or `systemd` itself) and are always:

- assigned `affected_services: ["(kernel-wide)"]` or `["(system-wide)"]`;
- given maximum criticality and exposure contributions to the score;
- flagged `requires_reboot: true`.

Every other package is `requires_reboot: false` — patching a library or an application does not require rebooting the host, only restarting the services that link against it.

## Native tooling used

This task performs **no live system queries**. It is a pure, deterministic join over two already-computed JSON files:

```text
vulnerability_inventory.json   (Task 0)
service_dependency_map.json    (Task 1, NDJSON)
```

JSON processing and the entire join/scoring/ranking pipeline:

```bash
jq
```

## Output structure

```json
{
  "generated_at": "2026-08-11T14:42:00Z",
  "weights": {
    "cvss_weight": 0.6,
    "kev_weight": 1.5,
    "criticality_weight": 0.3,
    "exposure_weight": 0.4
  },
  "plan": [
    {
      "rank": 1,
      "package": "linux-image-generic",
      "score": 8.58,
      "bucket": "emergency",
      "affected_services": ["(kernel-wide)"],
      "requires_restart": true,
      "requires_reboot": true,
      "rollback_target_version": "5.15.0-91.101",
      "candidate_version": "5.15.0-97.107",
      "max_cvss": 7.8,
      "in_cisa_kev": true,
      "cves": ["CVE-2024-1086"]
    }
  ],
  "summary": {
    "total_patches": 3,
    "emergency": 1,
    "urgent": 1,
    "scheduled": 1,
    "reboot_required": true,
    "kernel_update_present": true,
    "systemd_update_present": false
  }
}
```

`plan` is ordered by score descending, with the package name used as a deterministic alphabetical tie-breaker whenever two packages score identically.

## Running Task 3

Project directory:

```bash
cd ~/dlh-cyber_security/blue_team/2x03_patch_equation
```

Requires that Task 0 and Task 1 have already been run in this directory, producing:

```text
vulnerability_inventory.json
service_dependency_map.json
```

Make the script executable:

```bash
chmod +x 3-patch_plan.sh
```

Run:

```bash
./3-patch_plan.sh
```

Console output:

```text
Emergency: 1   Urgent: 3   Scheduled: 2
Reboot required by plan: yes (kernel update present)
Report saved to: patch_plan.json
```

The script only reads the two input JSON files — it does not install, upgrade, or restart anything.

## Reading the result

Complete plan:

```bash
jq . patch_plan.json
```

Only emergency patches:

```bash
jq '.plan[] | select(.bucket == "emergency")' patch_plan.json
```

Every patch that will disturb a given service:

```bash
jq '.plan[] | select(.affected_services[]? == "ssh.service")' patch_plan.json
```

Everything requiring a full reboot:

```bash
jq '.plan[] | select(.requires_reboot == true)' patch_plan.json
```

Rollback versions for the whole plan, at a glance:

```bash
jq '.plan[] | {package, rollback_target_version}' patch_plan.json
```

Validate JSON:

```bash
jq empty patch_plan.json
```

No output means valid JSON.

## Important principle

Task 3 turns two separate measurements into one decision:

```text
what is vulnerable (T0) + what depends on what (T1) → what to patch, in what order, and what it will disturb
```

not:

```text
patch everything with the highest CVSS score → discover the service impact during the outage
```

Because the join is deterministic, the same pair of `vulnerability_inventory.json` / `service_dependency_map.json` will always produce the same plan — the plan only changes when the underlying measurements change, never between runs of this script alone.

---

# Task 4 — The Safe Patch Execution

## What is being asked

Task 3 produces the *intent*: an ordered plan of what to patch and in what order. Task 4 is the *execution*: it actually runs the upgrades, one at a time, in plan order, recording exactly what happened at every step — so that if the run is interrupted halfway through, the log is still a trustworthy, consistent account of everything that was done up to that point.

For every entry in the plan, in order, the script must:

- capture a **pre** snapshot (installed version, and the state of every linked service) before touching anything;
- run the actual upgrade with `apt-get install --only-upgrade`;
- capture a **post** snapshot afterwards;
- restart the affected services when a restart (not a reboot) is enough;
- record success, failure, timing, and a bounded tail of stdout/stderr for every entry;
- stop cleanly — not crash — the moment something fails, and still produce a complete log of what was and wasn't attempted.

The script is:

```text
4-patch_execute.sh
```

and it produces:

```text
patch_execution_log.json
```

## Real-world use

A patch rollout script that silently does nothing when interrupted, or that can be run twice at once by two different operators, is a production incident waiting to happen. This task builds the operational safety rails around the actual system change:

```text
Can two people patch the same host at once?      → no, an advisory lock prevents it
Is the dpkg lock busy from another process?       → wait with backoff, don't just fail
Did the patch actually apply? What changed?       → pre/post snapshots prove it
Did the service come back up after the restart?   → recorded per service, per patch
Did something fail halfway through the plan?      → stop safely, log everything up to that point
```

## Native tooling used

Advisory locking:

```bash
flock -n 200
```

Installed version, before and after:

```bash
dpkg-query -W -f='${Version}' PACKAGE
```

The actual upgrade:

```bash
DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y -- PACKAGE
```

Service state, before and after:

```bash
systemctl is-active SERVICE
systemctl show -p SubState --value SERVICE
```

Restarting an affected service:

```bash
systemctl try-restart SERVICE
```

Plan integrity:

```bash
sha256sum patch_plan.json
```

JSON processing:

```bash
jq
```

## Locking

The script acquires an advisory lock on:

```text
/var/lock/meddefense-patch.lock
```

using `flock -n` on a held file descriptor. If the lock is already held by another running instance, the script exits immediately with **exit code 2** and does not touch the plan or the system at all.

Cleanup uses two separate traps, deliberately kept apart:

```text
trap cleanup EXIT           # releases the lock, always, on any exit path
trap on_interrupt INT TERM  # cleans up AND explicitly exits
```

A signal handler that only cleans up without calling `exit` does not stop a bash script — bash resumes execution right after the handler returns. `on_interrupt` calls `exit 130` itself, which then triggers the `EXIT` trap for the actual lock release. This is what makes `Ctrl-C` / `SIGTERM` stop the run immediately (mid-`apt-get`, if needed) instead of continuing on with a partially torn-down temp state.

## The dpkg lock (a different lock)

`/var/lock/meddefense-patch.lock` is this script's *own* lock, preventing two instances of `4-patch_execute.sh` from running together. It has nothing to do with dpkg/apt's *own* internal lock (`/var/lib/dpkg/lock-frontend`), which any other package manager activity on the host (unattended-upgrades, another admin, a background `apt update`) can be holding independently.

When `apt-get` reports the dpkg lock is busy, the script retries with exponential backoff (1s, 2s, 4s, 8s, ...) up to a **120 second total budget**, then fails that entry with a clear reason. Any other `apt-get` failure (unmet dependencies, package not found, etc.) is **not** retried — it fails immediately, since retrying a genuine failure would just waste the 120-second budget on something that was never going to succeed.

## Stop-on-failure behaviour

The moment one entry's `apt-get` call fails (after exhausting any dpkg-lock retries), that entry is marked `failed` and every remaining entry in the plan is marked `skipped` in the log, rather than attempted. The script does **not** abort mid-write — it always finishes writing a complete, valid `patch_execution_log.json` covering every entry, attempted or not.

## Output structure

```json
{
  "started_at": "2026-08-11T14:49:34Z",
  "finished_at": "2026-08-11T14:49:37Z",
  "hostname": "gomescabral-VirtualBox",
  "plan_source_hash": "10215ef9...",
  "entries": [
    {
      "package": "libssl3",
      "bucket": "urgent",
      "status": "success",
      "pre": {
        "installed_version": "3.0.2-0ubuntu1.10",
        "services": [
          {"service": "apache2.service", "active_state": "active", "sub_state": "running"}
        ]
      },
      "post": {
        "installed_version": "3.0.2-0ubuntu1.15",
        "services": [
          {"service": "apache2.service", "active_state": "active", "sub_state": "running"}
        ]
      },
      "duration_seconds": 3.1,
      "stdout_tail": "...",
      "stderr_tail": "",
      "restarts": [
        {"service": "apache2.service", "status": "ok"},
        {"service": "ssh.service", "status": "ok"},
        {"service": "mysql.service", "status": "ok"}
      ],
      "rollback_target_version": "3.0.2-0ubuntu1.10"
    }
  ],
  "summary": {"succeeded": 6, "failed": 0, "total": 6}
}
```

`stdout_tail` / `stderr_tail` are capped to the last 20 lines of each stream, so a runaway `apt-get` output never blows up the log file — the full output exists only transiently, for the duration of that entry, to detect the dpkg-lock condition.

`plan_source_hash` is a SHA-256 of the exact `patch_plan.json` that was executed, so the log can always be tied back to the plan that produced it, even if the plan file changes later.

## Running Task 4

Project directory:

```bash
cd ~/dlh-cyber_security/blue_team/2x03_patch_equation
```

Requires that Task 3 has already been run in this directory, producing:

```text
patch_plan.json
```

Make the script executable:

```bash
chmod +x 4-patch_execute.sh
```

Run:

```bash
sudo ./4-patch_execute.sh
```

Console output:

```text
[*] Acquiring lock /var/lock/meddefense-patch.lock...  OK
[*] Loading plan: patch_plan.json (6 entries)
[1/6] linux-image-generic   emergency     apt-get ... OK (12.4s)
[2/6] libssl3               urgent        apt-get ... OK (3.1s)
      try-restart apache2.service         OK
      try-restart ssh.service             OK
      try-restart mysql.service           OK
...
Succeeded: 6  Failed: 0
Log saved to: patch_execution_log.json
```

This script **does** change the system — unlike Tasks 0, 1, and 3, it actually installs the upgraded packages named in the plan and can restart services. Run it only after reviewing `patch_plan.json`.

## Exit codes

```text
0   every entry succeeded
1   at least one entry failed (remaining entries were skipped)
2   the advisory lock could not be acquired -- another instance is already running
```

## Reading the result

Complete log:

```bash
jq . patch_execution_log.json
```

Only failed entries:

```bash
jq '.entries[] | select(.status == "failed")' patch_execution_log.json
```

Every service restart that failed:

```bash
jq '.entries[] | .restarts[]? | select(.status == "failed")' patch_execution_log.json
```

Rollback versions for everything that was actually attempted:

```bash
jq '.entries[] | select(.status != "skipped") | {package, rollback_target_version}' patch_execution_log.json
```

Validate JSON:

```bash
jq empty patch_execution_log.json
```

No output means valid JSON.

## Important principle

Task 4 turns the plan into an auditable action, never a silent one:

```text
lock → snapshot → change → snapshot → verify → log, even on failure or interruption
```

not:

```text
run every apt-get in a loop and hope nothing goes wrong
```

Every patch that runs leaves behind proof of exactly what it touched, how long it took, and what state the affected services were in immediately before and after — the evidence the next task (drift detection / rollback) will need.

---

# Task 5 — The Post-Patch Service Validation

## What is being asked

`apt-get install` exiting `0` (Task 4) is not proof that anything actually works. The package may have installed cleanly while the service failed to come back up, started listening on a different socket, or stopped responding to real traffic entirely. Task 5 closes the loop: it compares the live system, after patching, against the pre-patch baseline, and proves — or disproves — that nothing regressed.

Three kinds of check, for every relevant service:

- is it still **active** (not just "installed", but actually running)?
- is it still **listening** on the port it was listening on before?
- for anything **critical**, does it actually **respond** to a real request (HTTP call, `mysqladmin ping`, SSH banner), not just "the process exists"?

The script is:

```text
5-post_patch_validate.sh
```

and it produces:

```text
post_patch_validation.json
```

## A note on `pre_patch_state.json`

This task reads a **pre-patch baseline snapshot**, `pre_patch_state.json`, which is the output of the project's "snapshot state" step (Task 2 in the pipeline diagram) — not yet implemented in this repository at the time Task 5 was written. The schema assumed here, and used by the sample fixture shipped alongside this script, is:

```json
{
  "captured_at": "2026-08-11T14:30:00Z",
  "services": [
    {"service": "apache2.service", "active_state": "active", "sub_state": "running"}
  ],
  "listening": [
    {"port": 443, "proto": "tcp", "service": "apache2.service"}
  ]
}
```

If Task 2 is implemented later with a different schema, only the two `jq` reads at the top of the "service state checks" and "listening socket checks" sections need to change — the rest of the script is agnostic to how the snapshot was produced.

## Real-world use

```text
Did the service actually restart, or did apt just unpack the files?
Is nginx still listening on 443, or did the new package change the default config?
Is the database actually answering queries, or just "not crashed"?
```

A patch rollout that only checks `apt-get`'s exit code is trusting the package manager to also guarantee application-level correctness — which it does not. This task is the independent, service-level proof that the previous four tasks' work actually held.

## Native tooling used

Service state, compared against the baseline:

```bash
systemctl is-active SERVICE
```

> `systemctl is-active` prints the real state (`active`, `failed`, `inactive`, ...) to stdout **and** exits non-zero for anything other than `active` — both facts matter. The script reads the printed state itself rather than inferring it from the exit code, so a `failed` service is correctly reported as `"failed"`, not silently swallowed into `"unknown"`.

Listening sockets, compared against the baseline:

```bash
ss -tln
ss -uln
```

> Column layout in `ss` output varies across `iproute2` versions (the `Netid` column is sometimes present, sometimes not). The script never trusts a fixed column index — it scans every field of every `LISTEN` line for one ending exactly in `:PORT`, which is robust to that variation.

Critical service liveness probes, defined per-service in the companion `service_probes.json`:

```bash
curl -fsS -m 5 -o /dev/null -w '%{http_code}' URL
mysqladmin ping -h HOST -u USER
ssh -o BatchMode=yes -o ConnectTimeout=5 HOST
```

> The `ssh` probe never actually needs to log in. `BatchMode=yes` guarantees it never prompts, and the script treats a `Permission denied` or `Host key verification failed` response as **proof the SSH daemon is alive and answering** — the point of the probe is liveness, not authentication.

JSON processing:

```bash
jq
```

## Criticality source

Which services get a liveness probe (not just a state/socket check) is driven by Task 1's `service_dependency_map.json` — only services tagged `criticality: "critical"` are probed. The probe itself (HTTP URL, DB host, SSH target) comes from the companion:

```text
service_probes.json
```

```json
{
  "apache2.service": {"type": "http", "url": "http://127.0.0.1/"},
  "ssh.service": {"type": "ssh", "host": "127.0.0.1", "port": 22, "user": "probe"},
  "mysql.service": {"type": "mysqladmin", "host": "127.0.0.1", "user": "root", "password": ""}
}
```

Supported probe `type` values: `http`, `mysqladmin`, `ssh`, `tcp` (a generic port-open fallback). A critical service with no entry in `service_probes.json` is skipped with a warning, rather than silently counted as passed or failed — an unprobed critical service should be visible, not hidden inside a clean-looking report.

## Classification rule

Every check lands in exactly one of three states:

```text
pass          the check matches or exceeds the baseline
regression    a service/socket check that used to be fine no longer is
probe_failed  a critical liveness probe did not get a healthy response
```

Per the task's literal wording, service state checks pass **only** if the current `ActiveState` is exactly `active` — a service that was already down before patching and is still down after is still reported as a regression, since the check is defined against "active", not against whatever the pre-patch value happened to be.

## Output structure

```json
{
  "total_checks": 38,
  "passed": 38,
  "failed": 0,
  "details": [
    {
      "check_type": "service_state",
      "name": "apache2.service",
      "status": "pass",
      "expected": "active",
      "actual": "active",
      "detail": "service is active"
    }
  ],
  "categories": {
    "service_state": {"total": 24, "passed": 24},
    "listening_socket": {"total": 11, "passed": 11},
    "liveness_probe": {"total": 3, "passed": 3}
  }
}
```

## Running Task 5

Project directory:

```bash
cd ~/dlh-cyber_security/blue_team/2x03_patch_equation
```

Requires, in this directory:

```text
pre_patch_state.json          (baseline snapshot -- see note above)
service_dependency_map.json   (Task 1)
service_probes.json           (companion probe definitions)
```

Make the script executable:

```bash
chmod +x 5-post_patch_validate.sh
```

Run:

```bash
sudo ./5-post_patch_validate.sh
```

Console output:

```text
Service state checks:     24/24   PASS
Listening socket checks:  11/11   PASS
Critical liveness probes: 3/3     PASS
VERDICT: PASS (38/38)
Report saved to: post_patch_validation.json
```

The script only reads system state and issues read-only probes (an HTTP GET-equivalent status check, a ping-style DB check, a no-login SSH connection) — it does not modify anything.

## Exit codes

```text
0   every check passed
1   at least one regression or probe failure was detected
```

## Reading the result

Complete report:

```bash
jq . post_patch_validation.json
```

Only failures (regressions or failed probes):

```bash
jq '.details[] | select(.status != "pass")' post_patch_validation.json
```

Just the liveness probes:

```bash
jq '.details[] | select(.check_type == "liveness_probe")' post_patch_validation.json
```

Per-category pass rate:

```bash
jq '.categories' post_patch_validation.json
```

Validate JSON:

```bash
jq empty post_patch_validation.json
```

No output means valid JSON.

## Important principle

Task 5 treats "the package manager said OK" and "the service actually works" as two different claims that both need evidence:

```text
apt-get exit 0  +  service active  +  socket listening  +  probe responds  →  actually validated
```

not:

```text
apt-get exit 0  →  assume everything downstream is fine
```

Whatever fails here is exactly what the next task (drift detection / rollback) needs to act on — a `regression` or `probe_failed` entry in this report is the trigger for rolling a specific package back to the `rollback_target_version` Task 3 already recorded for it.

---

# Task 6 — The Configuration Drift Detector

## What is being asked

Patches ship new default configuration files. On a `noninteractive` run, the package manager normally keeps the administrator's existing config and leaves the new default alongside it — but not always: some patches touch auxiliary conffiles directly, and that silent change can reintroduce a setting a previous hardening pass had deliberately turned off. Task 6 catches this by comparing every tracked configuration file's current SHA-256 against the value captured before the patch run, and separating changes the patch run itself explains from changes that have no such explanation.

For every conffile tracked in the pre-patch baseline, the script classifies it as:

- **unchanged** — hash matches, nothing happened;
- **modified** — hash differs; a unified diff is captured when a "before" copy is available;
- **missing** — the file is simply gone;
- **new** — a conffile the upgraded package now tracks that wasn't tracked before.

Every `modified` or `missing` file is then cross-referenced against Task 4's execution log: if the file's owning package was actually upgraded this run, the drift is **expected**. If not, it's **unexpected** — configuration changed with nothing in the patch run to explain why, which is exactly the kind of change that needs a human to look at it.

The script is:

```text
6-config_drift.sh
```

and it produces:

```text
config_drift.json
```

## Real-world use

```text
Did the openssl patch also rewrite /etc/ssl/openssl.cnf, and is that expected?      → yes, openssl was upgraded this run
Did sshd_config change even though openssh-server was never touched?                → that's unexpected drift, investigate
Did a conffile silently disappear during the run?
Did the new package version start tracking a config file it didn't before?
```

A CVE fix that also quietly reverts a hardened setting in a config file is a real, recurring failure mode of patch management. This task is the check that would catch it.

## A note on the diff source

`pre_patch_state.json` only stores a **SHA-256 hash** per conffile, not its content — there is no "before" copy saved to diff against directly. Rather than fabricate one, this script uses the backup files `dpkg` itself leaves behind during a conffile conflict:

```text
<path>.dpkg-old    the previous file, when dpkg overwrote the local copy
<path>.dpkg-dist    the new package default, when dpkg kept the local copy because it had been modified
```

If neither exists (common on a plain `apt-get install --only-upgrade` with no conffile conflict), the diff is explicitly reported as unavailable rather than guessed at. If Task 2's snapshot step is later extended to store full file copies (not just hashes), this is the one function (`get_diff`) that would need to change.

## Native tooling used

Hashing:

```bash
sha256sum PATH
```

Unified diff, truncated:

```bash
diff -u <path>.dpkg-old <path> | head -n 40
```

Current conffiles tracked by an upgraded package (to detect newly-tracked files):

```bash
dpkg-query -W -f='${Conffiles}\n' PACKAGE
```

JSON processing:

```bash
jq
```

## Classification and expected/unexpected logic

```text
unchanged   hash matches baseline                              -> always expected (no drift)
modified    hash differs                                       -> expected iff owning_package was upgraded this run
missing     file no longer present                              -> expected iff owning_package was upgraded this run
new         conffile now tracked by an upgraded package,
            absent from the pre-patch tracked list              -> always expected (a direct result of the upgrade)
```

The "expected" package set comes from `patch_execution_log.json`'s entries with `"status": "success"` — only packages that were actually, successfully upgraded in the Task 4 run count.

## Output structure

The script prints nothing to the console on a normal run — everything lands in the report file:

```json
{
  "summary": {
    "total": 5, "unchanged": 1, "modified": 2,
    "missing": 1, "new": 1, "unexpected_drift": true
  },
  "files": [
    {
      "path": "/etc/mysql/my.cnf",
      "owning_package": "mysql-server",
      "classification": "modified",
      "pre_sha256": "...",
      "current_sha256": "...",
      "expected": false,
      "diff": "(diff unavailable: neither ...dpkg-old nor ...dpkg-dist exist)"
    }
  ]
}
```

## Running Task 6

Project directory:

```bash
cd ~/dlh-cyber_security/blue_team/2x03_patch_equation
```

Requires, in this directory:

```text
pre_patch_state.json        (baseline snapshot, including its conffile_hashes block)
patch_execution_log.json    (Task 4)
```

Make the script executable:

```bash
chmod +x 6-config_drift.sh
```

Run:

```bash
sudo ./6-config_drift.sh
```

The script only reads files and package metadata — it never modifies a conffile, and it never runs `dpkg --configure` or answers a conffile prompt on your behalf.

## Exit codes

```text
0   no unexpected drift found
1   at least one unexpected drift was detected
```

## Reading the result

Complete report:

```bash
jq . config_drift.json
```

Only unexpected drift (what actually needs investigating):

```bash
jq '.files[] | select(.expected == false)' config_drift.json
```

Everything that changed, expected or not:

```bash
jq '.files[] | select(.classification != "unchanged")' config_drift.json
```

Just the summary:

```bash
jq '.summary' config_drift.json
```

Validate JSON:

```bash
jq empty config_drift.json
```

No output means valid JSON.

## Important principle

Task 6 separates "something changed" from "something changed that we can't explain":

```text
drift + an upgrade that explains it   → expected, no action needed
drift + nothing that explains it      → unexpected, exit 1, investigate
```

not:

```text
alert on every configuration change, expected or not, and let the noise drown the real signal
```

An `unexpected` entry in this report is exactly the kind of finding that should feed back into the incident process — someone or something touched a config file outside of the patch run this script already accounted for.

---

# Task 7 — The Broken Upgrade Recovery

## What is being asked

An aborted `apt upgrade` can leave a host in a genuinely broken state: `dpkg` locked, some packages half-configured, others merely unpacked but never set up. Recovery is not "try things until it works" — it's a specific, ordered sequence, and running the wrong command (or the right command out of order) on an already-damaged package database can make things measurably worse.

The script diagnoses first, changes nothing until the diagnosis is safe, then repairs in a strict order, restarts whatever the breakage actually affected, and produces a structured report of exactly what it found and did.

The script is:

```text
7-apt_recovery.sh
```

and it produces:

```text
apt_recovery.json
```

## Real-world use

```text
Is dpkg actually locked by a live process right now, or just left with a stale lock file?
Which packages are stuck half-configured, half-installed, unpacked, or triggers-pending?
Is there enough disk space on / and /var to even attempt a repair?
Did the repair actually work, or is the system still broken afterward?
Which running services were affected by the broken packages, and do they need a restart?
```

Running `dpkg --configure -a` or deleting a lock file while a real `apt` process is still mid-install is how a recoverable situation turns into a corrupted package database. This task's diagnose-first, refuse-if-live discipline exists specifically to prevent that.

## Diagnosis (read-only, always runs first)

```bash
pgrep -fa 'dpkg|apt-get|apt-cache|apt|unattended-upgr'
```

> Matched by binary name, anchored to path/word boundaries — never a bare substring search for `"apt"`. This script's own filename, `7-apt_recovery.sh`, contains that substring; an unanchored match would make the script detect itself as a live `apt` process and refuse to run, every time, on every host. The check also explicitly excludes its own PID and its own script name from the results.

```bash
# lock files inspected, never assumed broken just because they exist --
# dpkg's locks are flock()-based, so the kernel already released any lock
# held by a process that has since died. A file that exists but is held
# by nothing is what this script calls "stale".
/var/lib/dpkg/lock-frontend
/var/lib/dpkg/lock
/var/cache/apt/archives/lock

fuser <lockfile>          # any PID returned -> "held"; nothing -> "stale"

dpkg --audit               # raw diagnostic text, captured as-is
dpkg-query -W -f='${Package} ${Status}\n'   # the actual broken-package list,
                                             # matched against half-configured /
                                             # half-installed / unpacked / triggers-pending

df -Pk / /var               # free space on both filesystems
```

`dpkg --audit`'s prose output is captured verbatim for the report, but the authoritative broken-package list used for every downstream decision (restart targeting, final pass/fail) comes from `dpkg-query`'s machine-readable status field, which is far more reliable to parse than free-text advice paragraphs.

## Refuse-if-live

If any real `dpkg`/`apt` process is detected, the script **stops immediately** — it does not remove locks, does not run `dpkg --configure -a`, does not touch anything. It writes the diagnosis it already collected to `apt_recovery.json` and exits with **code 2**. This is a hard stop, not a warning: acting on the package database while another process legitimately owns it is exactly the scenario that turns a routine recovery into data corruption.

## Repair order (strict, never reordered, never repeated)

```text
1. remove ONLY stale lock files (confirmed unheld above)
2. dpkg --configure -a
3. DEBIAN_FRONTEND=noninteractive apt-get --fix-broken install -y
4. dpkg --audit (re-run) -- must be empty, cross-checked against dpkg-query
```

Each step's exit code and output (tail, truncated) is recorded regardless of success or failure — a failed step does not abort the report, since the whole point of the exercise is an honest account of what was attempted and what the result was.

## Service restarts

After repair, every service in `service_dependency_map.json` whose `owning_package` or `linked_packages` intersects the packages that were broken **before** repair gets `systemctl restart` (not `try-restart` — a half-configured package's service may not even be running yet, so the restart must start it unconditionally, not merely restart it if already active). Services unrelated to the broken package set are left untouched.

## Output structure

```json
{
  "initial_diagnosis": {
    "live_processes_detected": false,
    "stale_locks": ["/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"],
    "held_locks": [],
    "dpkg_audit_raw": "...",
    "broken_packages": ["apache2", "libapache2-mod-php8.1", "mysql-server-8.0"],
    "broken_package_count": 3,
    "disk_free_kb": {"root": 10464060, "var": 10464060}
  },
  "actions_taken": [
    {"step": "remove_stale_locks", "status": "ok", "detail": "removed: ..."},
    {"step": "dpkg_configure_a", "status": "ok", "detail": "..."},
    {"step": "apt_fix_broken_install", "status": "ok", "detail": "..."},
    {"step": "dpkg_audit_recheck", "status": "ok", "detail": "dpkg --audit is empty; no broken packages remain"},
    {"step": "restart_service:apache2.service", "status": "ok", "detail": "post-restart state: active"}
  ],
  "final_state": "clean",
  "recovered": true,
  "duration_seconds": 38
}
```

## Running Task 7

Project directory:

```bash
cd ~/dlh-cyber_security/blue_team/2x03_patch_equation
```

Optional (used for the service-restart step):

```text
service_dependency_map.json   (Task 1)
```

Make the script executable:

```bash
chmod +x 7-apt_recovery.sh
```

The lab's broken-state setup script should be run first, to actually produce a broken `dpkg`/`apt` state to recover from. Then:

```bash
sudo ./7-apt_recovery.sh
```

Console output:

```text
[*] Diagnosing...
    live dpkg/apt processes: none
    stale locks: /var/lib/dpkg/lock-frontend, /var/lib/dpkg/lock
    dpkg --audit: apache2, libapache2-mod-php8.1, mysql-server-8.0
    broken packages: 3
[*] Repairing...
    remove stale locks                     OK
    dpkg --configure -a                    OK
    apt-get --fix-broken install           OK
    dpkg --audit (re-run)                  clean
[*] Restarting affected services...
    apache2.service                        active
    mysql.service                          active
RECOVERED: yes
Duration: 38s
Report saved to: apt_recovery.json
```

This script **does** change the system when repair is needed: it can remove stale lock files, run `dpkg --configure -a`, run `apt-get --fix-broken install -y`, and restart services. It never does any of this if a live `dpkg`/`apt` process is detected, and it never repeats or reorders the repair sequence.

## Testing without touching the real dpkg locks

The three lock file paths can be overridden with environment variables, which default to the real system paths when unset:

```bash
LOCK_FRONTEND_PATH=/tmp/test/lock-frontend \
LOCK_DPKG_PATH=/tmp/test/lock \
LOCK_APT_ARCHIVES_PATH=/tmp/test/archives-lock \
  ./7-apt_recovery.sh
```

This is how the script was validated during development — against fake lock files, never the host's real ones — and is useful for testing recovery logic safely in any environment.

## Exit codes

```text
0   recovered -- dpkg --audit is clean after repair
1   residual broken state -- repair was attempted but packages are still broken
2   refused to run -- a live dpkg/apt process was detected
```

## Reading the result

Complete report:

```bash
jq . apt_recovery.json
```

Just the diagnosis:

```bash
jq '.initial_diagnosis' apt_recovery.json
```

Only failed repair steps:

```bash
jq '.actions_taken[] | select(.status != "ok")' apt_recovery.json
```

Validate JSON:

```bash
jq empty apt_recovery.json
```

No output means valid JSON.

## Important principle

Task 7 treats an already-broken system as something that demands more caution, not less:

```text
diagnose fully → refuse if unsafe → repair in the one correct order → verify → report
```

not:

```text
run dpkg --configure -a and apt-get --fix-broken install and hope it's enough
```

Never the same command twice, never out of order — the sequence exists because each step assumes the one before it actually finished cleanly.

---

# Task 8 — The Unattended Upgrades Configuration

## What is being asked

Not every patch needs a human watching it land. Library and utility updates, minor security fixes in non-critical packages — that's routine work that should happen every night, on its own. But `billing-srv-01` got broken by an *unattended*, *unguarded* upgrade in the first place. This task builds the guardrails: automation for what's safe to automate, an explicit blacklist for what isn't, and automatic reboots switched off entirely, because a healthcare system does not get to reboot itself without a human deciding that's okay.

The script is:

```text
8-unattended_config.sh
```

and it produces:

```text
unattended_config.json
```

## Real-world use

```text
Should curl's next security patch just install itself overnight?        → yes
Should the kernel, MySQL, or Apache do the same?                        → no -- blacklisted, needs a maintenance window
Should the box reboot itself if a kernel update needs it?               → never, automatically
Is the nightly timer actually enabled, or did someone disable it?
```

This is the difference between "automation" and "automation with guardrails" — the second is what Tasks 3 and 4 already model for anything that *does* need a human in the loop; this task is what happens to everything else, safely, without anyone watching.

## Idempotency

Both configuration files are **regenerated in full and written atomically** (temp file + `mv`) on every run — never appended to. There is no "check if this line already exists before adding it" logic to get subtly wrong; the file's entire content is deterministic from the script's fixed template, so running it once or fifty times produces byte-for-byte identical files. This was verified directly: running the script twice against the same target paths leaves an unchanged MD5 sum on both config files, and the `Package-Blacklist` block appears exactly once regardless of how many times the script runs.

## Native tooling used

Presence check and install:

```bash
dpkg -s unattended-upgrades
DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades
```

Timers:

```bash
systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
```

Dry run:

```bash
unattended-upgrade --dry-run --debug
```

> The package is named `unattended-upgrades` (plural), but the binary it installs is `unattended-upgrade` (singular). The script tries the real binary name first and falls back to the plural form if that's what's actually on `PATH`, so it works regardless of which naming convention a given install uses.

JSON processing:

```bash
jq
```

## Configuration written

`/etc/apt/apt.conf.d/50unattended-upgrades`:

```text
Unattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}-security"; };
Unattended-Upgrade::Package-Blacklist {
    "linux-image*"; "linux-headers*"; "mysql-server*"; "apache2*"; "libapache2-mod-php*";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
Unattended-Upgrade::Mail "";
```

`/etc/apt/apt.conf.d/20auto-upgrades`:

```text
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

Only the `-security` pocket is an allowed origin — regular `-updates` never install themselves unattended, only security fixes do.

## A note on dry-run parsing

`unattended-upgrade --dry-run --debug`'s exact transcript format is not perfectly stable across Ubuntu/package versions. This script's parser looks for three specific, well-known lines in that transcript:

```text
"Packages that will be upgraded: <list>"        -> would_upgrade
"Package <name> has a blacklist match ..."       -> skipped_blacklisted
"Package <name> is set on hold"                  -> skipped_held
```

If a given version's output doesn't match these patterns, the counts fall back to `0` rather than crashing the script — but that also means the counts could under-report on an unusual version. If the numbers in `unattended_config.json` look wrong for your system, share the real `--dry-run --debug` transcript and the three `grep -oP` patterns near the bottom of the script can be adjusted to match.

## Output structure

```json
{
  "installed": true,
  "config_paths": [
    "/etc/apt/apt.conf.d/50unattended-upgrades",
    "/etc/apt/apt.conf.d/20auto-upgrades"
  ],
  "blacklist": ["linux-image*", "linux-headers*", "mysql-server*", "apache2*", "libapache2-mod-php*"],
  "timer_state": [
    {"timer": "apt-daily.timer", "active_state": "active", "enabled_state": "enabled"},
    {"timer": "apt-daily-upgrade.timer", "active_state": "active", "enabled_state": "enabled"}
  ],
  "dry_run_summary": {
    "would_upgrade": 4,
    "would_upgrade_packages": ["curl", "libssl3", "libcurl4", "openssh-client"],
    "skipped_blacklisted": 2,
    "skipped_blacklisted_packages": ["apache2", "linux-image-generic"],
    "skipped_held": 0,
    "skipped_held_packages": []
  }
}
```

## Running Task 8

Project directory:

```bash
cd ~/dlh-cyber_security/blue_team/2x03_patch_equation
```

Make the script executable:

```bash
chmod +x 8-unattended_config.sh
```

Run:

```bash
sudo ./8-unattended_config.sh
```

Console output:

```text
[*] unattended-upgrades: already installed
[*] Writing /etc/apt/apt.conf.d/50unattended-upgrades...   OK
[*] Writing /etc/apt/apt.conf.d/20auto-upgrades...         OK
[*] Enabling timers...                                     OK
[*] Dry run...
would upgrade:       4
skipped (blacklist): 2 (apache2, linux-image-generic)
skipped (held):      0
Report saved to: unattended_config.json
```

This script **does** change the system: it can install a package, writes two files under `/etc/apt/apt.conf.d/`, and enables/starts two systemd timers. It never runs a real upgrade itself — the dry run step only observes what `unattended-upgrade` *would* do.

## Testing without touching the real apt config

Both config file paths can be overridden with environment variables, which default to the real system paths when unset:

```bash
UNATTENDED_CONF_PATH=/tmp/test/50unattended-upgrades \
AUTO_UPGRADES_CONF_PATH=/tmp/test/20auto-upgrades \
  ./8-unattended_config.sh
```

This is how idempotency and the config content were validated during development, without ever writing to the host's real `/etc/apt/apt.conf.d/`.

## Reading the result

Complete report:

```bash
jq . unattended_config.json
```

Just the blacklist that's actually in effect:

```bash
jq '.blacklist' unattended_config.json
```

Whether both timers are actually enabled and active:

```bash
jq '.timer_state' unattended_config.json
```

Validate JSON:

```bash
jq empty unattended_config.json
```

No output means valid JSON.

## Important principle

Task 8 automates what's safe and fences off what isn't, in the same file, at the same time:

```text
security-pocket only + explicit blacklist + no auto-reboot  →  safe to automate
```

not:

```text
turn on unattended-upgrades and hope the defaults are sensible for a healthcare system
```

The blacklist here is not incidental — `linux-image*`, `mysql-server*`, `apache2*`, and `libapache2-mod-php*` are exactly the packages `billing-srv-01`'s incident involved. Automating everything else, safely, is what frees up the patch-review process (Tasks 0–5) to focus on the packages that actually need a human's judgment.

---

# Task 9 — The Rollback Capability

## What is being asked

Every patch applied must be reversible, and rollback can't be a runbook entry someone reads at 3am — it has to be a script that actually works. Given a package name, this task restores that exact package to the version recorded before the patch run, holds it there so `unattended-upgrades` doesn't immediately undo the rollback, and then re-proves the affected services are actually healthy — not just that `apt-get` exited `0`.

The script is:

```text
9-rollback.sh
```

It takes one argument and produces no report file — the proof is the console output and the exit code.

## Real-world use

```text
$ sudo ./9-rollback.sh curl
```

```text
Is 8.18.0-1ubuntu2 (the pre-patch version) even still available to install?
Did the downgrade actually succeed, or did apt refuse for some dependency reason?
Is curl now held, so tonight's unattended-upgrades run doesn't silently re-upgrade it?
Do apache2 and every other service that links against curl still work?
```

A rollback that "succeeds" at the `apt-get` layer but leaves a service broken, or gets silently re-patched the same night, isn't a rollback — it's a delay. This task's exit code only ever means `0` when every one of those questions was answered "yes".

## A note on `pre_patch_state.json`

This task reads a new block from the shared baseline snapshot:

```json
{
  "packages": {
    "curl": "8.18.0-1ubuntu2",
    "libssl3": "3.5.5-1ubuntu3"
  }
}
```

a simple package-name-to-pre-patch-version map. If a package isn't a key in this object, the script fails immediately and explicitly — rather than guess at a version, it refuses to act on data it doesn't have.

## Native tooling used

Target version lookup:

```bash
jq -r --arg p "$PACKAGE" '.packages[$p] // empty' pre_patch_state.json
```

Version availability, checked two ways — a cached `.deb` first, then the repository:

```bash
ls /var/cache/apt/archives/<package>_<version>_*.deb
apt-cache madison <package>
```

The rollback itself, exactly as specified:

```bash
DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades <package>=<version>
```

Holding the package so it can't be silently re-upgraded:

```bash
apt-mark hold <package>
```

Liveness probes — the same four probe types from Task 5 (`http`, `mysqladmin`, `ssh`, `tcp`), re-run here rather than imported, so this script works standalone even without Task 5's script present:

```bash
curl -fsS -m 5 -o /dev/null -w '%{http_code}' URL
mysqladmin ping -h HOST -u USER
ssh -o BatchMode=yes -o ConnectTimeout=5 HOST
```

## Which services get re-probed

Every service in `service_dependency_map.json` whose `linked_packages` array contains the package being rolled back — not just the `critical` ones (that restriction is Task 5's, for post-patch validation across the whole fleet of services; a targeted rollback re-checks everything that specific package could have broken). A service with no entry in `service_probes.json` is reported as `NO PROBE DEFINED` rather than silently skipped or counted as a pass — visibility matters more than a clean-looking summary.

## Exit criteria

```text
0   version found + confirmed available + downgrade succeeded + hold succeeded + every probed service passed
1   any of the above failed
```

If the downgrade itself fails, the hold step is skipped entirely (holding a package that's still on the broken version would just lock in the problem) — but the script still re-runs the probes, purely as diagnostic information about the service's current state, before reporting overall failure.

## Running Task 9

Project directory:

```bash
cd ~/dlh-cyber_security/blue_team/2x03_patch_equation
```

Requires, in this directory:

```text
pre_patch_state.json          (baseline snapshot, including its packages block)
service_dependency_map.json   (Task 1)
service_probes.json           (Task 5's probe definitions)
```

Make the script executable:

```bash
chmod +x 9-rollback.sh
```

Run, naming the package to roll back:

```bash
sudo ./9-rollback.sh curl
```

Console output:

```text
[*] Target version from pre_patch_state.json: 8.18.0-1ubuntu2
[*] Version available in cache or repository: yes
[*] Downgrading curl...                              OK
[*] apt-mark hold curl                               OK
[*] Re-running probes for affected services...
    apache2.service probe                         PASS
ROLLBACK: success
from 8.18.0-1ubuntu2.3 to 8.18.0-1ubuntu2
```

This script **does** change the system: it installs a downgraded version of the named package and marks it held. It only ever acts on the one package passed as its argument.

## Important principle

Task 9 treats rollback as a capability that gets exercised, not a plan that gets written down:

```text
name the package → prove the old version is available → downgrade → hold → re-verify the services it touches
```

not:

```text
apt-get install <package>=<old-version> and assume it worked
```

Every other task in this project measures, plans, executes, and validates *forward* patches. This is the one script whose entire job is to prove the project can also go *backward*, on demand, for a single named package, without waiting for a maintenance window.

---

# Task 10 — The Version Hold Management

## What is being asked

A held package with no recorded reason becomes permanent by accident. Six months later, nobody remembers why `mysql-server` is pinned, and nobody dares touch it. This task makes hold management a **data-driven, convergent operation**: every hold is declared once, in one file, with a reason, an owner, and a review date — and one script is the only thing ever allowed to change `apt-mark` state or the pin file on disk.

The script is:

```text
10-version_hold.sh
```

and it produces:

```text
hold_management.json
```

## Real-world use

```text
Why is mysql-server-8.0 held? Who owns that decision, and when should it be revisited?
Is there a hold on the system that isn't in the registry -- who put that there, and why?
Which holds are overdue for review right now?
```

The registry is the single source of truth. If a hold exists on the system but isn't declared in `hold_registry.json`, this script treats that as drift and removes it — the same convergence philosophy Task 6 applies to configuration files, applied here to package holds.

## The registry is the only writer

This script is explicitly the **only** thing that should ever call `apt-mark hold`/`unhold` or touch `/etc/apt/preferences.d/meddefense-pins`. A manual `apt-mark hold` run outside this script will be silently reverted the next time `10-version_hold.sh` runs, because the script always converges the system to exactly what the registry declares — nothing more, nothing less. If a hold needs to exist, it needs an entry in `hold_registry.json` first.

## Idempotency

The preferences fragment is regenerated in full and written atomically (temp file + `mv`) from the registry on every run — the same pattern Task 8 uses for its config files. Verified directly: re-running the script against an already-converged system produces a byte-identical `meddefense-pins` file (same MD5 before and after) and an empty "releasing holds" section.

## Native tooling used

Current state and convergence:

```bash
apt-mark showhold
apt-mark hold <package>
apt-mark unhold <package>
```

Preferences pin, `Pin-Priority: 1001` per registry entry:

```text
Package: mysql-server-8.0
Pin: version 8.0.35-0ubuntu0.22.04.1
Pin-Priority: 1001
```

Review-date math:

```bash
date -u -d "<review_date>" +%s
```

JSON processing:

```bash
jq
```

## Registry schema

```json
{
  "holds": [
    {
      "package": "mysql-server-8.0",
      "reason": "billing app v8.0.35 dependency",
      "owner": "analyst",
      "review_date": "2026-05-28",
      "pin_version": "8.0.35-0ubuntu0.22.04.1"
    }
  ]
}
```

`days_to_review` is `review_date` minus today, in days — negative means the review is overdue.

## Output structure

```json
{
  "applied": [
    {
      "package": "mysql-server-8.0", "reason": "billing app v8.0.35 dependency",
      "owner": "analyst", "review_date": "2026-05-28",
      "pin_version": "8.0.35-0ubuntu0.22.04.1",
      "hold_applied": true, "days_to_review": -76
    }
  ],
  "released": [
    {"package": "old-stale-pkg", "released": true}
  ],
  "overdue_reviews": [
    {"package": "mysql-server-8.0", "owner": "analyst", "review_date": "2026-05-28", "days_to_review": -76}
  ],
  "total_held": 4
}
```

## Running Task 10

Project directory:

```bash
cd ~/dlh-cyber_security/blue_team/2x03_patch_equation
```

Requires, in this directory:

```text
hold_registry.json
```

Make the script executable:

```bash
chmod +x 10-version_hold.sh
```

Run:

```bash
sudo ./10-version_hold.sh
```

Console output:

```text
[*] Reading hold_registry.json...           (4 entries)
[*] Reading current apt-mark showhold...    (1 entry)
Applying holds:
  mysql-server-8.0        hold + pin 8.0.35-0ubuntu0.22.04.1   OK
  mysql-client-8.0        hold + pin 8.0.35-0ubuntu0.22.04.1   OK
  libapache2-mod-php8.1   hold + pin 8.1.2-1ubuntu2.14         OK
  php8.1-mysql            hold + pin 8.1.2-1ubuntu2.14         OK
Releasing holds no longer in registry:
  (none)
Overdue reviews: 0
Report saved to: hold_management.json
```

This script **does** change the system: it applies and releases `apt-mark` holds and rewrites `/etc/apt/preferences.d/meddefense-pins` in full on every run.

## Exit codes

The task spec doesn't define exit codes explicitly for this script (unlike Tasks 4, 5, 6, 7, and 9). For consistency with the rest of the project, this script exits non-zero if any individual hold or release action actually failed, so a caller can detect a partially-applied registry rather than only finding out by reading the report:

```text
0   every hold and release in this run succeeded
1   at least one hold or release action failed
```

## Testing without touching the real preferences file

The pin file path can be overridden with an environment variable, defaulting to the real system path when unset:

```bash
PREFERENCES_FILE_PATH=/tmp/test/meddefense-pins ./10-version_hold.sh
```

This is how idempotency was validated during development, without ever writing to the host's real `/etc/apt/preferences.d/`.

## Reading the result

Complete report:

```bash
jq . hold_management.json
```

Just the overdue reviews:

```bash
jq '.overdue_reviews' hold_management.json
```

Any hold or release that failed:

```bash
jq '.applied[] | select(.hold_applied == false), .released[] | select(.released == false)' hold_management.json
```

Validate JSON:

```bash
jq empty hold_management.json
```

No output means valid JSON.

## Important principle

Task 10 makes "why is this held" a question the system can answer itself:

```text
one registry, one owner, one review date per hold  →  one script converges the system to match it
```

not:

```text
someone runs apt-mark hold by hand during an incident, and six months later nobody remembers why
```

An overdue review in this report is a prompt, not a failure — it means a decision that was meant to be revisited is due for a second look, before "temporary" quietly becomes "permanent".

---

# Task 11 — The Maintenance Window Enforcement

## What is being asked

A policy that says "only patch inside the window" means nothing if enforcement is a human reading a clock. This task turns the policy into a predicate: a guard script that any patch operation calls first. If the guard says "out of window", the operation simply does not proceed — there's no judgment call left to make at 3am.

The script is:

```text
11-maintenance_window.sh
```

and it produces:

```text
maintenance_window.json
```

It **never** touches package state. This is pure decision logic — the only things it ever reads are the clock and `maintenance_windows.json`.

## Real-world use

```text
Is it safe to run 4-patch_execute.sh right now, or should it wait?
If we're outside the window, when does the next one open, and how long is that?
Is there a legitimate way to patch right now anyway, for a genuine emergency -- and is that fact logged distinctly?
```

Every other script in this project that changes system state should be preceded by a call to this guard, so "only patch inside the window" is enforced the same way every time, not remembered by whoever happens to be on call.

## Modes

```bash
11-maintenance_window.sh --check            # decide now, exit immediately
11-maintenance_window.sh --wait <seconds>    # poll until a window opens or the timeout elapses
11-maintenance_window.sh --report            # print the JSON report only, no text summary
```

All three modes write `maintenance_window.json` and share the exact same decision logic — `--wait` is simply `--check`, repeated on a poll interval, until either the answer changes or the budget runs out.

## Exit codes

```text
0    inside a standard/extended window -> proceed
10   only the "emergency" (always: true) window applies, AND
     MEDDEFENSE_EMERGENCY=1 was set -> proceed via emergency override
20   outside every window (including "emergency" present but no override) -> defer
```

Code `10` is deliberately distinct from `0` — a caller (or an audit log) can tell "this ran during a routine window" apart from "this ran via the emergency bypass" just from the exit code, without parsing the report.

## Window matching logic

```text
days              the window applies on these weekdays (3-letter abbrev: Mon, Tue, ... Sat, Sun)
start / end       "HH:MM" 24-hour local time, in the configured timezone
week_of_month     optional; 1 = the days 1-7 occurrence of that weekday, 2 = days 8-14, etc.
                  (i.e. "the Nth <weekday> of the month" in the conventional sense)
always            a window that applies at all times, regardless of day/time -- this is how
                  "emergency" is expressed; it never contributes to the next-window search
```

All time comparisons happen in the timezone declared in `maintenance_windows.json` (`TZ="<timezone>" date ...`), never the host's local timezone — a server in UTC and a maintenance window declared in `Europe/Paris` will be compared correctly regardless of what timezone the box itself is set to.

## Computing the next window

When nothing is active right now, the script looks up to 60 days ahead, day by day, for the soonest date that satisfies any non-emergency window's `days` (and `week_of_month`, if set), and reports whichever one starts earliest — which is not always the same window that matches first. If two windows both fall on the same day, the one with the earlier `start` time wins (e.g. an `extended` window starting at `00:00` beats a `standard` window on the same Saturday starting at `02:00`, even though `standard` has no `week_of_month` restriction and would otherwise seem like the more "generic" match).

## Output structure

```json
{
  "now": "2026-03-30 10:22 Europe/Paris (Mon)",
  "timezone": "Europe/Paris",
  "active_window": null,
  "next_window": {"name": "standard", "at": "2026-04-04T02:00:00+02:00"},
  "seconds_until_next": 394680,
  "decision": "defer",
  "exit_code": 20
}
```

## Running Task 11

Project directory:

```bash
cd ~/dlh-cyber_security/blue_team/2x03_patch_equation
```

Requires, in this directory:

```text
maintenance_windows.json
```

Make the script executable:

```bash
chmod +x 11-maintenance_window.sh
```

Run:

```bash
./11-maintenance_window.sh --check
```

Console output, inside a window:

```text
now:            2026-03-28 14:07 Europe/Paris (Sat)
active window:  standard
decision:       proceed
Report saved to: maintenance_window.json
```

```bash
$ echo $?
0
```

Outside every window:

```text
now:            2026-03-30 10:22 Europe/Paris (Mon)
active window:  (none)
next window:    standard  at 2026-04-04 02:00
seconds until:  403080
decision:       defer
```

```bash
$ echo $?
20
```

This script requires no `sudo` and changes nothing on the system — it can be run by any user, at any time, as often as needed.

## Testing without waiting for the real calendar

For development and testing, the "current time" can be pinned to a specific epoch with an environment variable, entirely bypassing the real clock:

```bash
MEDDEFENSE_NOW_OVERRIDE=$(TZ="Europe/Paris" date -d "2026-03-28 03:00" +%s) \
  ./11-maintenance_window.sh --check
```

When unset (normal use), the script always uses the real current time. This is how the window-matching, week-of-month, and next-window logic were validated deterministically during development, across multiple scenarios, without waiting for an actual Saturday.

## Reading the result

Complete report:

```bash
jq . maintenance_window.json
```

Just the decision:

```bash
jq -r '.decision' maintenance_window.json
```

Validate JSON:

```bash
jq empty maintenance_window.json
```

No output means valid JSON.

## Important principle

Task 11 makes the maintenance window a fact the system can check, not a rule someone has to remember:

```text
call the guard first  →  proceed / defer / emergency-override, with an exit code any script can act on
```

not:

```text
"we only patch on Saturdays" written in a wiki page nobody re-reads under pressure
```

Exit code `10` — the emergency path — exists specifically so that when the rule *is* bypassed, that fact is never silent. It shows up in the exit code, in the report, and in whatever calls this guard next.

---

## Project progress

| Task | Name | Status |
|---|---|---|
| 0 | The Vulnerability Inventory | ✅ Implemented |
| 1 | The Service Dependency Map | ✅ Implemented |
| 2 | (not yet requested) | ⏳ Pending |
| 3 | The Patch Plan | ✅ Implemented |
| 4 | The Safe Patch Execution | ✅ Implemented |
| 5 | The Post-Patch Service Validation | ✅ Implemented |
| 6 | The Configuration Drift Detector | ✅ Implemented |
| 7 | The Broken Upgrade Recovery | ✅ Implemented |
| 8 | The Unattended Upgrades Configuration | ✅ Implemented |
| 9 | The Rollback Capability | ✅ Implemented |
| 10 | The Version Hold Management | ✅ Implemented |
| 11 | The Maintenance Window Enforcement | ✅ Implemented |
| 12–19 | Upcoming tasks | ⏳ Pending |

---

**Author:** Pedro Cabral  
**Project:** 2x03 — Patch Equation

