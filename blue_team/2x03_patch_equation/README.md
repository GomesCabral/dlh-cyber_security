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

## Project progress

| Task | Name | Status |
|---|---|---|
| 0 | The Vulnerability Inventory | ✅ Implemented |
| 1–19 | Upcoming tasks | ⏳ Pending |

---

**Author:** Pedro Cabral  
**Project:** 2x03 — Patch Equation

---

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

## Project progress

| Task | Name | Status |
|---|---|---|
| 0 | The Vulnerability Inventory | ✅ Implemented |
| 1 | The Service Dependency Map | ✅ Implemented |
| 2–19 | Upcoming tasks | ⏳ Pending |

---

**Author:** Pedro Cabral  
**Project:** 2x03 — Patch Equation

---

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

## Project progress

| Task | Name | Status |
|---|---|---|
| 0 | The Vulnerability Inventory | ✅ Implemented |
| 1 | The Service Dependency Map | ✅ Implemented |
| 2 | (not yet requested) | ⏳ Pending |
| 3 | The Patch Plan | ✅ Implemented |
| 4–19 | Upcoming tasks | ⏳ Pending |

---

**Author:** Pedro Cabral  
**Project:** 2x03 — Patch Equation

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

## Project progress

| Task | Name | Status |
|---|---|---|
| 0 | The Vulnerability Inventory | ✅ Implemented |
| 1 | The Service Dependency Map | ✅ Implemented |
| 2 | (not yet requested) | ⏳ Pending |
| 3 | The Patch Plan | ✅ Implemented |
| 4 | The Safe Patch Execution | ✅ Implemented |
| 5–19 | Upcoming tasks | ⏳ Pending |

---

**Author:** Pedro Cabral  
**Project:** 2x03 — Patch Equation

---

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

## Project progress

| Task | Name | Status |
|---|---|---|
| 0 | The Vulnerability Inventory | ✅ Implemented |
| 1 | The Service Dependency Map | ✅ Implemented |
| 2 | (not yet requested) | ⏳ Pending |
| 3 | The Patch Plan | ✅ Implemented |
| 4 | The Safe Patch Execution | ✅ Implemented |
| 5 | The Post-Patch Service Validation | ✅ Implemented |
| 6–19 | Upcoming tasks | ⏳ Pending |

---

**Author:** Pedro Cabral  
**Project:** 2x03 — Patch Equation
