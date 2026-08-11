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

