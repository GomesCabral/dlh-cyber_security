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

