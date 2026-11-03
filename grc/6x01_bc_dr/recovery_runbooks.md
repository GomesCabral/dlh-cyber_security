# MedDefense Recovery Runbooks

**Version:** 1.0  
**Classification:** Confidential  
**Prepared by:** Pedro Cabral  
**Date:** 2026-11-03  
**Status:** Operational draft; lab execution and clinical sign-off pending

## Scope and Operating Rules

These runbooks cover (1) the prepared SQLite Laboratory Information System (LIS) recovery exercise and (2) documented Windows Active Directory (AD) recovery when DC01 is irrecoverable and DC02 remains healthy. Commands shown for AD **must not be run inside the Ubuntu lab**. Record the incident ID, operator, UTC timestamps, command outputs, deviations, and approving authority as each step completes. Do not assert recovery merely because a command exits successfully.

The LIS paths and expectations below come from `lab_config.env`, `app_config.env`, `expected_lis_records.txt`, and the provided runbook examples. Execute the LIS steps only in the supplied lab container; do not install packages, use Docker, or fetch internet resources.

## Runbook 1: Laboratory Information System Recovery

**Trigger:** LIS unavailable; incident commander authorizes recovery.  
**Operator:** Database/recovery administrator.  
**Verifier:** LIS application owner and clinical laboratory lead.  
**Declared lab RTO:** 30 minutes (from `lab_config.env`); record actual elapsed time, including failures.  
**Success condition:** Integrity verified; database restored; five orders and both specified critical results verified; clinical owner notified and accepts availability.

### Step 1 — Identify the Latest Available Recovery Target

**Command:**

```bash
cd /home/student/6x01
cat /opt/meddefense/materials/recovery_test/lab_config.env
ls -lt /tmp/meddefense-dr-test/backup/lis/*/lis_backup.sql.gz
```

**Expected output:** The configuration identifies `BACKUP_DATE=2026-04-21`, the backup at `/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz`, its SHA-256 manifest, and `DECLARED_RTO_MINUTES=30`.

**Verification:** Confirm the newest available backup is the approved recovery point; check the file exists and record its timestamp. The supplied exercise stages one dated backup; do not invent a newer point.

**Deviation handling:** If the file or configuration is missing, stop the restore, preserve listings, notify the incident commander, and record the recovery-point gap.

### Step 2 — Verify Backup Integrity

**Command:**

```bash
cd /tmp/meddefense-dr-test/backup/lis/2026-04-21
sha256sum -c backup_manifest.sha256
```

**Expected output:** `...lis_backup.sql.gz: OK` (the manifest uses the backup's absolute pathname).

**Verification:** Confirm exit status is zero using `echo $?` immediately after `sha256sum -c` and retain its complete output. A successful checksum establishes file consistency with the manifest, not database usability.

**Deviation handling:** Do not restore a mismatched backup. If the manifest is rejected because of an unexpected UTF-8 BOM or line formatting, preserve the original manifest and error, then generate a *temporary normalized copy* and recheck without changing the digest:

```bash
sed '1s/^\xEF\xBB\xBF//' backup_manifest.sha256 > /tmp/meddefense-dr-test/validation/manifest_normalized.sha256
sha256sum -c /tmp/meddefense-dr-test/validation/manifest_normalized.sha256
```

The `validation` directory must exist before using this fallback (create it with `mkdir -p` if necessary). Record the formatting deviation; **never** substitute a newly calculated digest for the supplied expected digest. If validation still fails, stop and escalate.

### Step 3 — Create the Recovery Workspace

**Command:**

```bash
mkdir -p /tmp/meddefense-dr-test/recovery /tmp/meddefense-dr-test/validation
ls -ld /tmp/meddefense-dr-test/recovery /tmp/meddefense-dr-test/validation
```

**Expected output:** Both directories exist and are accessible to the operator.

**Verification:** Confirm the directories exist; retain backup and manifest untouched. If an earlier recovered database exists, preserve it as incident evidence before a new restore; do not silently overwrite it.

**Deviation handling:** On permissions or storage failure, stop and escalate to the lab administrator; do not redirect output to an undocumented location.

### Step 4 — Decompress to the Correct Staging Path

**Command:**

```bash
gzip -cd /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /tmp/meddefense-dr-test/recovery/lis_dump.sql
ls -lh /tmp/meddefense-dr-test/recovery/lis_dump.sql
```

**Expected output:** Nonempty `lis_dump.sql` at the lab's staging path.

**Verification:** Check that `gzip` returned status zero and the staged SQL is nonempty (`test -s /tmp/meddefense-dr-test/recovery/lis_dump.sql`).

**Deviation handling — expected path mismatch:** The obsolete runbook uses `/recovery/lis_dump.sql`; that is **wrong** for this exercise. Log the failed old-path assumption as `Runbook Error / Environment Assumption` and use `/tmp/meddefense-dr-test/recovery/lis_dump.sql`. Do not create a misleading `/recovery` workaround.

### Step 5 — Restore the SQL Dump into SQLite

**Command:**

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db < /tmp/meddefense-dr-test/recovery/lis_dump.sql
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db 'PRAGMA integrity_check;'
```

**Expected output:** The restore command succeeds without SQL errors; integrity check prints `ok`.

**Verification:** Confirm both commands succeed and `PRAGMA integrity_check` returns exactly `ok`. Perform this step only on a clean recovery target; the SQL dump includes `DROP TABLE IF EXISTS patient_orders` and can overwrite previous test data.

**Deviation handling:** If a restore fails, preserve stderr, the staged SQL, and the partially restored database for analysis. Do not rerun destructively against the same target without an approved reset and evidence capture.

### Step 6 — Validate the Patient Order Count

**Command:**

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db 'SELECT COUNT(*) FROM patient_orders;'
```

**Expected output:**

```text
5
```

**Verification:** Compare with `EXPECTED_ROW_COUNT=5` in `lab_config.env` and `expected_lis_records.txt`.

**Deviation handling:** If the count is not five, declare validation failure, preserve output and database, and notify the laboratory lead; do not mark the service recovered.

### Step 7 — Validate Both Critical Results

**Command:**

```bash
sqlite3 -separator '|' /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045') ORDER BY patient_mrn;"
```

**Expected output:**

```text
MRN-10043|BMP|K+: 6.1 mEq/L|1
MRN-10045|TROPONIN|0.08 ng/mL|1
```

**Verification:** Compare both MRNs, test codes, result strings, and `critical_flag=1` against the provided expected-records file. A row count alone is insufficient.

**Deviation handling:** If either record differs or is absent, fail the test, preserve the SQL query and output, and alert the clinical laboratory lead immediately; do not infer patient safety from partial data.

### Step 8 — Inspect the Application Configuration Artifact

**Command:**

```bash
cat /tmp/meddefense-dr-test/config/app_config.env
grep '^DB_HOST=' /tmp/meddefense-dr-test/config/app_config.env
```

**Expected output:** `DB_HOST=lis-db-prod.meddefense.internal`.

**Verification:** Record this as a production hostname artifact, not the host of the restored SQLite file. Cross-check the configured `RECOVERY_DB_PATH` against `lab_config.env`.

**Deviation handling:** Categorize as `Configuration Drift / Documentation Gap`. Do not connect to or alter production DNS; do not claim a successful application failover based on the hostname.

### Step 9 — Apply a Local Recovery Override in Validation

**Command:**

```bash
RECOVERY_DB_PATH=/tmp/meddefense-dr-test/recovery/lis_recovered.db
sqlite3 "$RECOVERY_DB_PATH" 'SELECT COUNT(*) FROM patient_orders;'
sqlite3 "$RECOVERY_DB_PATH" 'PRAGMA integrity_check;'
```

**Expected output:** `5` and `ok`.

**Verification:** The command explicitly targets the local SQLite recovery database rather than `DB_HOST=lis-db-prod.meddefense.internal`. No modification to the original app config is required.

**Deviation handling:** If the local path is inaccessible or validation fails, retain the error and mark recovery unsuccessful. Do not rewrite production configuration to conceal the mismatch.

### Step 10 — Notify the Clinical Team and Record the Outcome

**Action:** The incident commander sends the following *template* after the clinical owner accepts the result; do not claim this message was actually sent during an offline exercise.

> LIS recovery update — Incident [ID], [UTC timestamp]. Restored recovery point: 2026-04-21 backup. SQLite integrity check: [PASS/FAIL]. Patient orders: [observed]/5. Critical results MRN-10043 (BMP, K+ 6.1 mEq/L) and MRN-10045 (Troponin 0.08 ng/mL): [verified/not verified]. Clinical validation: [approved/pending]. Downtime procedures remain active until clinical leadership authorizes return to normal operations. Contact: [role/channel].

**Expected output:** A timestamped notification record, recipient role, and explicit clinical acceptance or pending status.

**Verification:** Confirm the laboratory lead acknowledges the results and that the recovery timer's final elapsed duration is recorded separately.

**Deviation handling:** If the clinical team cannot be reached or declines acceptance, keep downtime procedures active and escalate; technical restoration alone is not a recovery declaration.

### LIS Evidence Checklist

Record: incident ID; operator; backup date and path; SHA-256 command and exit status; any BOM/path/configuration deviations; staged file path; restore command status; SQLite integrity result; order count; both critical records; clinical notification and acceptance; elapsed minutes; and RTO pass/fail. **No real execution results are asserted in this document.**

## Runbook 2: Active Directory — DC01 Loss, DC02 Healthy

**Trigger:** DC01 confirmed irrecoverable; DC02 responds normally.  
**Environment:** `meddefense.local`; DC01 normally holds FSMO roles; backup share `\\backup-srv\ad-backups\DC01\`.  
**Execution location:** Windows Server administrative PowerShell/Command Prompt on the approved DC/replacement host, **not** the Linux lab.  
**Operator:** AD recovery administrator.  
**Verifier:** Identity services lead and incident commander.

**Safety gate:** Isolate the failed DC01 and prevent its unexpected reconnection. A healthy DC02 is the source of truth for normal replication-based recovery. Do not reconnect an old DC snapshot or use unsupported image rollback: this risks USN rollback and directory divergence. The `wbadmin` sequence below is a documented *conditional backup-based alternative*; for a truly unrecoverable DC01, the preferred production procedure is to clean up its metadata, transfer/seize required FSMO roles to DC02, build a replacement DC, and promote it from the healthy replica. Do not attempt a system-state recovery onto an arbitrary live DC02.

### Step 1 — Document FSMO Role Holders

**Command (Windows):**

```powershell
netdom query fsmo
```

**Expected output (provided example):**

```text
Schema master               DC01.meddefense.local
Domain naming master        DC01.meddefense.local
PDC                         DC01.meddefense.local
RID pool manager            DC01.meddefense.local
Infrastructure master       DC01.meddefense.local
The command completed successfully.
```

**Verification:** Capture actual output with UTC timestamp; check which roles are on the lost DC01. Confirm DC02 is healthy before any transfer/seizure. Example output is illustrative, not evidence of the current environment.

**Deviation handling:** If the command fails, check DNS, privileges, and DC02 reachability. If roles remain on irrecoverable DC01, authorize FSMO seizure to DC02 using approved Windows procedures before rebuilding; document the decision and never reconnect the old DC01 afterward.

### Step 2 — Decide Authoritative vs Non-Authoritative Recovery

**Action:** Record the decision and approver before executing a restore.

- **Non-authoritative:** Default when DC02 holds a correct, healthy directory; a safely recovered DC01 obtains newer AD objects through replication. For permanently lost DC01, **rebuild and re-promote a replacement** rather than restoring a failed machine in place.
- **Authoritative:** Only when a specific deleted/corrupted directory object or subtree must override replicas and an approved directory recovery plan identifies scope, backup age, and impact. Requires specialist authorization and an authoritative-restore procedure; it is **not** justified by single-DC loss while DC02 is healthy.

**Expected output:** Written decision: `Non-authoritative / replacement DC` for the stated scenario, with reason and approver.

**Verification:** Verify DC02 replication/DNS/SYSVOL health, available backups, and role ownership; confirm the lost DC cannot reappear.

**Deviation handling:** If DC02 is unhealthy, stop and escalate to forest/domain recovery planning. Do not declare authoritative restoration simply to bypass errors.

### Step 3 — Document the Conditional `wbadmin` System-State Recovery Sequence

**Command (Windows, only on a supported and approved recovery target with matching backup prerequisites):**

```powershell
wbadmin get versions -backuptarget:\\backup-srv\ad-backups\DC01
wbadmin start systemstaterecovery -version:04/21/2026-01:00 -backuptarget:\\backup-srv\ad-backups\DC01 -quiet
```

**Expected output:** `get versions` lists the chosen backup version; `systemstaterecovery` reports completion without errors. The timestamp and command pattern are taken from the supplied examples; confirm the actual available version before using them.

**Verification:** Capture backup version, host identity, exit status, restore log, and reboot/DSRM prerequisites as required by the supported Windows recovery procedure. `wbadmin` does **not** make a permanently lost server magically available and must not be executed on the healthy DC02 as a shortcut. On a replacement server, use the approved AD DS reinstall/re-promotion process when DC02 is healthy; the sample restore command is for a valid backup-based recovery branch only.

**Deviation handling:** If no matching backup/version or supported target exists, do not improvise flags; take the replacement-DC branch and record the backup-based path as not applicable. If restoration errors occur, preserve logs and isolate the target.

### Step 4 — Check AD Replication Health

**Command (Windows, after approved recovery or replacement):**

```powershell
repadmin /showrepl
repadmin /replsummary
```

**Expected output (provided healthy example):**

```text
Default-First-Site-Name\DC01
==== INBOUND NEIGHBORS ======================================
DC=meddefense,DC=local
    Default-First-Site-Name\DC02 via RPC
        Last attempt @ 2026-04-21 09:42:13 was successful.
```

**Verification:** Confirm successful inbound replication from DC02 to the recovered/replacement DC, no sustained errors in `replsummary`, and current timestamps. The example describes a recovered DC01, not the pre-rebuild state.

**Deviation handling:** If replication fails, check DNS, RPC/network reachability, AD DS service, time synchronization, and event logs. Do not expose the replacement DC as healthy until replication is verified.

### Step 5 — Run Domain Controller Diagnostics

**Command (Windows):**

```powershell
dcdiag /s:DC02 /test:Connectivity /test:SysVolCheck /test:NetLogons
dcdiag /s:DC01 /test:Connectivity /test:SysVolCheck /test:NetLogons
dcdiag /e /q
```

**Expected output (provided example for restored DC01):**

```text
Testing server: Default-First-Site-Name\DC01
Starting test: Connectivity
......................... DC01 passed test Connectivity
Starting test: SysVolCheck
......................... DC01 passed test SysVolCheck
Starting test: NetLogons
......................... DC01 passed test NetLogons
```

**Verification:** All relevant tests pass on DC02 and the newly recovered/replacement DC01, `dcdiag /e /q` reports no unresolved errors, SYSVOL/NETLOGON shares are accessible, DNS resolves the domain, and a test account authenticates successfully. Before rebuilding DC01, the DC01-specific command is **not applicable** and must not be counted as a failure of healthy DC02.

**Deviation handling:** For failed checks, capture full output, investigate DNS/SYSVOL/replication or authentication, and maintain incident status. Do not silently suppress diagnostic errors.

### Step 6 — Declare Recovery Only Against Acceptance Criteria

**Action:** Identity lead and incident commander jointly approve the declaration after all applicable checks pass.

**Required criteria:** DC02 remains healthy; lost DC01 is permanently isolated; FSMO roles are reachable on valid holders (seized/transferred where needed); replacement DC01 is promoted and synchronized or an explicitly approved alternate topology is documented; `repadmin` and `dcdiag` checks pass; DNS, SYSVOL, NETLOGON and test authentication work; dependent clinical application owners confirm logins; and evidence, elapsed time, deviations, and residual risks are logged.

**Expected output:** Signed/timestamped recovery declaration with `PASS`, `FAIL`, or `PARTIAL` and specific outstanding issues.

**Verification:** Cross-check actual command logs and dependent-service sign-offs; do not treat example command output as live proof.

**Deviation handling:** If any mandatory criterion is unmet, record partial recovery and continue escalation. Never declare full recovery solely because DC02 is online.

## Document Control and Outstanding Validation

- The LIS runbook is executable only in the supplied lab after workspace setup; the timed recovery exercise must produce separate genuine command-output evidence.
- The AD runbook is documentation-only. Its output blocks are **provided examples**, not executed evidence.
- The supplied AD notes do not provide a tested replacement-DC promotion procedure, FSMO seizure authorization, or production backup catalog. Those operational prerequisites require validation by the AD team before use in production.
- This document does not imply clinical approval or a completed restore test.
