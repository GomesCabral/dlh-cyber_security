# LIS Recovery Test Record

**Test date:** 2026-11-03  
**Test conductor:** Pedro Cabral (assisted local reproduction)  
**Declared RTO:** 30 minutes  
**Test environment:** `/tmp/meddefense-dr-test/` (local reproduction, not the official DLH SSH lab)  
**Execution status:** Completed in the local environment; official DLH lab execution not verified.  
**Timing method:** Wall-clock timestamps to whole seconds; subsecond deviation measurements recorded using a monotonic clock.  

## Step Timing Log

```text
[STEP 01] Identify recovery target       | Start: 15:01:03 | End: 15:01:03 | Duration: 0m 00s | PASS
[STEP 02] Verify backup integrity        | Start: 15:01:03 | End: 15:01:03 | Duration: 0m 00s | PASS
[STEP 03] Create recovery workspace      | Start: 15:01:03 | End: 15:01:03 | Duration: 0m 00s | PASS
[STEP 04] Decompress backup and resolve path mismatch | Start: 15:01:04 | End: 15:01:04 | Duration: 0m 01s | PASS
[STEP 05] Restore SQLite database        | Start: 15:01:04 | End: 15:01:04 | Duration: 0m 00s | PASS
[STEP 06] Validate row count             | Start: 15:01:04 | End: 15:01:04 | Duration: 0m 00s | PASS
[STEP 07] Validate critical results      | Start: 15:01:04 | End: 15:01:04 | Duration: 0m 00s | PASS
[STEP 08] Inspect and override application config | Start: 15:01:04 | End: 15:01:04 | Duration: 0m 00s | PASS
[STEP 09] Validate local recovery        | Start: 15:01:04 | End: 15:01:04 | Duration: 0m 00s | PASS
[STEP 10] Complete recovery validation   | Start: 15:01:04 | End: 15:01:04 | Duration: 0m 00s | PASS
SUMMARY | Start: 15:01:03 | End: 15:01:04 | Total: 0m 01s | RTO: 30m 00s | RTO result: PASS | Test steps: PASS
```

The total measured recovery time was **0m 01s** against the **30m 00s** RTO. **RTO met: YES (local reproduction)**. The timer includes investigation and resolution of both deviations. The local dataset is small; these timings must not be interpreted as a realistic production recovery duration.

## Conditions Encountered

### Condition 1: Path mismatch

**Discovered at:** 15:01:04 (local execution clock)  
**Runbook specified:** `/recovery/lis_dump.sql`  
**Actual path:** `/tmp/meddefense-dr-test/recovery/lis_dump.sql`  
**Observed deviation:** Attempting to open the runbook's outdated output path failed with `FileNotFoundError: [Errno 2] No such file or directory: '/recovery/lis_dump.sql'`. The directory did not exist in this environment.  
**Resolution:** Created the valid recovery workspace and decompressed the backup into the corrected path using the following equivalent shell commands (local execution used Python gzip for the decompression):

```bash
mkdir -p /tmp/meddefense-dr-test/recovery
gzip -dc /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /tmp/meddefense-dr-test/recovery/lis_dump.sql
```

**Time added:** 0.000821 seconds (0.000014 minutes) for detection, error capture, and corrected decompression in the local reproduction. This is a measured subsecond operation, not an estimate of human troubleshooting time.  
**Corrective action:** Update the LIS runbook's output path and pre-create the recovery directory.

### Condition 2: Configuration artifact

**Discovered at:** 15:01:04 (local execution clock)  
**Expected:** Local recovery database path for validation  
**Actual:** `DB_HOST=lis-db-prod.meddefense.internal`  
**Observed deviation:** The supplied configuration still pointed to the production LIS host, which is inappropriate for an isolated SQLite recovery test.  
**Resolution:** Left the production configuration file unchanged and set the recovery database path in the local process environment. Validated the restored SQLite file directly. Equivalent shell commands:

```bash
export RECOVERY_DB_PATH=/tmp/meddefense-dr-test/recovery/lis_recovered.db
sqlite3 "$RECOVERY_DB_PATH" "SELECT COUNT(*) FROM patient_orders;"
```

**Time added:** 0.000405 seconds (0.000007 minutes) for configuration inspection and local override in the reproduced test. This measured interval excludes manual operator deliberation.  
**Corrective action:** Add an explicit SQLite-only recovery override and a check preventing accidental connection to the production hostname.

### Condition 3: Row count check

**Query:** `SELECT COUNT(*) FROM patient_orders;`  
**Expected:** 5  
**Actual:** 5  
**Outcome:** **PASS** — the restored database contains exactly five rows.

## Recovery Validation

**Backup SHA-256 verification:** **PASS** — the computed SHA-256 digest matched the digest supplied in `backup_manifest.sha256` (manifest text decoded with UTF-8 BOM handling in the local reproduction).  

**Recovered database file:**

```text
-rw-r--r-- 1 root root 12288 2026-11-03 /tmp/meddefense-dr-test/recovery/lis_recovered.db
```

The line above is a formatted file-size summary, **not a verbatim `ls -l` capture**; owner, mode and timestamp may differ in the official lab.

**Critical values accessible:**

```text
$ SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045') ORDER BY patient_mrn;
MRN-10043|BMP|K+: 6.1 mEq/L|1
MRN-10045|TROPONIN|0.08 ng/mL|1
```

**SQLite integrity check:** `PRAGMA integrity_check;` returned `ok`.  
**Backup decompression:** PASS.  
**Restore:** PASS.  

## Test Result

**Actual recovery time:** **0m 01s** (measured by `recovery_timer.sh` in local reproduction)  
**Declared RTO:** **30m 00s**  
**RTO met:** **YES — local reproduction only**  
**Test outcome:** **CONDITIONAL PASS** — all local technical validation checks passed, including row count and critical values, but the official DLH SSH lab execution and operational clinical recovery remain unverified.  

**Limitations:** This record documents actual commands and timing from a local reproduction using the staged files. It is not evidence of a student-operated run in the official lab, and the automated checker may require that environment's own outputs. Clinical readiness is not established by a database-only restoration.
