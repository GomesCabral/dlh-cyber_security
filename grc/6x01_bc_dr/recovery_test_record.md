# LIS Recovery Test Record

**Test date:** 2026-11-03  
**Test conductor:** Automated local test supervised by ChatGPT (not the student SSH lab)  
**Declared RTO:** 30 minutes  
**Test environment:** `/tmp/meddefense-dr-test/` (local reproduction, not official DLH container)  
**Execution:** 2026-11-03T14:56:43+00:00 to 2026-11-03T14:56:43+00:00  
**Status:** Local simulation completed; official lab execution not verified.

## Step Timing Log

The following is the actual output generated during the local execution. The timer records whole seconds, so fast steps can display `0m 00s`.

```text
[STEP 01] Identify recovery target       | Start: 14:56:43 | End: 14:56:43 | Duration: 0m 00s | PASS
[STEP 02] Verify backup integrity        | Start: 14:56:43 | End: 14:56:43 | Duration: 0m 00s | PASS
[STEP 03] Create recovery workspace      | Start: 14:56:43 | End: 14:56:43 | Duration: 0m 00s | PASS
[STEP 04] Decompress backup              | Start: 14:56:43 | End: 14:56:43 | Duration: 0m 00s | PASS
[STEP 05] Restore SQLite database        | Start: 14:56:43 | End: 14:56:43 | Duration: 0m 00s | PASS
[STEP 06] Validate row count             | Start: 14:56:43 | End: 14:56:43 | Duration: 0m 00s | PASS
[STEP 07] Validate critical results      | Start: 14:56:43 | End: 14:56:43 | Duration: 0m 00s | PASS
[STEP 08] Inspect application config     | Start: 14:56:43 | End: 14:56:43 | Duration: 0m 00s | PASS
[STEP 09] Validate local recovery        | Start: 14:56:43 | End: 14:56:43 | Duration: 0m 00s | PASS
[STEP 10] Complete recovery validation   | Start: 14:56:43 | End: 14:56:43 | Duration: 0m 00s | PASS
SUMMARY | Start: 14:56:43 | End: 14:56:43 | Total: 0m 00s | RTO: 30m 00s | RTO result: PASS | Test steps: PASS
```

## Conditions Encountered

### Condition 1: Path mismatch

**Discovered at:** 14:56:43 (local time)  
**Runbook specified:** `/recovery/lis_dump.sql`  
**Actual path:** `/tmp/meddefense-dr-test/recovery/lis_dump.sql`  
**Resolution:** Used the correct staging path for the compressed backup; the outdated path was identified from the supplied runbook and was not executed as a failing command.

```bash
gzip -dc /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /tmp/meddefense-dr-test/recovery/lis_dump.sql
```

**Time added:** Not separately measurable; addressed during the timed decompression step.  
**Deviation category:** Runbook error / environment assumption.

### Condition 2: Configuration artifact

**Discovered at:** 14:56:43 (local time)  
**Expected:** Local recovery database path for validation  
**Actual:** `DB_HOST=lis-db-prod.meddefense.internal`  
**Resolution:** Left production configuration unchanged and used the local SQLite recovery database path directly for validation.

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"
```

**Time added:** Not separately measurable; handled during the timed configuration and validation steps.  
**Deviation category:** Configuration artifact / documentation gap.

### Condition 3: Row count check

**Query:** `SELECT COUNT(*) FROM patient_orders;`  
**Expected:** `5`  
**Actual:** `5`  
**Outcome:** PASS (local SQLite execution)

## Recovery Validation

**Backup SHA-256 verification:**

```text
$ cd /tmp/meddefense-dr-test/backup/lis/2026-04-21 && sha256sum -c backup_manifest.sha256
/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz: OK
```

The supplied manifest included a UTF-8 BOM, which was removed in the local staging copy to allow `sha256sum` to parse the manifest. The original backup and SHA-256 digest were not modified. This packaging issue should be checked in the official lab.

**Recovered database file:**

```text
$ ls -l /tmp/meddefense-dr-test/recovery/lis_recovered.db
-rw-r--r-- 1 root root 12288 Nov  3 14:56 /tmp/meddefense-dr-test/recovery/lis_recovered.db
```

**Critical values accessible:**

```text
$ sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045');"
MRN-10043|BMP|K+: 6.1 mEq/L|1
MRN-10045|TROPONIN|0.08 ng/mL|1 
```

**Database integrity:** `PRAGMA integrity_check;` returned `ok`.

## Test Result

**Actual recovery time:** 0m 00s (local timed run)  
**RTO met:** YES, for this local simulation only  
**Test outcome:** CONDITIONAL PASS — SQLite recovery, row count, critical values and local timing passed; clinical readiness, production dependencies, and official lab execution were not established.

The measured time must not be represented as a timed recovery performed inside the official student SSH lab. No real clinical team was notified. The laboratory exercise demonstrates database restoration only, not full clinical-service recovery.
