# LIS Recovery Test Record

**Test date:** Pending actual lab execution  
**Test conductor:** Pedro Cabral  
**Declared RTO:** 30 minutes  
**Test environment:** `/tmp/meddefense-dr-test/`  
**Status:** Not executed in the user's SSH lab; replace pending entries with actual evidence.

## Step Timing Log

Paste the complete contents of `recovery_test_log.txt` followed by the exact output of `./recovery_timer.sh SUMMARY` after the lab test.

```text
PENDING — no measured laboratory timings available.
```

## Conditions Encountered

### Condition 1: Path mismatch

**Discovered at:** Pending timestamp  
**Runbook specified:** `/recovery/lis_dump.sql`  
**Actual path:** `/tmp/meddefense-dr-test/recovery/lis_dump.sql`  
**Resolution:** Run and record the following corrected command:

```bash
gzip -dc /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /tmp/meddefense-dr-test/recovery/lis_dump.sql
```

**Time added:** Pending measured time; do not estimate retrospectively.

### Condition 2: Configuration artifact

**Discovered at:** Pending timestamp  
**Expected:** Local recovery database path for validation  
**Actual in supplied configuration:** `DB_HOST=lis-db-prod.meddefense.internal`  
**Resolution:** Use the local SQLite database path rather than the production hostname:

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"
```

**Time added:** Pending measured time.

### Condition 3: Row count check

**Query:** `SELECT COUNT(*) FROM patient_orders;`  
**Expected:** `5`  
**Actual:** Pending exact command output  
**Outcome:** Pending

## Recovery Validation

**Recovered database file:**

```text
PENDING — paste exact output of ls -l /tmp/meddefense-dr-test/recovery/lis_recovered.db
```

**Critical values accessible:**

```text
PENDING — paste exact SQLite query output for MRN-10043 and MRN-10045.
```

## Test Result

**Actual recovery time:** Pending timer summary  
**RTO met:** Pending (YES / NO)  
**Test outcome:** Pending (PASS / CONDITIONAL PASS / FAIL)

The RTO result must reflect the measured wall-clock duration, including deviations. Clinical readiness is not established by a database-only restoration.
