#!/bin/bash
# name: 14-pipeline_test.sh
# purpose: Prove the pipeline (Task 13) handles a NEW advisory correctly,
#          not just today's real vulnerability data: swap in a simulated
#          CVE feed, run the full pipeline in dry-run mode (nothing is
#          actually installed), compare the resulting patch_plan.json
#          against a known-good "expected" baseline, and always restore
#          the real cve_feed.json afterward -- even on failure.
# Project: 2x03 - Patch Equation
# Task:    14 - The Pipeline Test Against a Simulated Advisory
#
# A note on patch_plan.expected.json: what the "correct" plan looks like
# for a given cve_feed.simulated.json depends on which packages actually
# have upgrade candidates on THIS host right now -- something no one can
# author by hand in the abstract. If patch_plan.expected.json does not
# yet exist, this script BOOTSTRAPS it from the first real run (a "golden
# file" pattern) rather than inventing a fixture that would almost
# certainly never match a real system. Delete patch_plan.expected.json
# and re-run once to intentionally re-baseline it.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
CVE_FEED="${SCRIPT_DIR}/cve_feed.json"
CVE_FEED_BACKUP="${SCRIPT_DIR}/cve_feed.json.bak"
CVE_FEED_SIMULATED="${SCRIPT_DIR}/cve_feed.simulated.json"
PLAN_FILE="${SCRIPT_DIR}/patch_plan.json"
PLAN_EXPECTED="${SCRIPT_DIR}/patch_plan.expected.json"
PIPELINE_SCRIPT="${SCRIPT_DIR}/13-patch_pipeline.sh"
PIPELINE_RUN_FILE="${SCRIPT_DIR}/pipeline_run.json"
OUTPUT_FILE="${SCRIPT_DIR}/pipeline_test_results.json"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq diff date; do need "$c"; done

[[ -f "${CVE_FEED_SIMULATED}" ]] || fail "cve_feed.simulated.json not found in ${SCRIPT_DIR}"
jq empty "${CVE_FEED_SIMULATED}" >/dev/null 2>&1 || fail "cve_feed.simulated.json is invalid JSON"
[[ -f "${PIPELINE_SCRIPT}" ]] || fail "13-patch_pipeline.sh not found in ${SCRIPT_DIR}"

STARTED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

echo "[*] Scenario: simulated CVE advisory"

# ---------------------------------------------------------------------------
# Ensure the real cve_feed.json is ALWAYS restored, no matter how this
# script exits -- a crash mid-test must never leave the simulated feed in
# place as if it were the real one.
# ---------------------------------------------------------------------------
RESTORE_DONE=false
restore_feed() {
    [[ "${RESTORE_DONE}" == "true" ]] && return
    if [[ -f "${CVE_FEED_BACKUP}" ]]; then
        mv -f "${CVE_FEED_BACKUP}" "${CVE_FEED}"
    fi
    RESTORE_DONE=true
}
trap restore_feed EXIT

PIPELINE_PID=""
on_interrupt() {
    echo "" >&2
    echo "[FAIL] Interrupted -- restoring cve_feed.json and aborting." >&2
    # Forward the signal to the pipeline child explicitly: a plain
    # foreground `bash otherscript.sh` call does NOT reliably interrupt
    # this shell's wait() when signaled (verified: a nested bash-in-bash
    # foreground call can make the parent's wait ride out the child's
    # full remaining runtime before the trap fires). Running the pipeline
    # as an explicit background job and using `wait` on its PID instead
    # (see below) is what makes this trap fire immediately.
    [[ -n "${PIPELINE_PID}" ]] && kill -TERM "${PIPELINE_PID}" 2>/dev/null
    exit 130
}
trap on_interrupt INT TERM

# ---------------------------------------------------------------------------
# 1-2. Backup real feed, inject the simulated one
# ---------------------------------------------------------------------------
echo -n "[*] Backing up cve_feed.json...              "
if [[ -f "${CVE_FEED}" ]]; then
    cp -f "${CVE_FEED}" "${CVE_FEED_BACKUP}"
    echo "OK"
else
    echo "SKIPPED (no existing cve_feed.json)"
fi

echo -n "[*] Injecting cve_feed.simulated.json...     "
cp -f "${CVE_FEED_SIMULATED}" "${CVE_FEED}"
echo "OK"

# ---------------------------------------------------------------------------
# 3. Run the pipeline in test mode -- PIPELINE_TEST=1 makes Task 4 use
#    apt-get --dry-run, so nothing is actually installed by this test.
# ---------------------------------------------------------------------------
echo "[*] Running pipeline (PIPELINE_TEST=1)..."

PIPELINE_TEST=1 bash "${PIPELINE_SCRIPT}" &
PIPELINE_PID=$!
wait "${PIPELINE_PID}"
PIPELINE_RC=$?

# ---------------------------------------------------------------------------
# 5. Validate pipeline_run.json: status ok/deferred, every stage has a
#    non-empty artifact.
# ---------------------------------------------------------------------------
STAGES_OK=false
PIPELINE_STATUS="unknown"
MISSING_ARTIFACTS=()

if [[ -f "${PIPELINE_RUN_FILE}" ]]; then
    PIPELINE_STATUS="$(jq -r '.pipeline_status // "unknown"' "${PIPELINE_RUN_FILE}")"

    if [[ "${PIPELINE_STATUS}" == "ok" || "${PIPELINE_STATUS}" == "deferred" ]]; then
        STAGES_OK=true
        while IFS= read -r artifact_path; do
            [[ -n "${artifact_path}" ]] || continue
            full_path="${SCRIPT_DIR}/${artifact_path}"
            if [[ ! -s "${full_path}" ]]; then
                STAGES_OK=false
                MISSING_ARTIFACTS+=("${artifact_path}")
            fi
        done < <(jq -r '.artifacts | to_entries[] | .value' "${PIPELINE_RUN_FILE}" 2>/dev/null)
    fi
fi

# ---------------------------------------------------------------------------
# 4. Compare patch_plan.json to patch_plan.expected.json, timestamps
#    normalized to a placeholder before diffing.
# ---------------------------------------------------------------------------
normalize_plan() {
    # Any field literally named *_at, plus the top-level generated_at, is
    # replaced with a fixed placeholder so a real timestamp never causes a
    # false mismatch. Key order is also sorted (-S) for a stable diff.
    jq -S '
      def normalize:
        if type == "object" then
          with_entries(
            if (.key | test("_at$")) or .key == "generated_at" then .value = "TIMESTAMP"
            else .value |= normalize end
          )
        elif type == "array" then map(normalize)
        else . end;
      normalize
    ' "$1" 2>/dev/null
}

PLAN_MATCHES=false
DIFF_LINES='[]'
COMPARE_NOTE=""

if [[ ! -f "${PLAN_FILE}" ]]; then
    COMPARE_NOTE="patch_plan.json was not produced by this run"
    echo "[*] Comparing patch_plan.json to expected...  ${COMPARE_NOTE}"
elif [[ ! -f "${PLAN_EXPECTED}" ]]; then
    # Bootstrap: no baseline exists yet. Create one from this run and
    # treat this specific run as a pass (there is nothing to diverge from).
    normalize_plan "${PLAN_FILE}" > "${PLAN_EXPECTED}"
    PLAN_MATCHES=true
    COMPARE_NOTE="no patch_plan.expected.json existed -- bootstrapped from this run"
    echo "[*] Comparing patch_plan.json to expected...  bootstrapped (no prior baseline)"
else
    NORM_ACTUAL="$(mktemp)"
    NORM_EXPECTED="$(mktemp)"
    normalize_plan "${PLAN_FILE}" > "${NORM_ACTUAL}"
    normalize_plan "${PLAN_EXPECTED}" > "${NORM_EXPECTED}"

    if diff -q "${NORM_EXPECTED}" "${NORM_ACTUAL}" > /dev/null 2>&1; then
        PLAN_MATCHES=true
        echo "[*] Comparing patch_plan.json to expected...  match"
    else
        PLAN_MATCHES=false
        DIFF_LINES="$(diff -u --label "expected" --label "actual" "${NORM_EXPECTED}" "${NORM_ACTUAL}" 2>/dev/null | jq -Rsc 'split("\n") | map(select(length > 0))')"
        echo "[*] Comparing patch_plan.json to expected...  MISMATCH"
    fi
    rm -f "${NORM_ACTUAL}" "${NORM_EXPECTED}"
fi

# ---------------------------------------------------------------------------
# 6. Restore the original cve_feed.json
# ---------------------------------------------------------------------------
echo -n "[*] Restoring cve_feed.json...                "
restore_feed
echo "OK"

# ---------------------------------------------------------------------------
# 7. Verdict + emit pipeline_test_results.json
# ---------------------------------------------------------------------------
VERDICT="fail"
if [[ "${PIPELINE_RC}" -eq 0 && "${STAGES_OK}" == "true" && "${PLAN_MATCHES}" == "true" ]]; then
    VERDICT="pass"
fi

FINISHED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
MISSING_JSON="$(printf '%s\n' "${MISSING_ARTIFACTS[@]:-}" | jq -Rsc 'split("\n")|map(select(length>0))')"

jq -n \
  --arg scenario "simulated CVE advisory" \
  --arg started_at "${STARTED_AT}" \
  --arg finished_at "${FINISHED_AT}" \
  --argjson stages_ok "${STAGES_OK}" \
  --arg pipeline_status "${PIPELINE_STATUS}" \
  --argjson missing_artifacts "${MISSING_JSON}" \
  --argjson plan_matches_expected "${PLAN_MATCHES}" \
  --arg compare_note "${COMPARE_NOTE}" \
  --argjson diff "${DIFF_LINES}" \
  --arg verdict "${VERDICT}" \
  '{
     scenario: $scenario,
     started_at: $started_at,
     finished_at: $finished_at,
     stages_ok: $stages_ok,
     pipeline_status: $pipeline_status,
     missing_artifacts: $missing_artifacts,
     plan_matches_expected: $plan_matches_expected,
     compare_note: (if $compare_note == "" then null else $compare_note end),
     diff: $diff,
     verdict: $verdict
   }' > "${OUTPUT_FILE}"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "pipeline_test_results.json is invalid JSON"

echo "VERDICT: ${VERDICT}"
echo "Report saved to: pipeline_test_results.json"

[[ "${VERDICT}" == "pass" ]] && exit 0
exit 1