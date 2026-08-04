#!/bin/bash

# MedDefense Health Systems - Production Hardening Orchestrator
#
# Runs the complete MedDefense Linux hardening workflow in dependency order.
#
# The orchestrator:
# - validates all prerequisites before making changes;
# - captures the security baseline;
# - records the pre-hardening Lynis score;
# - executes each hardening control in dependency order;
# - stops immediately when a step fails;
# - records timing and exit codes;
# - executes final validation;
# - captures the post-hardening Lynis score;
# - calculates the measurable security delta;
# - produces machine-readable JSON evidence.
#
# Threat context:
# The Crimson Tide response requires repeatable and measurable hardening.
# A server rebuilt after compromise must be capable of reaching the same
# hardened state through automation rather than manual configuration.
#
# Idempotency:
# This orchestrator depends on every underlying hardening script being
# idempotent. Re-running the workflow must preserve the same desired state.

set -euo pipefail

export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RUN_REPORT="${SCRIPT_DIR}/hardening_run.json"
IMPROVEMENT_REPORT="${SCRIPT_DIR}/hardening_improvement.json"

LYNIS_REPORT="/var/log/lynis-report.dat"

PRE_LYNIS_JSON="${SCRIPT_DIR}/lynis_before.json"
POST_LYNIS_JSON="${SCRIPT_DIR}/lynis_after.json"

TEMP_RESULTS="$(mktemp)"
RUN_START_EPOCH="$(date +%s)"
RUN_START_ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

STEPS_COMPLETED=0
STEPS_FAILED=0
CURRENT_STEP=""
FINALIZED=0

# ---------------------------------------------------------------------------
# Required workflow scripts
# ---------------------------------------------------------------------------

REQUIRED_SCRIPTS=(
    "0-baseline_snapshot.sh"
    "2-lynis_parse.sh"
    "4-ssh_hardening.sh"
    "5-sysctl_hardening.sh"
    "6-filesystem_hardening.sh"
    "7-service_minimization.sh"
    "8-pam_hardening.sh"
    "9-apparmor_config.sh"
    "10-auditd_config.sh"
    "11-audit_coverage_test.sh"
    "12-log_config.sh"
    "13-firewall_baseline.sh"
    "15-validation.sh"
)

# Exactly 13 workflow steps are required by the project.
TOTAL_STEPS="${#REQUIRED_SCRIPTS[@]}"

cleanup() {
    rm -f "$TEMP_RESULTS"
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Root requirement
# ---------------------------------------------------------------------------

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: run this script with sudo." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helper: write final hardening_run.json
# ---------------------------------------------------------------------------

write_run_report() {
    local final_status="$1"

    if [[ "$FINALIZED" -eq 1 ]]; then
        return
    fi

    FINALIZED=1

    local run_end_epoch
    local run_end_iso
    local duration

    run_end_epoch="$(date +%s)"
    run_end_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    duration=$((run_end_epoch - RUN_START_EPOCH))

    python3 - \
        "$TEMP_RESULTS" \
        "$RUN_REPORT" \
        "$RUN_START_ISO" \
        "$run_end_iso" \
        "$duration" \
        "$final_status" \
        "$TOTAL_STEPS" \
        "$STEPS_COMPLETED" \
        "$STEPS_FAILED" <<'PYTHON'
import json
import sys
from pathlib import Path

(
    result_path,
    output_path,
    started,
    ended,
    duration,
    final_status,
    total_steps,
    completed,
    failed,
) = sys.argv[1:]

steps = []

path = Path(result_path)

if path.exists():
    for line in path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        if line.strip():
            steps.append(json.loads(line))

report = {
    "workflow": "MedDefense Production Hardening",
    "started_at_utc": started,
    "finished_at_utc": ended,
    "duration_seconds": int(duration),
    "status": final_status,
    "steps_scheduled": int(total_steps),
    "steps_completed": int(completed),
    "steps_failed": int(failed),
    "steps": steps,
}

Path(output_path).write_text(
    json.dumps(report, indent=2) + "\n",
    encoding="utf-8",
)
PYTHON
}

# ---------------------------------------------------------------------------
# Helper: record one workflow step
# ---------------------------------------------------------------------------

record_step() {
    local position="$1"
    local script_name="$2"
    local description="$3"
    local started="$4"
    local ended="$5"
    local duration="$6"
    local exit_code="$7"
    local status="$8"

    python3 - \
        "$position" \
        "$script_name" \
        "$description" \
        "$started" \
        "$ended" \
        "$duration" \
        "$exit_code" \
        "$status" >> "$TEMP_RESULTS" <<'PYTHON'
import json
import sys

(
    position,
    script_name,
    description,
    started,
    ended,
    duration,
    exit_code,
    status,
) = sys.argv[1:]

record = {
    "step": int(position),
    "script": script_name,
    "description": description,
    "started_at_utc": started,
    "finished_at_utc": ended,
    "duration_seconds": int(duration),
    "exit_code": int(exit_code),
    "status": status,
}

print(json.dumps(record))
PYTHON
}

# ---------------------------------------------------------------------------
# Helper: execute a normal script and stop immediately on failure
# ---------------------------------------------------------------------------

run_script_step() {
    local position="$1"
    local script_name="$2"
    local description="$3"

    local start_epoch
    local end_epoch
    local start_iso
    local end_iso
    local duration
    local exit_code

    CURRENT_STEP="$script_name"

    echo
    echo "[${position}/${TOTAL_STEPS}] ${description}"
    echo "    Script: ${script_name}"

    start_epoch="$(date +%s)"
    start_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    if "${SCRIPT_DIR}/${script_name}"; then
        exit_code=0
    else
        exit_code=$?
    fi

    end_epoch="$(date +%s)"
    end_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    duration=$((end_epoch - start_epoch))

    if [[ "$exit_code" -eq 0 ]]; then
        STEPS_COMPLETED=$((STEPS_COMPLETED + 1))

        record_step \
            "$position" \
            "$script_name" \
            "$description" \
            "$start_iso" \
            "$end_iso" \
            "$duration" \
            "$exit_code" \
            "success"

        echo "    Result: PASS (${duration}s)"
    else
        STEPS_FAILED=$((STEPS_FAILED + 1))

        record_step \
            "$position" \
            "$script_name" \
            "$description" \
            "$start_iso" \
            "$end_iso" \
            "$duration" \
            "$exit_code" \
            "failed"

        echo "    Result: FAIL (exit ${exit_code})" >&2
        echo "    Workflow stopped at: ${script_name}" >&2

        write_run_report "failed"

        echo "Run log saved to: $(basename "$RUN_REPORT")" >&2

        exit "$exit_code"
    fi
}

# ---------------------------------------------------------------------------
# Helper: execute Lynis audit and parser as workflow step 2
# ---------------------------------------------------------------------------

run_lynis_baseline_step() {
    local position="2"
    local script_name="2-lynis_parse.sh"
    local description="Capture pre-hardening Lynis baseline"

    local start_epoch
    local end_epoch
    local start_iso
    local end_iso
    local duration
    local exit_code=0

    CURRENT_STEP="$script_name"

    echo
    echo "[${position}/${TOTAL_STEPS}] ${description}"
    echo "    Running Lynis system audit..."

    start_epoch="$(date +%s)"
    start_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    if ! lynis audit system --quick >/dev/null 2>&1; then
        exit_code=$?
    fi

    if [[ "$exit_code" -eq 0 ]]; then
        if ! "${SCRIPT_DIR}/2-lynis_parse.sh" \
            "$LYNIS_REPORT" \
            > "${SCRIPT_DIR}/lynis_findings.json"; then

            exit_code=$?
        fi
    fi

    if [[ "$exit_code" -eq 0 ]]; then
        cp "${SCRIPT_DIR}/lynis_findings.json" "$PRE_LYNIS_JSON"
    fi

    end_epoch="$(date +%s)"
    end_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    duration=$((end_epoch - start_epoch))

    if [[ "$exit_code" -eq 0 ]]; then
        STEPS_COMPLETED=$((STEPS_COMPLETED + 1))

        record_step \
            "$position" \
            "$script_name" \
            "$description" \
            "$start_iso" \
            "$end_iso" \
            "$duration" \
            "0" \
            "success"

        PRE_SCORE="$(jq -r '.hardening_index' "$PRE_LYNIS_JSON")"

        echo "    Lynis score: ${PRE_SCORE}"
        echo "    Result: PASS (${duration}s)"
    else
        STEPS_FAILED=$((STEPS_FAILED + 1))

        record_step \
            "$position" \
            "$script_name" \
            "$description" \
            "$start_iso" \
            "$end_iso" \
            "$duration" \
            "$exit_code" \
            "failed"

        write_run_report "failed"

        echo "Error: Lynis baseline capture failed." >&2
        exit "$exit_code"
    fi
}

# ---------------------------------------------------------------------------
# Pre-checks
# ---------------------------------------------------------------------------

echo "[*] Running pre-checks..."

PRECHECK_FAILURES=0

for script_name in "${REQUIRED_SCRIPTS[@]}"; do
    script_path="${SCRIPT_DIR}/${script_name}"

    if [[ ! -f "$script_path" ]]; then
        echo "    Missing: ${script_name}" >&2
        PRECHECK_FAILURES=$((PRECHECK_FAILURES + 1))
        continue
    fi

    if [[ ! -x "$script_path" ]]; then
        echo "    Not executable: ${script_name}" >&2
        PRECHECK_FAILURES=$((PRECHECK_FAILURES + 1))
    fi
done

for command_name in lynis jq python3; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "    Missing command: ${command_name}" >&2
        PRECHECK_FAILURES=$((PRECHECK_FAILURES + 1))
    fi
done

if (( PRECHECK_FAILURES > 0 )); then
    echo "Pre-checks: FAIL (${PRECHECK_FAILURES} issue(s))" >&2
    echo "No hardening changes were started." >&2
    exit 1
fi

echo "Pre-checks: PASS"
echo "Steps scheduled: ${TOTAL_STEPS}"

# ---------------------------------------------------------------------------
# Step 1 - Baseline snapshot
# ---------------------------------------------------------------------------

run_script_step \
    "1" \
    "0-baseline_snapshot.sh" \
    "Capture system security baseline"

# ---------------------------------------------------------------------------
# Step 2 - Pre-hardening Lynis assessment
# ---------------------------------------------------------------------------

PRE_SCORE=0

run_lynis_baseline_step

# ---------------------------------------------------------------------------
# Steps 3-12 - Security hardening
# ---------------------------------------------------------------------------

run_script_step \
    "3" \
    "4-ssh_hardening.sh" \
    "Apply SSH lockdown"

run_script_step \
    "4" \
    "5-sysctl_hardening.sh" \
    "Apply kernel and sysctl hardening"

run_script_step \
    "5" \
    "6-filesystem_hardening.sh" \
    "Apply filesystem permission hardening"

run_script_step \
    "6" \
    "7-service_minimization.sh" \
    "Minimize enabled services"

run_script_step \
    "7" \
    "8-pam_hardening.sh" \
    "Apply PAM authentication hardening"

run_script_step \
    "8" \
    "9-apparmor_config.sh" \
    "Apply AppArmor confinement"

run_script_step \
    "9" \
    "10-auditd_config.sh" \
    "Deploy audit telemetry rules"

run_script_step \
    "10" \
    "11-audit_coverage_test.sh" \
    "Validate audit telemetry coverage"

run_script_step \
    "11" \
    "12-log_config.sh" \
    "Configure logging and retention"

run_script_step \
    "12" \
    "13-firewall_baseline.sh" \
    "Apply host firewall baseline"

# ---------------------------------------------------------------------------
# Post-hardening Lynis assessment
#
# This is evidence collection rather than another scheduled remediation step.
# ---------------------------------------------------------------------------

echo
echo "[*] Capturing post-hardening Lynis score..."

if ! lynis audit system --quick >/dev/null 2>&1; then
    echo "Error: post-hardening Lynis audit failed." >&2
    write_run_report "failed"
    exit 1
fi

if ! "${SCRIPT_DIR}/2-lynis_parse.sh" \
    "$LYNIS_REPORT" \
    > "${SCRIPT_DIR}/lynis_findings.json"; then

    echo "Error: post-hardening Lynis parsing failed." >&2
    write_run_report "failed"
    exit 1
fi

cp "${SCRIPT_DIR}/lynis_findings.json" "$POST_LYNIS_JSON"

POST_SCORE="$(jq -r '.hardening_index' "$POST_LYNIS_JSON")"

if [[ ! "$PRE_SCORE" =~ ^[0-9]+$ ]]; then
    echo "Error: invalid pre-hardening Lynis score." >&2
    exit 1
fi

if [[ ! "$POST_SCORE" =~ ^[0-9]+$ ]]; then
    echo "Error: invalid post-hardening Lynis score." >&2
    exit 1
fi

DELTA=$((POST_SCORE - PRE_SCORE))

# ---------------------------------------------------------------------------
# Generate measurable improvement evidence
# ---------------------------------------------------------------------------

python3 - \
    "$IMPROVEMENT_REPORT" \
    "$PRE_SCORE" \
    "$POST_SCORE" \
    "$DELTA" \
    "$PRE_LYNIS_JSON" \
    "$POST_LYNIS_JSON" <<'PYTHON'
import json
import sys
from pathlib import Path

(
    output_path,
    before_score,
    after_score,
    delta,
    before_report,
    after_report,
) = sys.argv[1:]

before_score = int(before_score)
after_score = int(after_score)
delta = int(delta)

if delta > 0:
    assessment = "improved"
elif delta == 0:
    assessment = "unchanged"
else:
    assessment = "decreased"

report = {
    "metric": "Lynis hardening index",
    "before_score": before_score,
    "after_score": after_score,
    "delta": delta,
    "assessment": assessment,
    "before_evidence": Path(before_report).name,
    "after_evidence": Path(after_report).name,
}

Path(output_path).write_text(
    json.dumps(report, indent=2) + "\n",
    encoding="utf-8",
)
PYTHON

# ---------------------------------------------------------------------------
# Step 13 - Final validation
# ---------------------------------------------------------------------------

run_script_step \
    "13" \
    "15-validation.sh" \
    "Run final hardening validation"

# ---------------------------------------------------------------------------
# Finalize workflow evidence
# ---------------------------------------------------------------------------

write_run_report "success"

echo
echo "Steps completed: ${STEPS_COMPLETED}"
echo "Steps failed: ${STEPS_FAILED}"
echo "Before Lynis score: ${PRE_SCORE}"
echo "After Lynis score: ${POST_SCORE}"

if (( DELTA >= 0 )); then
    echo "Delta: +${DELTA}"
else
    echo "Delta: ${DELTA}"
fi

echo "Run log saved to: $(basename "$RUN_REPORT")"
echo "Improvement saved to: $(basename "$IMPROVEMENT_REPORT")"
