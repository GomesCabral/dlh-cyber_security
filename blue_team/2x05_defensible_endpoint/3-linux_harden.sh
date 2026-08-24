#!/bin/bash
#
# 3-linux_harden.sh
#
# Orchestrates the Linux hardening pass against hawthorne-app-01. This
# script does not reinvent hardening logic -- it composes the existing
# hardening scripts in a deterministic order, captures every sub-step as
# structured evidence, and measures the result against the Linux controls
# already declared in capstone/target_state.json (task 2). A missing or
# corrupted target_state.json is fatal, per that contract.
#
# IMPORTANT: the *_SCRIPT defaults below point at this repo's test
# fixtures (test_fixtures/hardening/*.sh), used to validate this
# orchestrator end-to-end. Before running against the real Hawthorne
# server, override each with the actual hardening script from the 2x00
# (Linux hardening) project, e.g.:
#   SSH_SCRIPT=/path/to/real/ssh_harden.sh ./3-linux_harden.sh
#
# Usage:
#   sudo ./3-linux_harden.sh [capstone_dir]
#
# Exit codes:
#   0 - every sub-step exited 0 AND lynis_after >= target hardening index
#   1 - orchestration completed but the pass criterion above was not met
#   2 - environment error (not root, missing target_state.json/control,
#       missing lynis/jq, cannot write output)
#
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
CAPSTONE_DIR="${1:-$SCRIPT_DIR/capstone}"
EXEC_DIR="$CAPSTONE_DIR/exec"
LOG_FILE="$EXEC_DIR/linux_harden.log"
OUTPUT_JSON="$EXEC_DIR/linux_harden.json"
TARGET_STATE_JSON="$CAPSTONE_DIR/target_state.json"
BASELINE_JSON="$CAPSTONE_DIR/baseline/baseline_linux.json"
LYNIS_REPORT_DAT="${LYNIS_REPORT_DAT:-/var/log/lynis-report.dat}"

# Sub-step script paths -- see the IMPORTANT note above.
SSH_SCRIPT="${SSH_SCRIPT:-$SCRIPT_DIR/test_fixtures/hardening/ssh_harden.sh}"
SYSCTL_SCRIPT="${SYSCTL_SCRIPT:-$SCRIPT_DIR/test_fixtures/hardening/sysctl_harden.sh}"
PERMISSION_SCRIPT="${PERMISSION_SCRIPT:-$SCRIPT_DIR/test_fixtures/hardening/permission_sweep.sh}"
SERVICE_SCRIPT="${SERVICE_SCRIPT:-$SCRIPT_DIR/test_fixtures/hardening/service_minimization.sh}"
PAM_SCRIPT="${PAM_SCRIPT:-$SCRIPT_DIR/test_fixtures/hardening/pam_configuration.sh}"
APPARMOR_SCRIPT="${APPARMOR_SCRIPT:-$SCRIPT_DIR/test_fixtures/hardening/apparmor_enforce.sh}"
AUDITD_SCRIPT="${AUDITD_SCRIPT:-$SCRIPT_DIR/test_fixtures/hardening/auditd_deploy.sh}"

die() { printf '[linux_harden] ERROR: %s\n' "$1" >&2; case "${2:-2}" in 1) exit 1 ;; *) exit 2 ;; esac; }
log() { printf '[linux_harden] %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "this script must be run as root (sudo ./3-linux_harden.sh)"

for cmd in jq hostname date lynis; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
done

# Per task 2's own documented contract: a missing or corrupted
# target_state.json is fatal for every downstream script.
[[ -f "$TARGET_STATE_JSON" ]] || die "target_state.json not found at $TARGET_STATE_JSON -- run 2-target_state.sh first"
jq empty "$TARGET_STATE_JSON" 2>/dev/null || die "target_state.json at $TARGET_STATE_JSON is corrupted (invalid JSON)"

TARGET_HARDENING_INDEX="$(jq -r '.controls[] | select(.id=="LNX-LYNIS-01") | .expected_value' "$TARGET_STATE_JSON")"
[[ -n "$TARGET_HARDENING_INDEX" && "$TARGET_HARDENING_INDEX" != "null" ]] \
  || die "target_state.json does not declare control LNX-LYNIS-01 (Lynis hardening index target)"

[[ -f "$BASELINE_JSON" ]] || die "$BASELINE_JSON not found -- run 1-baseline_snapshot.sh first"
LYNIS_BEFORE="$(jq -r '.hardening_index // "null"' "$BASELINE_JSON")"
[[ "$LYNIS_BEFORE" != "null" ]] || die "$BASELINE_JSON has no hardening_index; run 1-baseline_snapshot.sh first"

mkdir -p "$EXEC_DIR" || die "failed to create $EXEC_DIR"
[[ -w "$EXEC_DIR" ]] || die "$EXEC_DIR is not writable"

: > "$LOG_FILE"
RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  echo "===== 3-linux_harden.sh run started: $RUN_STARTED_AT ====="
  echo "target hardening index (LNX-LYNIS-01): $TARGET_HARDENING_INDEX"
  echo "lynis_before (from baseline_linux.json): $LYNIS_BEFORE"
  echo
} >> "$LOG_FILE"

# ---------------------------------------------------------------------------
# Per-step target-state control mapping (documented, static). Steps with no
# currently-declared control in target_state.json map to an empty list --
# that is expected for permission_sweep/service_minimization/pam_configuration
# today, not a bug; extend target_state.json's controls if that changes.
# ---------------------------------------------------------------------------
declare -A CONTROLS_MAP=(
  [ssh_hardening]="LNX-SSH-01 LNX-SSH-02"
  [sysctl_hardening]="LNX-SYSCTL-01 LNX-SYSCTL-02"
  [permission_sweep]=""
  [service_minimization]=""
  [pam_configuration]=""
  [apparmor_enforcement]="LNX-APPARMOR-01"
  [auditd_deployment]="LNX-AUDITD-01 LNX-AUDITD-02 LNX-AUDITD-03"
)

STEP_NAMES=()
STEP_SCRIPTS=()
STEP_EXIT_CODES=()
STEP_DURATIONS=()
STEP_CHANGED=()
ALL_STEPS_OK=1

# ---------------------------------------------------------------------------
# Wrapper: runs one sub-step, times it, appends its full stdout+stderr and
# exit code to LOG_FILE, and records structured evidence for the JSON.
# "changed" is derived from a documented sub-step contract: a step prints
# a line starting with "CHANGED:" to stdout for each modification it made;
# no such line means the step found the system already compliant.
# ---------------------------------------------------------------------------
run_step() {
  local name="$1" script="$2"
  local start end duration exit_code changed step_log

  step_log="$(mktemp)"
  {
    echo "===== STEP: $name ====="
    echo "script_path: $script"
    echo "started_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >> "$LOG_FILE"

  start="$(date +%s.%N)"
  if [[ -f "$script" ]]; then
    bash "$script" > "$step_log" 2>&1
    exit_code=$?
  else
    echo "sub-step script not found: $script" > "$step_log"
    exit_code=127
  fi
  end="$(date +%s.%N)"
  duration="$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.3f", b-a}')"

  cat "$step_log" >> "$LOG_FILE"
  {
    echo "exit_code: $exit_code"
    echo "duration_seconds: $duration"
    echo
  } >> "$LOG_FILE"

  changed=false
  grep -q '^CHANGED:' "$step_log" && changed=true

  STEP_NAMES+=("$name")
  STEP_SCRIPTS+=("$script")
  STEP_EXIT_CODES+=("$exit_code")
  STEP_DURATIONS+=("$duration")
  STEP_CHANGED+=("$changed")

  rm -f "$step_log"

  [[ "$exit_code" -eq 0 ]] || ALL_STEPS_OK=0
  log "step '$name' exit=$exit_code duration=${duration}s changed=$changed"
}

# ---------------------------------------------------------------------------
# Run the composition in deterministic order: SSH hardening, sysctl
# hardening, permission sweep, service minimization, PAM configuration,
# AppArmor enforcement, auditd deployment.
# ---------------------------------------------------------------------------
run_step "ssh_hardening"        "$SSH_SCRIPT"
run_step "sysctl_hardening"     "$SYSCTL_SCRIPT"
run_step "permission_sweep"     "$PERMISSION_SCRIPT"
run_step "service_minimization" "$SERVICE_SCRIPT"
run_step "pam_configuration"    "$PAM_SCRIPT"
run_step "apparmor_enforcement" "$APPARMOR_SCRIPT"
run_step "auditd_deployment"    "$AUDITD_SCRIPT"

# ---------------------------------------------------------------------------
# Re-run lynis and capture the new Hardening Index (same primary/fallback
# parsing strategy as 1-baseline_snapshot.sh: report.dat first, regex on
# the captured log as a fallback).
# ---------------------------------------------------------------------------
log "Re-running lynis audit system --no-colors (this can take a minute)..."
{
  echo "===== STEP: lynis_reaudit ====="
  echo "started_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >> "$LOG_FILE"

LYNIS_REAUDIT_LOG="$(mktemp)"
lynis audit system --no-colors > "$LYNIS_REAUDIT_LOG" 2>&1
LYNIS_EXIT=$?
{
  cat "$LYNIS_REAUDIT_LOG"
  echo "exit_code: $LYNIS_EXIT"
  echo
} >> "$LOG_FILE"

LYNIS_AFTER=""
if [[ -r "$LYNIS_REPORT_DAT" ]]; then
  LYNIS_AFTER="$(grep -m1 '^hardening_index=' "$LYNIS_REPORT_DAT" | cut -d= -f2)"
fi
if [[ -z "$LYNIS_AFTER" ]]; then
  LYNIS_AFTER="$(grep -m1 -oE 'Hardening index[[:space:]]*:[[:space:]]*[0-9]+' "$LYNIS_REAUDIT_LOG" | grep -oE '[0-9]+$')"
fi
rm -f "$LYNIS_REAUDIT_LOG"

if [[ -z "$LYNIS_AFTER" ]]; then
  die "could not parse hardening index from the post-hardening lynis run" 2
fi

INDEX_DELTA="$((LYNIS_AFTER - LYNIS_BEFORE))"

log "lynis_before=$LYNIS_BEFORE lynis_after=$LYNIS_AFTER index_delta=$INDEX_DELTA target=$TARGET_HARDENING_INDEX"

# ---------------------------------------------------------------------------
# Assemble controls_touched (deduplicated union across all steps) and the
# steps array, then write linux_harden.json.
# ---------------------------------------------------------------------------
ALL_CONTROLS_TOUCHED="$(printf '%s\n' "${CONTROLS_MAP[@]}" | tr ' ' '\n' | sed '/^$/d' | sort -u)"
ALL_CONTROLS_TOUCHED_JSON="$(printf '%s\n' "$ALL_CONTROLS_TOUCHED" | jq -R . | jq -s 'map(select(length > 0))')"

STEPS_JSON="[]"
for i in "${!STEP_NAMES[@]}"; do
  name="${STEP_NAMES[$i]}"
  step_controls="${CONTROLS_MAP[$name]:-}"
  step_controls_json="$(printf '%s\n' "$step_controls" | tr ' ' '\n' | sed '/^$/d' | jq -R . | jq -s '.')"
  entry="$(jq -n \
    --arg name "$name" \
    --arg script_path "${STEP_SCRIPTS[$i]}" \
    --argjson exit_code "${STEP_EXIT_CODES[$i]}" \
    --argjson duration_seconds "${STEP_DURATIONS[$i]}" \
    --argjson changed "${STEP_CHANGED[$i]}" \
    --argjson controls_touched "$step_controls_json" \
    '{name: $name, script_path: $script_path, exit_code: $exit_code, duration_seconds: $duration_seconds, changed: $changed, controls_touched: $controls_touched}')"
  STEPS_JSON="$(echo "$STEPS_JSON" | jq --argjson e "$entry" '. + [$e]')"
done

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME_VAL="$(hostname)"

jq -n \
  --arg timestamp "$TIMESTAMP" \
  --arg hostname "$HOSTNAME_VAL" \
  --argjson steps "$STEPS_JSON" \
  --argjson lynis_before "$LYNIS_BEFORE" \
  --argjson lynis_after "$LYNIS_AFTER" \
  --argjson index_delta "$INDEX_DELTA" \
  --argjson controls_touched "$ALL_CONTROLS_TOUCHED_JSON" \
  '{
    timestamp: $timestamp,
    hostname: $hostname,
    steps: $steps,
    lynis_before: $lynis_before,
    lynis_after: $lynis_after,
    index_delta: $index_delta,
    controls_touched: $controls_touched
  }' > "$OUTPUT_JSON" || die "failed to write $OUTPUT_JSON"

log "Wrote $OUTPUT_JSON"
log "Full step log at $LOG_FILE"

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
if [[ "$ALL_STEPS_OK" -eq 1 && "$LYNIS_AFTER" -ge "$TARGET_HARDENING_INDEX" ]]; then
  log "PASS: all steps succeeded and lynis_after ($LYNIS_AFTER) >= target ($TARGET_HARDENING_INDEX)"
  exit 0
else
  log "FAIL: all_steps_ok=$ALL_STEPS_OK lynis_after=$LYNIS_AFTER target=$TARGET_HARDENING_INDEX"
  exit 1
fi