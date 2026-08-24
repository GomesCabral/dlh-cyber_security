#!/usr/bin/env bash
#
# 8-validate_all.sh
#
# The single command Dr. Morales wants to run. No human judgment, no
# narrative, no partial credit: reads capstone/target_state.json, walks
# every control, performs exactly the check that control specifies, and
# produces one machine-readable verdict. This script does not re-run any
# hardening/telemetry/patch/network logic itself -- it is a dispatcher
# that reads the evidence T3 through T7 already produced (per the task's
# own hint) and reports what it finds, nothing more.
#
# Usage:
#   ./8-validate_all.sh [capstone_dir]
#
# Exit codes:
#   0 - fail_count == 0 AND error_count == 0 (environment is ready)
#   1 - at least one control failed or errored
#   2 - environment error (missing/corrupted target_state.json, missing
#       required command, cannot write output)
#
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
CAPSTONE_DIR="${1:-$SCRIPT_DIR/capstone}"
TARGET_STATE="${TARGET_STATE:-$CAPSTONE_DIR/target_state.json}"
# Writes: capstone/validation.json
REPORT_FILE="${VALIDATION_REPORT:-$CAPSTONE_DIR/validation.json}"

fatal() { printf '[validate] ERROR: %s\n' "$1" >&2; exit 2; }

command -v jq   >/dev/null 2>&1 || fatal "required command not found: jq"
command -v grep >/dev/null 2>&1 || fatal "required command not found: grep"

# Per task 2's own documented contract: a missing or corrupted
# target_state.json is fatal for every downstream script -- there is no
# meaningful pass/fail verdict without it.
[[ -f "$TARGET_STATE" ]] || fatal "target_state.json not found at $TARGET_STATE -- run 2-target_state.sh first"
jq empty "$TARGET_STATE" 2>/dev/null || fatal "target_state.json at $TARGET_STATE is corrupted (invalid JSON)"
jq -e '.controls | type == "array" and length > 0' "$TARGET_STATE" >/dev/null 2>&1 \
  || fatal "target_state.json has no non-empty controls array"

mkdir -p "$CAPSTONE_DIR" || fatal "cannot create $CAPSTONE_DIR"
[[ -w "$CAPSTONE_DIR" ]] || fatal "$CAPSTONE_DIR is not writable"

# ---------------------------------------------------------------------------
# Resolve a check_target path to an actual filesystem location. Absolute
# paths (starting with /) are used exactly as written -- e.g. /etc/... file
# checks for command_exit_zero/grep_match controls. Relative paths (how
# most JSON-evidence check_targets are written, e.g.
# "capstone/baseline/baseline_linux.json") are tried in order: as given
# relative to the current directory, relative to this script's own
# directory, and relative to the capstone directory -- covering every
# convention used across target_state.json's controls without guessing
# which one a given control author used.
# ---------------------------------------------------------------------------
resolve_path() {
  local requested="$1" candidate
  if [[ "$requested" == /* ]]; then
    printf '%s\n' "$requested"
    return
  fi
  for candidate in \
    "$requested" \
    "$SCRIPT_DIR/$requested" \
    "$CAPSTONE_DIR/$requested" \
    "$CAPSTONE_DIR/${requested#capstone/}"; do
    [[ -e "$candidate" ]] && { printf '%s\n' "$candidate"; return; }
  done
  # Nothing matched -- return the most informative unresolved path so a
  # failed control's evidence field still shows where this script looked.
  printf '%s\n' "$SCRIPT_DIR/$requested"
}

RESULTS_JSONL="$(mktemp)"
trap 'rm -f "$RESULTS_JSONL"' EXIT

append_result() {
  # $1 = control object (compact JSON), $2 = verdict, $3 = evidence,
  # $4 = actual_value (compact JSON, may be "null"), $5 = message
  jq -nc \
    --argjson control "$1" \
    --arg verdict "$2" \
    --arg evidence "$3" \
    --argjson actual "$4" \
    --arg message "$5" \
    '{
      id: ($control.id // "unknown"),
      platform: ($control.platform // "unknown"),
      family: ($control.family // "unknown"),
      severity: ($control.severity // "unknown"),
      check_type: ($control.check_type // "unknown"),
      check_target: ($control.check_target // ""),
      expected_value: $control.expected_value,
      verdict: $verdict,
      evidence: $evidence,
      actual_value: $actual,
      message: $message
    }' >> "$RESULTS_JSONL"
}

# ---------------------------------------------------------------------------
# Dispatch on check_type. Exactly the five types the task specifies --
# this script does not invent new ones and does not re-run any of the
# underlying tools; it only reads the JSON/log/config artifacts already
# produced by T3 through T7 (and the raw system state for
# command_exit_zero/grep_match controls that check live configuration).
# ---------------------------------------------------------------------------
evaluate_control() {
  local control="$1"
  local check_type target expected_json
  check_type="$(jq -r '.check_type // ""' <<< "$control")"
  target="$(jq -r '.check_target // ""' <<< "$control")"
  expected_json="$(jq -c '.expected_value' <<< "$control")"

  if [[ -z "$check_type" || -z "$target" ]]; then
    append_result "$control" "error" "$target" "null" "missing check_type or check_target"
    return
  fi

  case "$check_type" in

    file_exists)
      local file_path
      file_path="$(resolve_path "$target")"
      if [[ -e "$file_path" ]]; then
        append_result "$control" "pass" "$file_path" "true" "path exists"
      else
        append_result "$control" "fail" "$file_path" "false" "path does not exist"
      fi
      ;;

    json_field_equals|json_field_gte)
      if [[ "$target" != *'#'* ]]; then
        append_result "$control" "error" "$target" "null" "check_target must be in the form file.json#jq_filter"
        return
      fi
      local json_target jq_filter json_file evidence
      json_target="${target%%#*}"
      jq_filter="${target#*#}"
      json_file="$(resolve_path "$json_target")"
      evidence="${json_file}#${jq_filter}"

      if [[ ! -f "$json_file" ]]; then
        append_result "$control" "error" "$evidence" "null" "evidence file not found: $json_file"
        return
      fi
      if ! jq empty "$json_file" 2>/dev/null; then
        append_result "$control" "error" "$evidence" "null" "evidence file is not valid JSON"
        return
      fi

      local actual_value jq_err jq_rc
      jq_err="$(mktemp)"
      actual_value="$(jq -c "$jq_filter" "$json_file" 2>"$jq_err")"
      jq_rc=$?
      if [[ "$jq_rc" -ne 0 ]]; then
        append_result "$control" "error" "$evidence" "null" "jq filter error: $(tr '\n' ' ' < "$jq_err")"
        rm -f "$jq_err"
        return
      fi
      rm -f "$jq_err"

      if [[ -z "$actual_value" || "$(wc -l <<< "$actual_value")" -ne 1 ]]; then
        append_result "$control" "error" "$evidence" "null" "jq filter did not return exactly one value"
        return
      fi

      if [[ "$check_type" == "json_field_equals" ]]; then
        if jq -ne --argjson a "$actual_value" --argjson e "$expected_json" '$a == $e' >/dev/null 2>&1; then
          append_result "$control" "pass" "$evidence" "$actual_value" "value equals expected"
        else
          append_result "$control" "fail" "$evidence" "$actual_value" "value does not equal expected"
        fi
      else
        if ! jq -ne --argjson a "$actual_value" '$a | type == "number"' >/dev/null 2>&1; then
          append_result "$control" "error" "$evidence" "$actual_value" "actual value is not numeric"
          return
        fi
        if jq -ne --argjson a "$actual_value" --argjson e "$expected_json" '$a >= $e' >/dev/null 2>&1; then
          append_result "$control" "pass" "$evidence" "$actual_value" "value meets minimum"
        else
          append_result "$control" "fail" "$evidence" "$actual_value" "value is below minimum"
        fi
      fi
      ;;

    command_exit_zero)
      local output exit_code
      output="$(bash -o pipefail -c "$target" 2>&1)"
      exit_code=$?
      if [[ "$exit_code" -eq 0 ]]; then
        append_result "$control" "pass" "$target" "$exit_code" "command exited 0"
      elif [[ "$exit_code" -eq 126 || "$exit_code" -eq 127 ]]; then
        append_result "$control" "error" "$target" "$exit_code" "command could not run: $(tr '\n' ' ' <<< "$output" | head -c 300)"
      else
        append_result "$control" "fail" "$target" "$exit_code" "command exited $exit_code: $(tr '\n' ' ' <<< "$output" | head -c 300)"
      fi
      ;;

    grep_match)
      local grep_file pattern evidence output rc
      grep_file="$(resolve_path "$target")"
      pattern="$(jq -r '.expected_value | if type == "string" then . else tojson end' <<< "$control")"
      evidence="grep -E $(printf '%q' "$pattern") $(printf '%q' "$grep_file")"

      if [[ ! -f "$grep_file" ]]; then
        append_result "$control" "error" "$evidence" "null" "file not found: $grep_file"
        return
      fi

      output="$(grep -E -- "$pattern" "$grep_file" 2>&1)"
      rc=$?
      case "$rc" in
        0)
          local first_match
          first_match="$(jq -Rn --arg m "$(head -1 <<< "$output")" '$m')"
          append_result "$control" "pass" "$evidence" "$first_match" "pattern matched"
          ;;
        1)
          append_result "$control" "fail" "$evidence" "null" "pattern did not match"
          ;;
        *)
          append_result "$control" "error" "$evidence" "null" "grep error: $output"
          ;;
      esac
      ;;

    *)
      append_result "$control" "error" "$target" "null" "unsupported check_type: $check_type"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Walk every control. Base64 transport avoids word-splitting/quoting
# problems from arbitrary characters in a control's jq filter or command.
# ---------------------------------------------------------------------------
while IFS= read -r encoded; do
  [[ -z "$encoded" ]] && continue
  evaluate_control "$(base64 --decode <<< "$encoded")"
done < <(jq -r '.controls[] | @base64' "$TARGET_STATE")

RESULTS_JSON="$(jq -s '.' "$RESULTS_JSONL")"

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------
TOTAL_CONTROLS="$(jq 'length' <<< "$RESULTS_JSON")"
PASS_COUNT="$(jq '[.[] | select(.verdict == "pass")] | length' <<< "$RESULTS_JSON")"
FAIL_COUNT="$(jq '[.[] | select(.verdict == "fail")] | length' <<< "$RESULTS_JSON")"
ERROR_COUNT="$(jq '[.[] | select(.verdict == "error")] | length' <<< "$RESULTS_JSON")"
PASS_PERCENTAGE="$(jq -n --argjson p "$PASS_COUNT" --argjson t "$TOTAL_CONTROLS" \
  'if $t == 0 then 0 else (($p * 10000 / $t) | round) / 100 end')"

FAMILY_TOTALS="$(jq '
  group_by(.family) | map({
    family: .[0].family,
    total: length,
    pass: ([.[] | select(.verdict == "pass")] | length),
    fail: ([.[] | select(.verdict == "fail")] | length),
    error: ([.[] | select(.verdict == "error")] | length)
  }) | sort_by(.family)
' <<< "$RESULTS_JSON")"

OVERALL_VERDICT="fail"
[[ "$FAIL_COUNT" -eq 0 && "$ERROR_COUNT" -eq 0 ]] && OVERALL_VERDICT="pass"

# ---------------------------------------------------------------------------
# Write capstone/validation.json
# ---------------------------------------------------------------------------
jq -n \
  --arg schema_version "1.0" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg hostname "$(hostname)" \
  --arg target_state "$TARGET_STATE" \
  --arg verdict "$OVERALL_VERDICT" \
  --argjson total_controls "$TOTAL_CONTROLS" \
  --argjson pass_count "$PASS_COUNT" \
  --argjson fail_count "$FAIL_COUNT" \
  --argjson error_count "$ERROR_COUNT" \
  --argjson pass_percentage "$PASS_PERCENTAGE" \
  --argjson family_totals "$FAMILY_TOTALS" \
  --argjson controls "$RESULTS_JSON" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    hostname: $hostname,
    target_state: $target_state,
    verdict: $verdict,
    total_controls: $total_controls,
    pass_count: $pass_count,
    fail_count: $fail_count,
    error_count: $error_count,
    pass_percentage: $pass_percentage,
    family_totals: $family_totals,
    controls: $controls
  }' > "$REPORT_FILE" || fatal "failed to write $REPORT_FILE"

# ---------------------------------------------------------------------------
# Print a clean family-grouped table to stdout. This is the only stdout
# output -- no narrative, matching the task's own framing
# ---------------------------------------------------------------------------
printf '%-14s %7s %7s %7s %7s\n' "FAMILY" "TOTAL" "PASS" "FAIL" "ERROR"
printf '%-14s %7s %7s %7s %7s\n' "--------------" "-------" "-------" "-------" "-------"
jq -r '.[] | [.family, .total, .pass, .fail, .error] | @tsv' <<< "$FAMILY_TOTALS" \
  | while IFS=$'\t' read -r family total pass fail error; do
      printf '%-14s %7d %7d %7d %7d\n' "$family" "$total" "$pass" "$fail" "$error"
    done
printf '%-14s %7s %7s %7s %7s\n' "--------------" "-------" "-------" "-------" "-------"
printf '%-14s %7d %7d %7d %7d\n' "TOTAL" "$TOTAL_CONTROLS" "$PASS_COUNT" "$FAIL_COUNT" "$ERROR_COUNT"
printf '\npass_percentage: %s%%   verdict: %s\n' "$PASS_PERCENTAGE" "$OVERALL_VERDICT"

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
if [[ "$FAIL_COUNT" -eq 0 && "$ERROR_COUNT" -eq 0 ]]; then
  exit 0
fi
exit 1
