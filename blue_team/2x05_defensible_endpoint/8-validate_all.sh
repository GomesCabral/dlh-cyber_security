#!/usr/bin/bash
# Evaluate every control in capstone/target_state.json and emit one
# machine-readable end-to-end validation report.
#
# Usage: ./8-validate_all.sh [capstone_dir]
# Exit 0 only when fail_count and error_count are both zero.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
CAPSTONE_DIR="${1:-$SCRIPT_DIR/capstone}"
TARGET_STATE="${TARGET_STATE:-$CAPSTONE_DIR/target_state.json}"
# Required machine-readable artifact: capstone/validation.json
REPORT_FILE="${VALIDATION_REPORT:-$CAPSTONE_DIR/validation.json}"

fatal() { printf '[validate] ERROR: %s\n' "$1" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || fatal "required command not found: jq"
command -v grep >/dev/null 2>&1 || fatal "required command not found: grep"
[[ -f "$TARGET_STATE" ]] || fatal "target state not found: $TARGET_STATE"
jq empty "$TARGET_STATE" 2>/dev/null || fatal "target state is not valid JSON: $TARGET_STATE"
jq -e '.controls | type == "array" and length > 0' "$TARGET_STATE" >/dev/null \
  || fatal "target_state.controls must be a non-empty array"
mkdir -p "$(dirname -- "$REPORT_FILE")" || fatal "cannot create report directory"

# Resolve the exact artifact used as evidence. Absolute paths remain absolute.
# Relative paths are tried as written, relative to this repository, and in the
# capstone/network artifact directory used by Task 7.
resolve_path() {
  local requested="$1" candidate
  if [[ "$requested" == /* ]]; then
    printf '%s\n' "$requested"
    return
  fi
  for candidate in \
    "$requested" \
    "$SCRIPT_DIR/$requested" \
    "$CAPSTONE_DIR/${requested#capstone/}" \
    "$CAPSTONE_DIR/network/$requested"; do
    [[ -e "$candidate" ]] && { printf '%s\n' "$candidate"; return; }
  done
  # Return a deterministic unresolved path for useful failure evidence.
  printf '%s\n' "$SCRIPT_DIR/$requested"
}

RESULTS='[]'

append_result() {
  local control="$1" verdict="$2" evidence="$3" actual_json="$4" message="$5"
  local result
  result="$(jq -n \
    --argjson control "$control" \
    --arg verdict "$verdict" \
    --arg evidence "$evidence" \
    --argjson actual "$actual_json" \
    --arg message "$message" \
    '{id:($control.id // "unknown"),
      platform:($control.platform // "unknown"),
      family:($control.family // "unknown"),
      check_type:($control.check_type // "unknown"),
      check_target:($control.check_target // ""),
      expected_value:$control.expected_value,
      verdict:$verdict,evidence:$evidence,actual_value:$actual,message:$message}')" \
    || fatal "could not build result JSON"
  RESULTS="$(jq --argjson result "$result" '. + [$result]' <<<"$RESULTS")" \
    || fatal "could not append validation result"
}

validate_control() {
  local control="$1"
  local check_type target expected_json verdict evidence actual_json message
  check_type="$(jq -r '.check_type // ""' <<<"$control")"
  target="$(jq -r '.check_target // ""' <<<"$control")"
  expected_json="$(jq -c '.expected_value' <<<"$control")"
  verdict='error'; evidence="$target"; actual_json='null'; message=''

  if [[ -z "$check_type" || -z "$target" ]]; then
    append_result "$control" error "$target" null "missing check_type or check_target"
    return
  fi

  case "$check_type" in
    file_exists)
      local file_path
      file_path="$(resolve_path "$target")"
      evidence="$file_path"
      if [[ -e "$file_path" ]]; then
        verdict='pass'; actual_json='true'; message='path exists'
      else
        verdict='fail'; actual_json='false'; message='path does not exist'
      fi
      ;;

    json_field_equals|json_field_gte)
      local json_target json_file jq_expression jq_stderr actual_value jq_rc
      if [[ "$target" != *'#'* ]]; then
        append_result "$control" error "$target" null "JSON target must use file.json#jq_expression"
        return
      fi
      json_target="${target%%#*}"
      jq_expression="${target#*#}"
      json_file="$(resolve_path "$json_target")"
      evidence="$json_file#$jq_expression"
      if [[ ! -f "$json_file" ]]; then
        append_result "$control" error "$evidence" null "JSON evidence file not found"
        return
      fi
      if ! jq empty "$json_file" 2>/dev/null; then
        append_result "$control" error "$evidence" null "evidence file is invalid JSON"
        return
      fi

      jq_stderr="$(mktemp)"
      actual_value="$(jq -c "$jq_expression" "$json_file" 2>"$jq_stderr")"
      jq_rc=$?
      if [[ "$jq_rc" -ne 0 ]]; then
        message="jq evaluation error: $(tr '\n' ' ' <"$jq_stderr")"
        rm -f "$jq_stderr"
        append_result "$control" error "$evidence" null "$message"
        return
      fi
      rm -f "$jq_stderr"
      # More than one result cannot be compared as one field value.
      if [[ "$(printf '%s\n' "$actual_value" | wc -l)" -ne 1 || -z "$actual_value" ]]; then
        append_result "$control" error "$evidence" null "jq expression did not return exactly one value"
        return
      fi
      actual_json="$actual_value"

      if [[ "$check_type" == 'json_field_equals' ]]; then
        if jq -n -e --argjson actual "$actual_json" --argjson expected "$expected_json" \
          '$actual == $expected' >/dev/null; then
          verdict='pass'; message='JSON value equals expected value'
        else
          verdict='fail'; message='JSON value does not equal expected value'
        fi
      else
        if ! jq -n -e --argjson actual "$actual_json" --argjson expected "$expected_json" \
          '($actual|type)=="number" and ($expected|type)=="number"' >/dev/null; then
          append_result "$control" error "$evidence" "$actual_json" "json_field_gte requires numeric actual and expected values"
          return
        fi
        if jq -n -e --argjson actual "$actual_json" --argjson expected "$expected_json" \
          '$actual >= $expected' >/dev/null; then
          verdict='pass'; message='JSON numeric value meets minimum'
        else
          verdict='fail'; message='JSON numeric value is below minimum'
        fi
      fi
      ;;

    command_exit_zero)
      local command_output command_rc
      evidence="$target"
      command_output="$(bash -o pipefail -c "$target" 2>&1)"
      command_rc=$?
      actual_json="$command_rc"
      if [[ "$command_rc" -eq 0 ]]; then
        verdict='pass'; message="command exited 0"
      elif [[ "$command_rc" -eq 126 || "$command_rc" -eq 127 ]]; then
        verdict='error'; message="command could not run (exit $command_rc): $command_output"
      else
        verdict='fail'; message="command exited $command_rc: $command_output"
      fi
      ;;

    grep_match)
      local grep_file pattern grep_output grep_rc
      grep_file="$(resolve_path "$target")"
      pattern="$(jq -r '.expected_value | if type == "string" then . else tojson end' <<<"$control")"
      evidence="grep -E -- $(printf '%q' "$pattern") $(printf '%q' "$grep_file")"
      if [[ ! -f "$grep_file" ]]; then
        append_result "$control" error "$evidence" null "grep evidence file not found"
        return
      fi
      grep_output="$(grep -E -- "$pattern" "$grep_file" 2>&1)"
      grep_rc=$?
      case "$grep_rc" in
        0)
          verdict='pass'
          actual_json="$(jq -Rn --arg match "$(printf '%s\n' "$grep_output" | head -n 1)" '$match')"
          message='extended regular expression matched'
          ;;
        1) verdict='fail'; actual_json='null'; message='extended regular expression did not match' ;;
        *) verdict='error'; actual_json='null'; message="grep error: $grep_output" ;;
      esac
      ;;

    *)
      append_result "$control" error "$target" null "unsupported check_type: $check_type"
      return
      ;;
  esac

  append_result "$control" "$verdict" "$evidence" "$actual_json" "$message"
}

# Base64 transport prevents shell word splitting and preserves each complete
# control object, including quoted jq expressions and commands.
while IFS= read -r encoded_control; do
  [[ -z "$encoded_control" ]] && continue
  validate_control "$(printf '%s' "$encoded_control" | base64 --decode)"
done < <(jq -r '.controls[] | @base64' "$TARGET_STATE")

TOTAL_CONTROLS="$(jq 'length' <<<"$RESULTS")"
PASS_COUNT="$(jq '[.[] | select(.verdict == "pass")] | length' <<<"$RESULTS")"
FAIL_COUNT="$(jq '[.[] | select(.verdict == "fail")] | length' <<<"$RESULTS")"
ERROR_COUNT="$(jq '[.[] | select(.verdict == "error")] | length' <<<"$RESULTS")"
PASS_PERCENTAGE="$(jq -n --argjson passed "$PASS_COUNT" --argjson total "$TOTAL_CONTROLS" \
  'if $total == 0 then 0 else (($passed * 10000 / $total) | round) / 100 end')"

FAMILY_TOTALS="$(jq '
  sort_by(.family) | group_by(.family) | map({
    family: .[0].family,
    total: length,
    pass: ([.[] | select(.verdict == "pass")] | length),
    fail: ([.[] | select(.verdict == "fail")] | length),
    error: ([.[] | select(.verdict == "error")] | length)
  })' <<<"$RESULTS")" || fatal "could not aggregate control families"

OVERALL_VERDICT='fail'
[[ "$FAIL_COUNT" -eq 0 && "$ERROR_COUNT" -eq 0 ]] && OVERALL_VERDICT='pass'

jq -n \
  --arg schema_version '1.0' \
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
  --argjson controls "$RESULTS" \
  '{schema_version:$schema_version,generated_at:$generated_at,hostname:$hostname,
    target_state:$target_state,verdict:$verdict,total_controls:$total_controls,
    pass_count:$pass_count,fail_count:$fail_count,error_count:$error_count,
    pass_percentage:$pass_percentage,family_totals:$family_totals,controls:$controls}' \
  >"$REPORT_FILE" || fatal "could not write $REPORT_FILE"

# The only stdout output is the requested clean family summary table.
printf '%-20s %7s %7s %7s %7s\n' 'FAMILY' 'TOTAL' 'PASS' 'FAIL' 'ERROR'
printf '%-20s %7s %7s %7s %7s\n' '--------------------' '-------' '-------' '-------' '-------'
jq -r '.[] | [.family,.total,.pass,.fail,.error] | @tsv' <<<"$FAMILY_TOTALS" |
while IFS=$'\t' read -r family total passed failed errors; do
  printf '%-20s %7d %7d %7d %7d\n' "$family" "$total" "$passed" "$failed" "$errors"
done

if [[ "$FAIL_COUNT" -eq 0 && "$ERROR_COUNT" -eq 0 ]]; then
  exit 0
fi
exit 1