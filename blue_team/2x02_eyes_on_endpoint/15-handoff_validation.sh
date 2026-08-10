#!/bin/bash

# name: 15-handoff_validation.sh
# purpose: Validate the final telemetry handoff package against operational quality gates before analyst consumption.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 15 - Handoff Validation
#
# Validation checks:
# - file existence
# - JSON validity
# - required fields
# - minimum event counts
# - timestamp consistency
# - cross-platform alignment
# - ground truth completeness
# - detection matrix correlation
#
# Output:
# - handoff_validation.json
#
# Safety:
# READ-ONLY with respect to telemetry and detection matrices.
# Writes only handoff_validation.json.

set -euo pipefail

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1
    pwd -P
)"

HANDOFF_DIR="${SCRIPT_DIR}/telemetry_handoff"

WINDOWS_FILE="${HANDOFF_DIR}/windows_events.json"
LINUX_FILE="${HANDOFF_DIR}/linux_events.json"
GROUND_TRUTH_FILE="${HANDOFF_DIR}/attack_ground_truth.json"

WINDOWS_MATRIX="${SCRIPT_DIR}/windows_detection_matrix.json"
LINUX_MATRIX="${SCRIPT_DIR}/linux_detection_matrix.json"

OUTPUT_FILE="${SCRIPT_DIR}/handoff_validation.json"

MIN_WINDOWS=1000
MIN_LINUX=500
MIN_GROUND_TRUTH=10

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

CHECKS_FILE="${TMP_DIR}/checks.jsonl"
: > "${CHECKS_FILE}"

PASS_COUNT=0
FAIL_COUNT=0

require_command() {
    local command_name="$1"

    if ! command -v "${command_name}" >/dev/null 2>&1; then
        printf '[FAIL] Required command not found: %s\n' "${command_name}"
        exit 1
    fi
}

require_command jq
require_command date
require_command stat
require_command awk

record_check() {
    local category="$1"
    local check_name="$2"
    local status="$3"
    local message="$4"

    if [[ "${status}" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        printf '[PASS] %s\n' "${message}"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        printf '[FAIL] %s\n' "${message}"
    fi

    jq -cn \
        --arg category "${category}" \
        --arg check "${check_name}" \
        --arg status "${status}" \
        --arg message "${message}" \
        '{
            category: $category,
            check: $check,
            status: $status,
            message: $message
        }' >> "${CHECKS_FILE}"
}

human_size() {
    local file="$1"
    local bytes

    bytes="$(stat -c '%s' "${file}")"

    awk -v bytes="${bytes}" '
        BEGIN {
            if (bytes >= 1073741824)
                printf "%.1f GB", bytes / 1073741824
            else if (bytes >= 1048576)
                printf "%.1f MB", bytes / 1048576
            else if (bytes >= 1024)
                printf "%.1f KB", bytes / 1024
            else
                printf "%d B", bytes
        }
    '
}

event_count() {
    jq '
        if (.events? | type) == "array"
        then .events | length
        elif type == "array"
        then length
        else 0
        end
    ' "$1"
}

ground_truth_count() {
    jq '
        if (.actions? | type) == "array"
        then .actions | length
        else 0
        end
    ' "$1"
}

printf '[*] Validating telemetry_handoff/ ...\n'

# =============================================================================
# File Existence
# =============================================================================

printf '=== File Existence ===\n'

FILES_EXIST=true

for entry in \
    "windows_events.json|${WINDOWS_FILE}" \
    "linux_events.json|${LINUX_FILE}" \
    "attack_ground_truth.json|${GROUND_TRUTH_FILE}"
do
    name="${entry%%|*}"
    file="${entry#*|}"

    if [[ -f "${file}" ]]; then
        size="$(human_size "${file}")"
        record_check \
            "File Existence" \
            "${name}_exists" \
            "PASS" \
            "${name} exists (${size})"
    else
        FILES_EXIST=false
        record_check \
            "File Existence" \
            "${name}_exists" \
            "FAIL" \
            "${name} is missing"
    fi
done

if [[ "${FILES_EXIST}" != true ]]; then
    WINDOWS_COUNT=0
    LINUX_COUNT=0
    GROUND_TRUTH_COUNT=0
else
    WINDOWS_COUNT="$(event_count "${WINDOWS_FILE}")"
    LINUX_COUNT="$(event_count "${LINUX_FILE}")"
    GROUND_TRUTH_COUNT="$(ground_truth_count "${GROUND_TRUTH_FILE}")"
fi

# =============================================================================
# JSON Validity
# =============================================================================

printf '=== JSON Validity ===\n'

WINDOWS_JSON_VALID=false
LINUX_JSON_VALID=false
GROUND_TRUTH_JSON_VALID=false

validate_json() {
    local name="$1"
    local file="$2"
    local kind="$3"

    if [[ ! -f "${file}" ]]; then
        record_check \
            "JSON Validity" \
            "${name}_json" \
            "FAIL" \
            "${name}: cannot validate because file is missing"
        return
    fi

    if jq empty "${file}" >/dev/null 2>&1; then
        local count

        if [[ "${kind}" == "events" ]]; then
            count="$(event_count "${file}")"
        else
            count="$(ground_truth_count "${file}")"
        fi

        record_check \
            "JSON Validity" \
            "${name}_json" \
            "PASS" \
            "${name}: valid JSON, ${count} objects"

        case "${name}" in
            windows_events.json) WINDOWS_JSON_VALID=true ;;
            linux_events.json) LINUX_JSON_VALID=true ;;
            attack_ground_truth.json) GROUND_TRUTH_JSON_VALID=true ;;
        esac
    else
        record_check \
            "JSON Validity" \
            "${name}_json" \
            "FAIL" \
            "${name}: invalid JSON"
    fi
}

validate_json "windows_events.json" "${WINDOWS_FILE}" "events"
validate_json "linux_events.json" "${LINUX_FILE}" "events"
validate_json "attack_ground_truth.json" "${GROUND_TRUTH_FILE}" "actions"

if [[ "${WINDOWS_JSON_VALID}" == true ]]; then
    WINDOWS_COUNT="$(event_count "${WINDOWS_FILE}")"
fi

if [[ "${LINUX_JSON_VALID}" == true ]]; then
    LINUX_COUNT="$(event_count "${LINUX_FILE}")"
fi

if [[ "${GROUND_TRUTH_JSON_VALID}" == true ]]; then
    GROUND_TRUTH_COUNT="$(ground_truth_count "${GROUND_TRUTH_FILE}")"
fi

# =============================================================================
# Required Fields
# =============================================================================

printf '=== Required Fields ===\n'

if [[ "${WINDOWS_JSON_VALID}" == true && "${LINUX_JSON_VALID}" == true ]]; then

    WINDOWS_MISSING="$(
        jq '
            [
                .events[]
                | select(
                    (.timestamp // "") == ""
                    or (.hostname // "") == ""
                    or (.source_type // "") == ""
                    or (.event_category // "") == ""
                )
            ]
            | length
        ' "${WINDOWS_FILE}"
    )"

    LINUX_MISSING="$(
        jq '
            [
                .events[]
                | select(
                    (.timestamp // "") == ""
                    or (.hostname // "") == ""
                    or (.source_type // "") == ""
                    or (.event_category // "") == ""
                )
            ]
            | length
        ' "${LINUX_FILE}"
    )"

    if [[ "${WINDOWS_MISSING}" -eq 0 && "${LINUX_MISSING}" -eq 0 ]]; then
        record_check \
            "Required Fields" \
            "required_event_fields" \
            "PASS" \
            "All events have timestamp, hostname, source_type, event_category"
    else
        record_check \
            "Required Fields" \
            "required_event_fields" \
            "FAIL" \
            "Missing required fields: Windows=${WINDOWS_MISSING}, Linux=${LINUX_MISSING}"
    fi
else
    record_check \
        "Required Fields" \
        "required_event_fields" \
        "FAIL" \
        "Required fields cannot be validated because telemetry JSON is invalid"
fi

# =============================================================================
# Minimum Event Counts
# =============================================================================

printf '=== Minimum Event Counts ===\n'

if [[ "${WINDOWS_JSON_VALID}" == true && "${WINDOWS_COUNT}" -ge "${MIN_WINDOWS}" ]]; then
    record_check \
        "Minimum Event Counts" \
        "windows_minimum" \
        "PASS" \
        "Windows: ${WINDOWS_COUNT} >= ${MIN_WINDOWS}"
else
    record_check \
        "Minimum Event Counts" \
        "windows_minimum" \
        "FAIL" \
        "Windows: ${WINDOWS_COUNT} < ${MIN_WINDOWS}"
fi

if [[ "${LINUX_JSON_VALID}" == true && "${LINUX_COUNT}" -ge "${MIN_LINUX}" ]]; then
    record_check \
        "Minimum Event Counts" \
        "linux_minimum" \
        "PASS" \
        "Linux: ${LINUX_COUNT} >= ${MIN_LINUX}"
else
    record_check \
        "Minimum Event Counts" \
        "linux_minimum" \
        "FAIL" \
        "Linux: ${LINUX_COUNT} < ${MIN_LINUX}"
fi

if [[ "${GROUND_TRUTH_JSON_VALID}" == true && "${GROUND_TRUTH_COUNT}" -ge "${MIN_GROUND_TRUTH}" ]]; then
    record_check \
        "Minimum Event Counts" \
        "ground_truth_minimum" \
        "PASS" \
        "Ground truth: ${GROUND_TRUTH_COUNT} >= ${MIN_GROUND_TRUTH}"
else
    record_check \
        "Minimum Event Counts" \
        "ground_truth_minimum" \
        "FAIL" \
        "Ground truth: ${GROUND_TRUTH_COUNT} < ${MIN_GROUND_TRUTH}"
fi

# =============================================================================
# Timestamp Consistency
# =============================================================================

printf '=== Timestamp Consistency ===\n'

TIMESTAMPS_VALID=false
NO_FUTURE=false

if [[ "${WINDOWS_JSON_VALID}" == true && "${LINUX_JSON_VALID}" == true ]]; then

    ISO_REGEX='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$'

    WINDOWS_BAD_TS="$(
        jq --arg regex "${ISO_REGEX}" '
            [
                .events[]
                | .timestamp
                | select(
                    type != "string"
                    or (test($regex) | not)
                )
            ]
            | length
        ' "${WINDOWS_FILE}"
    )"

    LINUX_BAD_TS="$(
        jq --arg regex "${ISO_REGEX}" '
            [
                .events[]
                | .timestamp
                | select(
                    type != "string"
                    or (test($regex) | not)
                )
            ]
            | length
        ' "${LINUX_FILE}"
    )"

    if [[ "${WINDOWS_BAD_TS}" -eq 0 && "${LINUX_BAD_TS}" -eq 0 ]]; then
        TIMESTAMPS_VALID=true
        record_check \
            "Timestamp Consistency" \
            "iso8601" \
            "PASS" \
            "All timestamps valid ISO 8601"
    else
        record_check \
            "Timestamp Consistency" \
            "iso8601" \
            "FAIL" \
            "Invalid ISO 8601 timestamps: Windows=${WINDOWS_BAD_TS}, Linux=${LINUX_BAD_TS}"
    fi

    if [[ "${TIMESTAMPS_VALID}" == true ]]; then

        NOW_EPOCH="$(date -u '+%s')"

        WINDOWS_FUTURE="$(
            jq -r '.events[].timestamp' "${WINDOWS_FILE}" |
            while IFS= read -r ts; do
                epoch="$(date -u -d "${ts}" '+%s' 2>/dev/null || printf '99999999999')"
                if [[ "${epoch}" -gt "${NOW_EPOCH}" ]]; then
                    printf '1\n'
                fi
            done |
            awk '{sum += $1} END {print sum + 0}'
        )"

        LINUX_FUTURE="$(
            jq -r '.events[].timestamp' "${LINUX_FILE}" |
            while IFS= read -r ts; do
                epoch="$(date -u -d "${ts}" '+%s' 2>/dev/null || printf '99999999999')"
                if [[ "${epoch}" -gt "${NOW_EPOCH}" ]]; then
                    printf '1\n'
                fi
            done |
            awk '{sum += $1} END {print sum + 0}'
        )"

        if [[ "${WINDOWS_FUTURE}" -eq 0 && "${LINUX_FUTURE}" -eq 0 ]]; then
            NO_FUTURE=true
            record_check \
                "Timestamp Consistency" \
                "no_future_timestamps" \
                "PASS" \
                "No future timestamps"
        else
            record_check \
                "Timestamp Consistency" \
                "no_future_timestamps" \
                "FAIL" \
                "Future timestamps found: Windows=${WINDOWS_FUTURE}, Linux=${LINUX_FUTURE}"
        fi

        WINDOWS_START="$(jq -r '[.events[].timestamp] | min' "${WINDOWS_FILE}")"
        WINDOWS_END="$(jq -r '[.events[].timestamp] | max' "${WINDOWS_FILE}")"
        LINUX_START="$(jq -r '[.events[].timestamp] | min' "${LINUX_FILE}")"
        LINUX_END="$(jq -r '[.events[].timestamp] | max' "${LINUX_FILE}")"

        GLOBAL_START="$(
            printf '%s\n%s\n' "${WINDOWS_START}" "${LINUX_START}" |
            sort |
            head -n 1
        )"

        GLOBAL_END="$(
            printf '%s\n%s\n' "${WINDOWS_END}" "${LINUX_END}" |
            sort |
            tail -n 1
        )"

        record_check \
            "Timestamp Consistency" \
            "reasonable_range" \
            "PASS" \
            "Range: ${GLOBAL_START} to ${GLOBAL_END}"

    else
        record_check \
            "Timestamp Consistency" \
            "no_future_timestamps" \
            "FAIL" \
            "Future timestamp check skipped because timestamp format is invalid"

        record_check \
            "Timestamp Consistency" \
            "reasonable_range" \
            "FAIL" \
            "Timestamp range cannot be reliably calculated"
    fi

else
    record_check \
        "Timestamp Consistency" \
        "iso8601" \
        "FAIL" \
        "Timestamp consistency cannot be validated because telemetry JSON is invalid"

    record_check \
        "Timestamp Consistency" \
        "no_future_timestamps" \
        "FAIL" \
        "Future timestamp check cannot be performed"

    record_check \
        "Timestamp Consistency" \
        "reasonable_range" \
        "FAIL" \
        "Timestamp range cannot be calculated"
fi

# =============================================================================
# Cross-Platform Alignment
# =============================================================================

printf '=== Cross-Platform Alignment ===\n'

OVERLAP_SECONDS=0

if [[ "${TIMESTAMPS_VALID}" == true ]]; then

    WINDOWS_START_EPOCH="$(date -u -d "${WINDOWS_START}" '+%s')"
    WINDOWS_END_EPOCH="$(date -u -d "${WINDOWS_END}" '+%s')"
    LINUX_START_EPOCH="$(date -u -d "${LINUX_START}" '+%s')"
    LINUX_END_EPOCH="$(date -u -d "${LINUX_END}" '+%s')"

    if [[ "${WINDOWS_START_EPOCH}" -gt "${LINUX_START_EPOCH}" ]]; then
        OVERLAP_START="${WINDOWS_START_EPOCH}"
    else
        OVERLAP_START="${LINUX_START_EPOCH}"
    fi

    if [[ "${WINDOWS_END_EPOCH}" -lt "${LINUX_END_EPOCH}" ]]; then
        OVERLAP_END="${WINDOWS_END_EPOCH}"
    else
        OVERLAP_END="${LINUX_END_EPOCH}"
    fi

    OVERLAP_SECONDS=$((OVERLAP_END - OVERLAP_START))

    if [[ "${OVERLAP_SECONDS}" -gt 0 ]]; then
        OVERLAP_HOURS="$(
            awk -v seconds="${OVERLAP_SECONDS}" \
                'BEGIN {printf "%.2f", seconds / 3600}'
        )"

        record_check \
            "Cross-Platform Alignment" \
            "timestamp_overlap" \
            "PASS" \
            "Windows and Linux time ranges overlap (${OVERLAP_HOURS} hours shared)"
    else
        record_check \
            "Cross-Platform Alignment" \
            "timestamp_overlap" \
            "FAIL" \
            "Windows and Linux time ranges do not overlap"
    fi
else
    record_check \
        "Cross-Platform Alignment" \
        "timestamp_overlap" \
        "FAIL" \
        "Cross-platform alignment cannot be calculated because timestamps are invalid"
fi

# =============================================================================
# Ground Truth Completeness
# =============================================================================

printf '=== Ground Truth Completeness ===\n'

if [[ ! -f "${WINDOWS_MATRIX}" || ! -f "${LINUX_MATRIX}" ]]; then
    record_check \
        "Ground Truth Completeness" \
        "detection_matrix_entries" \
        "FAIL" \
        "Detection matrix file missing"
elif ! jq empty "${WINDOWS_MATRIX}" >/dev/null 2>&1 ||
     ! jq empty "${LINUX_MATRIX}" >/dev/null 2>&1; then
    record_check \
        "Ground Truth Completeness" \
        "detection_matrix_entries" \
        "FAIL" \
        "One or more detection matrix files contain invalid JSON"
elif [[ "${GROUND_TRUTH_JSON_VALID}" != true ]]; then
    record_check \
        "Ground Truth Completeness" \
        "detection_matrix_entries" \
        "FAIL" \
        "Ground truth cannot be correlated because JSON is invalid"
else

    WINDOWS_GT_COUNT="$(
        jq '
            [
                .actions[]
                | select((.platform // "") == "Windows")
            ]
            | length
        ' "${GROUND_TRUTH_FILE}"
    )"

    LINUX_GT_COUNT="$(
        jq '
            [
                .actions[]
                | select((.platform // "") == "Linux")
            ]
            | length
        ' "${GROUND_TRUTH_FILE}"
    )"

    WINDOWS_MATRIX_COUNT="$(
        jq '
            [
                (.detections // [])[]
                | (.action_number // .action // empty)
            ]
            | unique
            | length
        ' "${WINDOWS_MATRIX}"
    )"

    LINUX_MATRIX_COUNT="$(
        jq '
            [
                (.detections // [])[]
                | (.action_number // .action // empty)
            ]
            | unique
            | length
        ' "${LINUX_MATRIX}"
    )"

    MATCHED=$((WINDOWS_MATRIX_COUNT + LINUX_MATRIX_COUNT))

    if [[ "${WINDOWS_MATRIX_COUNT}" -ge "${WINDOWS_GT_COUNT}" &&
          "${LINUX_MATRIX_COUNT}" -ge "${LINUX_GT_COUNT}" &&
          "${MATCHED}" -ge "${GROUND_TRUTH_COUNT}" ]]; then

        record_check \
            "Ground Truth Completeness" \
            "detection_matrix_entries" \
            "PASS" \
            "${GROUND_TRUTH_COUNT}/${GROUND_TRUTH_COUNT} actions have detection matrix entries"
    else
        record_check \
            "Ground Truth Completeness" \
            "detection_matrix_entries" \
            "FAIL" \
            "${MATCHED}/${GROUND_TRUTH_COUNT} actions have detection matrix entries"
    fi
fi

# =============================================================================
# Final Verdict
# =============================================================================

TOTAL_CHECKS=$((PASS_COUNT + FAIL_COUNT))

if [[ "${FAIL_COUNT}" -eq 0 ]]; then
    VERDICT="PASS"
else
    VERDICT="FAIL"
fi

if [[ -s "${CHECKS_FILE}" ]]; then
    CHECKS_JSON="$(jq -s '.' "${CHECKS_FILE}")"
else
    CHECKS_JSON='[]'
fi

jq -n \
    --arg generated_at_utc "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg verdict "${VERDICT}" \
    --argjson total_checks "${TOTAL_CHECKS}" \
    --argjson passed_checks "${PASS_COUNT}" \
    --argjson failed_checks "${FAIL_COUNT}" \
    --argjson windows_events "${WINDOWS_COUNT}" \
    --argjson linux_events "${LINUX_COUNT}" \
    --argjson ground_truth_actions "${GROUND_TRUTH_COUNT}" \
    --argjson checks "${CHECKS_JSON}" \
    '{
        metadata: {
            report: "2x02 Eyes on Endpoint - Handoff Validation",
            generated_at_utc: $generated_at_utc,
            handoff_directory: "telemetry_handoff/"
        },
        summary: {
            verdict: $verdict,
            total_checks: $total_checks,
            passed_checks: $passed_checks,
            failed_checks: $failed_checks,
            windows_events: $windows_events,
            linux_events: $linux_events,
            ground_truth_actions: $ground_truth_actions
        },
        checks: $checks
    }' > "${OUTPUT_FILE}"

printf 'VERDICT: %s (%s/%s checks)\n' \
    "${VERDICT}" \
    "${PASS_COUNT}" \
    "${TOTAL_CHECKS}"

if [[ "${VERDICT}" == "PASS" ]]; then
    printf 'Handoff package is ready for Module 3.\n'
else
    printf 'Handoff package is NOT ready for Module 3. Review failed checks.\n'
fi

printf 'Report saved to: handoff_validation.json\n'

if [[ "${VERDICT}" == "PASS" ]]; then
    exit 0
else
    exit 1
fi