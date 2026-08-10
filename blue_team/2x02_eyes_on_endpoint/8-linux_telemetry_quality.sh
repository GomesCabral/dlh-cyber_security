#!/bin/bash

# name: 8-linux_telemetry_quality.sh
# purpose: Assess Linux telemetry quality by measuring event distribution, time coverage, gaps, field completeness, and a weighted quality score.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 8 - Linux Telemetry Quality Gate
#
# Input:
# - linux_events_export.json
#
# Output:
# - linux_telemetry_quality.json
#
# Required quality dimensions:
#
# Event distribution
# - count per event category
# - count per source type
# - percentage of total
#
# Time coverage
# - events per hour
# - hours with events
# - hours without events
#
# Gap detection
# - any period longer than 30 minutes with no events
#
# Field completeness
# - timestamp
# - hostname
# - source_type
# - event_category
# - command line for execve
# - source IP/user for SSH events
# - path/operation/key for auditd file events
#
# Quality score
# - weighted score from 0-100
# - assessment: good, acceptable, poor
#
# JSON parsing:
# - jq
#
# Safety:
# READ-ONLY with respect to system telemetry.
# This script reads linux_events_export.json and writes a quality report only.

set -e
set -u
set -o pipefail

# =============================================================================
# Configuration
# =============================================================================

INPUT_FILE="linux_events_export.json"
OUTPUT_FILE="linux_telemetry_quality.json"

GAP_THRESHOLD_MINUTES=30

# Weighted score model
WEIGHT_COMMON_FIELDS=20
WEIGHT_EXECVE_COMMAND_LINE=20
WEIGHT_SSH_SOURCE_IP=15
WEIGHT_SSH_USER=10
WEIGHT_AUDIT_FILE=15
WEIGHT_TIME_COVERAGE=10
WEIGHT_GAP_CONTINUITY=10

TMP_DIR="$(mktemp -d)"

TIMESTAMPS_FILE="${TMP_DIR}/timestamps.txt"
GAPS_FILE="${TMP_DIR}/gaps.jsonl"
HOURLY_FILE="${TMP_DIR}/hourly.jsonl"

trap 'rm -rf "${TMP_DIR}"' EXIT

# =============================================================================
# Prerequisites
# =============================================================================

require_command() {
    local command_name="$1"

    if ! command -v "${command_name}" >/dev/null 2>&1; then
        printf '[FAIL] Required command not found: %s\n' \
            "${command_name}"
        exit 1
    fi
}

require_command jq
require_command date
require_command awk
require_command sort
require_command head
require_command tail

# =============================================================================
# Helper: percentage
# =============================================================================

percentage() {
    local part="$1"
    local total="$2"

    if [[ "${total}" -le 0 ]]; then
        printf '0.00'
        return
    fi

    awk \
        -v part="${part}" \
        -v total="${total}" \
        'BEGIN {
            printf "%.2f", (part / total) * 100
        }'
}

# =============================================================================
# Helper: assessment
# =============================================================================

get_assessment() {
    local score="$1"

    awk \
        -v score="${score}" \
        'BEGIN {
            if (score >= 85) {
                print "good"
            } else if (score >= 65) {
                print "acceptable"
            } else {
                print "poor"
            }
        }'
}

# =============================================================================
# Start
# =============================================================================

printf '\n'
printf '==============================================\n'
printf 'MedDefense Linux Telemetry Quality Gate\n'
printf '==============================================\n'
printf '\n'

printf '[*] Analyzing linux_events_export.json...\n'

# =============================================================================
# Validate Input
# =============================================================================

if [[ ! -f "${INPUT_FILE}" ]]; then

    printf '[FAIL] linux_events_export.json not found.\n'
    printf '       Run Task 7 first: sudo ./7-linux_export.sh\n'

    exit 1
fi

if ! jq empty "${INPUT_FILE}" >/dev/null 2>&1; then

    printf '[FAIL] linux_events_export.json is invalid JSON.\n'

    exit 1
fi

TOTAL_EVENTS="$(
    jq '.events | length' "${INPUT_FILE}"
)"

if [[ "${TOTAL_EVENTS}" -eq 0 ]]; then

    jq -n \
        '{
            total_events: 0,
            quality_score: {
                score: 0,
                assessment: "poor"
            },
            reason: "No telemetry events available"
        }' > "${OUTPUT_FILE}"

    printf 'Total events: 0\n'
    printf 'Quality score: 0%% (poor)\n'
    printf 'Report saved to: %s\n' "${OUTPUT_FILE}"

    exit 1
fi

# =============================================================================
# Event Distribution
# =============================================================================

printf '[*] Event Distribution...\n'

EVENT_CATEGORY_DISTRIBUTION="$(
    jq '
        .events
        | group_by(.event_category)
        | map({
            event_category: .[0].event_category,
            count: length
        })
    ' "${INPUT_FILE}"
)"

EVENT_CATEGORY_DISTRIBUTION="$(
    jq \
        --argjson total "${TOTAL_EVENTS}" \
        '
        map(
            . + {
                percentage_of_total:
                    (
                        if $total == 0
                        then 0
                        else ((.count / $total) * 100)
                        end
                    )
            }
        )
        ' <<< "${EVENT_CATEGORY_DISTRIBUTION}"
)"

SOURCE_TYPE_DISTRIBUTION="$(
    jq '
        .events
        | group_by(.source_type)
        | map({
            source_type: .[0].source_type,
            count: length
        })
    ' "${INPUT_FILE}"
)"

SOURCE_TYPE_DISTRIBUTION="$(
    jq \
        --argjson total "${TOTAL_EVENTS}" \
        '
        map(
            . + {
                percentage_of_total:
                    (
                        if $total == 0
                        then 0
                        else ((.count / $total) * 100)
                        end
                    )
            }
        )
        ' <<< "${SOURCE_TYPE_DISTRIBUTION}"
)"

# =============================================================================
# Time Coverage
# =============================================================================

printf '[*] Time Coverage...\n'
printf '    Calculating events per hour...\n'

WINDOW_START="$(
    jq -r '
        .metadata.StartTime
        // .metadata.start_time
        // .metadata.window_start
        // empty
    ' "${INPUT_FILE}"
)"

WINDOW_END="$(
    jq -r '
        .metadata.EndTime
        // .metadata.end_time
        // .metadata.window_end
        // empty
    ' "${INPUT_FILE}"
)"

if [[ -z "${WINDOW_START}" ]]; then

    WINDOW_START="$(
        jq -r \
            '[.events[].timestamp] | min' \
            "${INPUT_FILE}"
    )"
fi

if [[ -z "${WINDOW_END}" ]]; then

    WINDOW_END="$(
        jq -r \
            '[.events[].timestamp] | max' \
            "${INPUT_FILE}"
    )"
fi

WINDOW_START_EPOCH="$(
    date -u -d "${WINDOW_START}" '+%s'
)"

WINDOW_END_EPOCH="$(
    date -u -d "${WINDOW_END}" '+%s'
)"

# Round the first bucket down to the hour.
BUCKET_START_EPOCH="$(
    date -u \
        -d "${WINDOW_START}" \
        '+%s'
)"

BUCKET_START_EPOCH=$((BUCKET_START_EPOCH - (BUCKET_START_EPOCH % 3600)))

TOTAL_HOURS=0
HOURS_WITH_EVENTS=0
HOURS_WITHOUT_EVENTS=0

: > "${HOURLY_FILE}"

while [[ "${BUCKET_START_EPOCH}" -lt "${WINDOW_END_EPOCH}" ]]; do

    BUCKET_END_EPOCH=$((BUCKET_START_EPOCH + 3600))

    BUCKET_START_ISO="$(
        date -u \
            -d "@${BUCKET_START_EPOCH}" \
            '+%Y-%m-%dT%H:%M:%SZ'
    )"

    BUCKET_END_ISO="$(
        date -u \
            -d "@${BUCKET_END_EPOCH}" \
            '+%Y-%m-%dT%H:%M:%SZ'
    )"

    HOUR_COUNT="$(
        jq \
            --arg start "${BUCKET_START_ISO}" \
            --arg end "${BUCKET_END_ISO}" \
            '
            [
                .events[]
                | select(
                    .timestamp >= $start
                    and
                    .timestamp < $end
                )
            ]
            | length
            ' "${INPUT_FILE}"
    )"

    if [[ "${HOUR_COUNT}" -gt 0 ]]; then

        HAS_EVENTS=true
        HOURS_WITH_EVENTS=$((HOURS_WITH_EVENTS + 1))

    else

        HAS_EVENTS=false
        HOURS_WITHOUT_EVENTS=$((HOURS_WITHOUT_EVENTS + 1))
    fi

    TOTAL_HOURS=$((TOTAL_HOURS + 1))

    jq -cn \
        --arg hour_start "${BUCKET_START_ISO}" \
        --arg hour_end "${BUCKET_END_ISO}" \
        --argjson event_count "${HOUR_COUNT}" \
        --argjson has_events "${HAS_EVENTS}" \
        '{
            hour_start: $hour_start,
            hour_end: $hour_end,
            event_count: $event_count,
            has_events: $has_events
        }' >> "${HOURLY_FILE}"

    BUCKET_START_EPOCH="${BUCKET_END_EPOCH}"
done

TIME_COVERAGE_PERCENT="$(
    percentage \
        "${HOURS_WITH_EVENTS}" \
        "${TOTAL_HOURS}"
)"

# =============================================================================
# Gap Detection
# =============================================================================

printf '[*] Gap Detection...\n'

jq -r \
    '.events[].timestamp' \
    "${INPUT_FILE}" |
    sort > "${TIMESTAMPS_FILE}"

GAP_COUNT=0
LARGEST_GAP_MINUTES=0

: > "${GAPS_FILE}"

PREVIOUS_TIMESTAMP=""

while IFS= read -r CURRENT_TIMESTAMP; do

    if [[ -z "${PREVIOUS_TIMESTAMP}" ]]; then
        PREVIOUS_TIMESTAMP="${CURRENT_TIMESTAMP}"
        continue
    fi

    PREVIOUS_EPOCH="$(
        date -u -d "${PREVIOUS_TIMESTAMP}" '+%s'
    )"

    CURRENT_EPOCH="$(
        date -u -d "${CURRENT_TIMESTAMP}" '+%s'
    )"

    GAP_SECONDS=$((CURRENT_EPOCH - PREVIOUS_EPOCH))
    GAP_MINUTES=$((GAP_SECONDS / 60))

    if [[ "${GAP_MINUTES}" -gt "${LARGEST_GAP_MINUTES}" ]]; then
        LARGEST_GAP_MINUTES="${GAP_MINUTES}"
    fi

    if [[ "${GAP_MINUTES}" -gt "${GAP_THRESHOLD_MINUTES}" ]]; then

        GAP_COUNT=$((GAP_COUNT + 1))

        jq -cn \
            --arg start "${PREVIOUS_TIMESTAMP}" \
            --arg end "${CURRENT_TIMESTAMP}" \
            --argjson duration_minutes "${GAP_MINUTES}" \
            '{
                start: $start,
                end: $end,
                duration_minutes: $duration_minutes
            }' >> "${GAPS_FILE}"
    fi

    PREVIOUS_TIMESTAMP="${CURRENT_TIMESTAMP}"

done < "${TIMESTAMPS_FILE}"

# -----------------------------------------------------------------------------
# Initial gap
# -----------------------------------------------------------------------------

FIRST_EVENT="$(
    head -n 1 "${TIMESTAMPS_FILE}"
)"

if [[ -n "${FIRST_EVENT}" ]]; then

    FIRST_EPOCH="$(
        date -u -d "${FIRST_EVENT}" '+%s'
    )"

    INITIAL_GAP_MINUTES=$(( (FIRST_EPOCH - WINDOW_START_EPOCH) / 60 ))

    if [[ "${INITIAL_GAP_MINUTES}" -lt 0 ]]; then
        INITIAL_GAP_MINUTES=0
    fi

    if [[ "${INITIAL_GAP_MINUTES}" -gt "${LARGEST_GAP_MINUTES}" ]]; then
        LARGEST_GAP_MINUTES="${INITIAL_GAP_MINUTES}"
    fi

    if [[ "${INITIAL_GAP_MINUTES}" -gt "${GAP_THRESHOLD_MINUTES}" ]]; then

        GAP_COUNT=$((GAP_COUNT + 1))

        jq -cn \
            --arg start "${WINDOW_START}" \
            --arg end "${FIRST_EVENT}" \
            --argjson duration_minutes "${INITIAL_GAP_MINUTES}" \
            '{
                start: $start,
                end: $end,
                duration_minutes: $duration_minutes
            }' >> "${GAPS_FILE}"
    fi
fi

# -----------------------------------------------------------------------------
# Final gap
# -----------------------------------------------------------------------------

LAST_EVENT="$(
    tail -n 1 "${TIMESTAMPS_FILE}"
)"

if [[ -n "${LAST_EVENT}" ]]; then

    LAST_EPOCH="$(
        date -u -d "${LAST_EVENT}" '+%s'
    )"

    FINAL_GAP_MINUTES=$(( (WINDOW_END_EPOCH - LAST_EPOCH) / 60 ))

    if [[ "${FINAL_GAP_MINUTES}" -lt 0 ]]; then
        FINAL_GAP_MINUTES=0
    fi

    if [[ "${FINAL_GAP_MINUTES}" -gt "${LARGEST_GAP_MINUTES}" ]]; then
        LARGEST_GAP_MINUTES="${FINAL_GAP_MINUTES}"
    fi

    if [[ "${FINAL_GAP_MINUTES}" -gt "${GAP_THRESHOLD_MINUTES}" ]]; then

        GAP_COUNT=$((GAP_COUNT + 1))

        jq -cn \
            --arg start "${LAST_EVENT}" \
            --arg end "${WINDOW_END}" \
            --argjson duration_minutes "${FINAL_GAP_MINUTES}" \
            '{
                start: $start,
                end: $end,
                duration_minutes: $duration_minutes
            }' >> "${GAPS_FILE}"
    fi
fi

# =============================================================================
# Field Completeness
# =============================================================================

printf '[*] Field Completeness...\n'

# -----------------------------------------------------------------------------
# Common fields:
# timestamp
# hostname
# source_type
# event_category
# -----------------------------------------------------------------------------

COMMON_COMPLETE="$(
    jq '
        [
            .events[]
            | select(
                (.timestamp // "") != ""
                and
                (.hostname // "") != ""
                and
                (.source_type // "") != ""
                and
                (.event_category // "") != ""
            )
        ]
        | length
    ' "${INPUT_FILE}"
)"

COMMON_COMPLETENESS="$(
    percentage \
        "${COMMON_COMPLETE}" \
        "${TOTAL_EVENTS}"
)"

# -----------------------------------------------------------------------------
# execve command line
# -----------------------------------------------------------------------------

EXECVE_TOTAL="$(
    jq '
        [
            .events[]
            | select(.event_category == "execve")
        ]
        | length
    ' "${INPUT_FILE}"
)"

EXECVE_COMMAND_LINE_COMPLETE="$(
    jq '
        [
            .events[]
            | select(
                .event_category == "execve"
                and
                (.command_line // "") != ""
            )
        ]
        | length
    ' "${INPUT_FILE}"
)"

EXECVE_COMMAND_LINE_COMPLETENESS="$(
    percentage \
        "${EXECVE_COMMAND_LINE_COMPLETE}" \
        "${EXECVE_TOTAL}"
)"

if [[ "${EXECVE_TOTAL}" -eq 0 ]]; then
    EXECVE_COMMAND_LINE_COMPLETENESS=0
fi

# -----------------------------------------------------------------------------
# SSH source IP and user
# -----------------------------------------------------------------------------

SSH_TOTAL="$(
    jq '
        [
            .events[]
            | select(
                .event_category == "ssh_login_success"
                or
                .event_category == "ssh_login_failure"
            )
        ]
        | length
    ' "${INPUT_FILE}"
)"

SSH_SOURCE_IP_COMPLETE="$(
    jq '
        [
            .events[]
            | select(
                (
                    .event_category == "ssh_login_success"
                    or
                    .event_category == "ssh_login_failure"
                )
                and
                (.source_ip // "") != ""
                and
                (.source_ip // "") != "-"
            )
        ]
        | length
    ' "${INPUT_FILE}"
)"

SSH_USER_COMPLETE="$(
    jq '
        [
            .events[]
            | select(
                (
                    .event_category == "ssh_login_success"
                    or
                    .event_category == "ssh_login_failure"
                )
                and
                (.user // "") != ""
            )
        ]
        | length
    ' "${INPUT_FILE}"
)"

SSH_SOURCE_IP_COMPLETENESS="$(
    percentage \
        "${SSH_SOURCE_IP_COMPLETE}" \
        "${SSH_TOTAL}"
)"

SSH_USER_COMPLETENESS="$(
    percentage \
        "${SSH_USER_COMPLETE}" \
        "${SSH_TOTAL}"
)"

if [[ "${SSH_TOTAL}" -eq 0 ]]; then
    SSH_SOURCE_IP_COMPLETENESS=0
    SSH_USER_COMPLETENESS=0
fi

# -----------------------------------------------------------------------------
# auditd file event completeness:
# path
# operation
# key
#
# Task 7 may expose:
# syscall as operation
# audit_key as key
# -----------------------------------------------------------------------------

AUDIT_FILE_TOTAL="$(
    jq '
        [
            .events[]
            | select(
                .source_type == "auditd"
                and
                .event_category == "file_access"
            )
        ]
        | length
    ' "${INPUT_FILE}"
)"

AUDIT_FILE_PATH_COMPLETE="$(
    jq '
        [
            .events[]
            | select(
                .source_type == "auditd"
                and
                .event_category == "file_access"
                and
                (.path // "") != ""
            )
        ]
        | length
    ' "${INPUT_FILE}"
)"

AUDIT_FILE_OPERATION_COMPLETE="$(
    jq '
        [
            .events[]
            | select(
                .source_type == "auditd"
                and
                .event_category == "file_access"
                and
                (
                    (.operation // "") != ""
                    or
                    (.syscall // "") != ""
                )
            )
        ]
        | length
    ' "${INPUT_FILE}"
)"

AUDIT_FILE_KEY_COMPLETE="$(
    jq '
        [
            .events[]
            | select(
                .source_type == "auditd"
                and
                .event_category == "file_access"
                and
                (
                    (.key // "") != ""
                    or
                    (.audit_key // "") != ""
                )
            )
        ]
        | length
    ' "${INPUT_FILE}"
)"

AUDIT_FILE_PATH_COMPLETENESS="$(
    percentage \
        "${AUDIT_FILE_PATH_COMPLETE}" \
        "${AUDIT_FILE_TOTAL}"
)"

AUDIT_FILE_OPERATION_COMPLETENESS="$(
    percentage \
        "${AUDIT_FILE_OPERATION_COMPLETE}" \
        "${AUDIT_FILE_TOTAL}"
)"

AUDIT_FILE_KEY_COMPLETENESS="$(
    percentage \
        "${AUDIT_FILE_KEY_COMPLETE}" \
        "${AUDIT_FILE_TOTAL}"
)"

AUDIT_FILE_COMPLETENESS="$(
    awk \
        -v path="${AUDIT_FILE_PATH_COMPLETENESS}" \
        -v operation="${AUDIT_FILE_OPERATION_COMPLETENESS}" \
        -v key="${AUDIT_FILE_KEY_COMPLETENESS}" \
        'BEGIN {
            printf "%.2f", (path + operation + key) / 3
        }'
)"

if [[ "${AUDIT_FILE_TOTAL}" -eq 0 ]]; then
    AUDIT_FILE_PATH_COMPLETENESS=0
    AUDIT_FILE_OPERATION_COMPLETENESS=0
    AUDIT_FILE_KEY_COMPLETENESS=0
    AUDIT_FILE_COMPLETENESS=0
fi

# =============================================================================
# Gap Continuity Score
# =============================================================================

if [[ "${LARGEST_GAP_MINUTES}" -le 30 ]]; then

    GAP_CONTINUITY_SCORE=100

elif [[ "${LARGEST_GAP_MINUTES}" -le 60 ]]; then

    GAP_CONTINUITY_SCORE=80

elif [[ "${LARGEST_GAP_MINUTES}" -le 120 ]]; then

    GAP_CONTINUITY_SCORE=60

elif [[ "${LARGEST_GAP_MINUTES}" -le 240 ]]; then

    GAP_CONTINUITY_SCORE=40

else

    GAP_CONTINUITY_SCORE=20
fi

# =============================================================================
# Quality Score
# =============================================================================

printf '[*] Quality Score...\n'

QUALITY_SCORE="$(
    awk \
        -v common="${COMMON_COMPLETENESS}" \
        -v execve="${EXECVE_COMMAND_LINE_COMPLETENESS}" \
        -v ssh_ip="${SSH_SOURCE_IP_COMPLETENESS}" \
        -v ssh_user="${SSH_USER_COMPLETENESS}" \
        -v audit_file="${AUDIT_FILE_COMPLETENESS}" \
        -v time="${TIME_COVERAGE_PERCENT}" \
        -v gap="${GAP_CONTINUITY_SCORE}" \
        -v w_common="${WEIGHT_COMMON_FIELDS}" \
        -v w_execve="${WEIGHT_EXECVE_COMMAND_LINE}" \
        -v w_ssh_ip="${WEIGHT_SSH_SOURCE_IP}" \
        -v w_ssh_user="${WEIGHT_SSH_USER}" \
        -v w_audit="${WEIGHT_AUDIT_FILE}" \
        -v w_time="${WEIGHT_TIME_COVERAGE}" \
        -v w_gap="${WEIGHT_GAP_CONTINUITY}" \
    'BEGIN{
        score=((common/100)*w_common)+((execve/100)*w_execve)+((ssh_ip/100)*w_ssh_ip)+((ssh_user/100)*w_ssh_user)+((audit_file/100)*w_audit)+((time/100)*w_time)+((gap/100)*w_gap);
        printf "%.2f",score
    }'
)"

ASSESSMENT="$(
    get_assessment "${QUALITY_SCORE}"
)"

# =============================================================================
# Convert JSONL helper files
# =============================================================================

if [[ -s "${GAPS_FILE}" ]]; then

    GAPS_JSON="$(
        jq -s '.' "${GAPS_FILE}"
    )"

else

    GAPS_JSON='[]'
fi

if [[ -s "${HOURLY_FILE}" ]]; then

    HOURLY_JSON="$(
        jq -s '.' "${HOURLY_FILE}"
    )"

else

    HOURLY_JSON='[]'
fi

# =============================================================================
# Build linux_telemetry_quality.json
# =============================================================================

jq -n \
    --arg generated_at "$(
        date -u '+%Y-%m-%dT%H:%M:%SZ'
    )" \
    --arg source_file "${INPUT_FILE}" \
    --arg window_start "${WINDOW_START}" \
    --arg window_end "${WINDOW_END}" \
    --arg assessment "${ASSESSMENT}" \
    --argjson total_events "${TOTAL_EVENTS}" \
    --argjson event_distribution "${EVENT_CATEGORY_DISTRIBUTION}" \
    --argjson source_distribution "${SOURCE_TYPE_DISTRIBUTION}" \
    --argjson total_hours "${TOTAL_HOURS}" \
    --argjson hours_with_events "${HOURS_WITH_EVENTS}" \
    --argjson hours_without_events "${HOURS_WITHOUT_EVENTS}" \
    --argjson coverage_percentage "${TIME_COVERAGE_PERCENT}" \
    --argjson events_per_hour "${HOURLY_JSON}" \
    --argjson gap_threshold "${GAP_THRESHOLD_MINUTES}" \
    --argjson gap_count "${GAP_COUNT}" \
    --argjson largest_gap "${LARGEST_GAP_MINUTES}" \
    --argjson gaps "${GAPS_JSON}" \
    --argjson common_complete "${COMMON_COMPLETENESS}" \
    --argjson execve_total "${EXECVE_TOTAL}" \
    --argjson execve_complete "${EXECVE_COMMAND_LINE_COMPLETE}" \
    --argjson execve_percentage "${EXECVE_COMMAND_LINE_COMPLETENESS}" \
    --argjson ssh_total "${SSH_TOTAL}" \
    --argjson ssh_ip_complete "${SSH_SOURCE_IP_COMPLETE}" \
    --argjson ssh_ip_percentage "${SSH_SOURCE_IP_COMPLETENESS}" \
    --argjson ssh_user_complete "${SSH_USER_COMPLETE}" \
    --argjson ssh_user_percentage "${SSH_USER_COMPLETENESS}" \
    --argjson audit_total "${AUDIT_FILE_TOTAL}" \
    --argjson audit_path_percentage "${AUDIT_FILE_PATH_COMPLETENESS}" \
    --argjson audit_operation_percentage "${AUDIT_FILE_OPERATION_COMPLETENESS}" \
    --argjson audit_key_percentage "${AUDIT_FILE_KEY_COMPLETENESS}" \
    --argjson audit_overall_percentage "${AUDIT_FILE_COMPLETENESS}" \
    --argjson quality_score "${QUALITY_SCORE}" \
    '
    {
        metadata: {
            generated_at: $generated_at,
            source_file: $source_file,
            window_start: $window_start,
            window_end: $window_end,
            gap_threshold_minutes: $gap_threshold
        },

        total_events: $total_events,

        event_distribution: {
            by_event_category: $event_distribution,
            by_source_type: $source_distribution
        },

        time_coverage: {
            total_hours: $total_hours,
            hours_with_events: $hours_with_events,
            hours_without_events: $hours_without_events,
            coverage_percentage: $coverage_percentage,
            events_per_hour: $events_per_hour
        },

        gap_detection: {
            threshold_minutes: $gap_threshold,
            gap_count: $gap_count,
            largest_gap_minutes: $largest_gap,
            gaps: $gaps
        },

        field_completeness: {
            common_fields: {
                required_fields: [
                    "timestamp",
                    "hostname",
                    "source_type",
                    "event_category"
                ],
                completeness_percentage: $common_complete
            },

            execve: {
                required_field: "command_line",
                total_events: $execve_total,
                populated: $execve_complete,
                completeness_percentage: $execve_percentage
            },

            ssh: {
                required_fields: [
                    "source_ip",
                    "user"
                ],
                total_events: $ssh_total,

                source_ip: {
                    populated: $ssh_ip_complete,
                    completeness_percentage: $ssh_ip_percentage
                },

                user: {
                    populated: $ssh_user_complete,
                    completeness_percentage: $ssh_user_percentage
                }
            },

            auditd_file_events: {
                required_fields: [
                    "path",
                    "operation",
                    "key"
                ],
                total_events: $audit_total,
                path_completeness_percentage: $audit_path_percentage,
                operation_completeness_percentage: $audit_operation_percentage,
                key_completeness_percentage: $audit_key_percentage,
                overall_completeness_percentage: $audit_overall_percentage
            }
        },

        quality_score: {
            score: $quality_score,
            assessment: $assessment
        }
    }
    ' > "${OUTPUT_FILE}"

# =============================================================================
# Validate Output
# =============================================================================

if ! jq empty "${OUTPUT_FILE}" >/dev/null 2>&1; then

    printf '[FAIL] linux_telemetry_quality.json is invalid JSON.\n'

    exit 1
fi

# =============================================================================
# Expected Output Summary
# =============================================================================

printf '\n'
printf 'Total events: %d\n' "${TOTAL_EVENTS}"

printf 'Hours with events: %d/%d\n' \
    "${HOURS_WITH_EVENTS}" \
    "${TOTAL_HOURS}"

printf 'Hours without events: %d/%d\n' \
    "${HOURS_WITHOUT_EVENTS}" \
    "${TOTAL_HOURS}"

if [[ "${GAP_COUNT}" -eq 0 ]]; then

    printf 'No gaps detected\n'

else

    printf 'Gaps longer than 30 minutes: %d\n' \
        "${GAP_COUNT}"

    printf 'Largest gap: %d minutes\n' \
        "${LARGEST_GAP_MINUTES}"
fi

printf 'execve command_line completeness: %s%%\n' \
    "${EXECVE_COMMAND_LINE_COMPLETENESS}"

printf 'SSH source_ip completeness: %s%%\n' \
    "${SSH_SOURCE_IP_COMPLETENESS}"

printf 'SSH user completeness: %s%%\n' \
    "${SSH_USER_COMPLETENESS}"

printf 'auditd file path completeness: %s%%\n' \
    "${AUDIT_FILE_PATH_COMPLETENESS}"

printf 'auditd file operation completeness: %s%%\n' \
    "${AUDIT_FILE_OPERATION_COMPLETENESS}"

printf 'auditd file key completeness: %s%%\n' \
    "${AUDIT_FILE_KEY_COMPLETENESS}"

printf 'Quality score: %s%% (%s)\n' \
    "${QUALITY_SCORE}" \
    "${ASSESSMENT}"

printf 'Report saved to: %s\n' \
    "${OUTPUT_FILE}"

printf '\n'

exit 0