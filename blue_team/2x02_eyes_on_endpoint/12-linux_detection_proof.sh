#!/bin/bash

# name: 12-linux_detection_proof.sh
# purpose: Correlate Task 11 Linux attack-simulation ground truth against auditd, auth.log, and syslog telemetry and produce a structured detection matrix.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 12 - Linux Detection Proof
#
# Input:
# - linux_attack_log.json
#
# Output:
# - linux_detection_matrix.json
#
# Sources:
# - auditd via ausearch
# - auth.log (or journal fallback)
# - syslog (or journal fallback)
#
# Correlation:
# - +/- 30 seconds around each ground-truth timestamp
#
# Safety:
# - READ-ONLY with respect to system telemetry.

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

WINDOW_SECONDS=30

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1
    pwd -P
)"

GROUND_TRUTH_FILE="${SCRIPT_DIR}/linux_attack_log.json"
OUTPUT_FILE="${SCRIPT_DIR}/linux_detection_matrix.json"

AUTH_LOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"

TMP_DIR="$(mktemp -d)"
ROWS_FILE="${TMP_DIR}/rows.jsonl"

trap 'rm -rf "${TMP_DIR}"' EXIT

# =============================================================================
# Prerequisites
# =============================================================================

require_command() {
    local command_name="$1"

    if ! command -v "${command_name}" >/dev/null 2>&1; then
        printf '[FAIL] Required command not found: %s\n' "${command_name}"
        exit 1
    fi
}

require_command jq
require_command date
require_command ausearch
require_command awk
require_command grep

if [[ "${EUID}" -ne 0 ]]; then
    printf '[FAIL] Run this script with sudo/root privileges.\n'
    exit 1
fi

if [[ ! -f "${GROUND_TRUTH_FILE}" ]]; then
    printf '[FAIL] Ground truth file not found: %s\n' "${GROUND_TRUTH_FILE}"
    printf '       Run Task 11 first: sudo ./11-linux_attack_sim.sh\n'
    exit 1
fi

if ! jq empty "${GROUND_TRUTH_FILE}" >/dev/null 2>&1; then
    printf '[FAIL] linux_attack_log.json is invalid JSON.\n'
    exit 1
fi

# =============================================================================
# Helpers
# =============================================================================

display_name() {
    case "$1" in
        1) printf 'Create user' ;;
        2) printf 'Modify sudoers' ;;
        3) printf 'Execute from /tmp' ;;
        4) printf 'Reverse shell' ;;
        5) printf 'Cron persistence' ;;
        6) printf 'Access /etc/shadow' ;;
        *) printf 'Action %s' "$1" ;;
    esac
}

expected_audit_key() {
    case "$1" in
        1) printf 'identity' ;;
        2) printf 'sudoers' ;;
        3) printf 'process_exec' ;;
        4) printf 'network_connect' ;;
        5) printf 'cron_persist' ;;
        6) printf 'identity' ;;
        *) printf '' ;;
    esac
}

iso_to_epoch() {
    date -u -d "$1" '+%s'
}

epoch_to_audit_date() {
    date -d "@$1" '+%m/%d/%Y'
}

epoch_to_audit_time() {
    date -d "@$1" '+%H:%M:%S'
}

# Search a normal text log using timestamps when the log exists.
# This handles the common "Aug 10 13:02:00" syslog/auth.log format.
search_text_log_window() {
    local file="$1"
    local start_epoch="$2"
    local end_epoch="$3"

    [[ -r "${file}" ]] || return 0

    local cursor="${start_epoch}"

    while [[ "${cursor}" -le "${end_epoch}" ]]; do
        local prefix
        prefix="$(LC_ALL=C date -d "@${cursor}" '+%b %e %H:%M:%S')"
        grep -F "${prefix}" "${file}" 2>/dev/null || true
        cursor=$((cursor + 1))
    done
}

search_journal_window() {
    local unit_hint="$1"
    local start_epoch="$2"
    local end_epoch="$3"

    command -v journalctl >/dev/null 2>&1 || return 0

    local since until
    since="$(date -d "@${start_epoch}" '+%Y-%m-%d %H:%M:%S')"
    until="$(date -d "@${end_epoch}" '+%Y-%m-%d %H:%M:%S')"

    if [[ -n "${unit_hint}" ]]; then
        journalctl --since "${since}" --until "${until}" \
            --no-pager -o short-iso 2>/dev/null |
            grep -Ei "${unit_hint}" || true
    else
        journalctl --since "${since}" --until "${until}" \
            --no-pager -o short-iso 2>/dev/null || true
    fi
}

search_audit_window() {
    local start_epoch="$1"
    local end_epoch="$2"

    local start_date start_time end_date end_time

    start_date="$(epoch_to_audit_date "${start_epoch}")"
    start_time="$(epoch_to_audit_time "${start_epoch}")"
    end_date="$(epoch_to_audit_date "${end_epoch}")"
    end_time="$(epoch_to_audit_time "${end_epoch}")"

    ausearch \
        -ts "${start_date}" "${start_time}" \
        -te "${end_date}" "${end_time}" \
        -i 2>/dev/null || true
}

action_pattern() {
    case "$1" in
        1) printf 'testattacker|useradd|add-user|add_user|USER_ACCT|USER_MGMT' ;;
        2) printf 'sudoers|/etc/sudoers.d/backdoor|backdoor|testattacker' ;;
        3) printf 'suspicious_bin|/tmp/suspicious_bin|execve|EXECVE' ;;
        4) printf '127\.0\.0\.1|4444|/dev/tcp|bash -i|network_connect' ;;
        5) printf 'persistence_test|/etc/cron.d/persistence_test|/tmp/beacon.sh|cron_persist' ;;
        6) printf '/etc/shadow|shadow|identity' ;;
        *) printf '.' ;;
    esac
}

auth_pattern() {
    case "$1" in
        1) printf 'useradd.*testattacker|new user.*testattacker|testattacker.*useradd' ;;
        2) printf 'sudo|testattacker|backdoor' ;;
        *) printf 'a^' ;;
    esac
}

syslog_pattern() {
    case "$1" in
        4) printf '127\.0\.0\.1|4444|bash' ;;
        5) printf 'cron|persistence_test|beacon\.sh' ;;
        *) printf 'a^' ;;
    esac
}

detail_level_audit() {
    local action="$1"
    local text="$2"

    local score=0
    local required=2

    case "${action}" in
        1)
            grep -Eqi 'testattacker' <<< "${text}" && score=$((score + 1))
            grep -Eqi 'useradd|ADD_USER|USER_ACCT|USER_MGMT|identity' <<< "${text}" && score=$((score + 1))
            ;;
        2)
            grep -Eqi '/etc/sudoers.d/backdoor|sudoers|backdoor' <<< "${text}" && score=$((score + 1))
            grep -Eqi 'testattacker|sudoers' <<< "${text}" && score=$((score + 1))
            ;;
        3)
            grep -Eqi '/tmp/suspicious_bin|suspicious_bin' <<< "${text}" && score=$((score + 1))
            grep -Eqi 'EXECVE|execve|process_exec' <<< "${text}" && score=$((score + 1))
            ;;
        4)
            grep -Eqi '127\.0\.0\.1|4444|/dev/tcp' <<< "${text}" && score=$((score + 1))
            grep -Eqi 'bash|EXECVE|network_connect' <<< "${text}" && score=$((score + 1))
            ;;
        5)
            grep -Eqi '/etc/cron.d/persistence_test|persistence_test|cron_persist' <<< "${text}" && score=$((score + 1))
            grep -Eqi '/tmp/beacon.sh|cron' <<< "${text}" && score=$((score + 1))
            ;;
        6)
            grep -Eqi '/etc/shadow|shadow' <<< "${text}" && score=$((score + 1))
            grep -Eqi 'cat|PATH|SYSCALL|identity' <<< "${text}" && score=$((score + 1))
            ;;
    esac

    if [[ "${score}" -ge "${required}" ]]; then
        printf 'Full'
    elif [[ "${score}" -gt 0 ]]; then
        printf 'Partial'
    else
        printf 'Missing'
    fi
}

build_key_fields() {
    local action="$1"
    local text="$2"

    case "${action}" in
        1)
            jq -cn \
                --arg user "$(grep -Eio 'testattacker' <<< "${text}" | head -n1 || true)" \
                '{user:$user}'
            ;;
        2)
            jq -cn \
                --arg path "$(grep -Eio '/etc/sudoers\.d/backdoor' <<< "${text}" | head -n1 || true)" \
                --arg user "$(grep -Eio 'testattacker' <<< "${text}" | head -n1 || true)" \
                '{path:$path,user:$user}'
            ;;
        3)
            jq -cn \
                --arg path "$(grep -Eio '/tmp/suspicious_bin' <<< "${text}" | head -n1 || true)" \
                '{executable_path:$path}'
            ;;
        4)
            jq -cn \
                --arg destination_ip "$(grep -Eio '127\.0\.0\.1' <<< "${text}" | head -n1 || true)" \
                --arg destination_port "$(grep -Eio '4444' <<< "${text}" | head -n1 || true)" \
                '{destination_ip:$destination_ip,destination_port:$destination_port}'
            ;;
        5)
            jq -cn \
                --arg cron_file "$(grep -Eio '/etc/cron\.d/persistence_test' <<< "${text}" | head -n1 || true)" \
                --arg beacon "$(grep -Eio '/tmp/beacon\.sh' <<< "${text}" | head -n1 || true)" \
                '{cron_file:$cron_file,command:$beacon}'
            ;;
        6)
            jq -cn \
                --arg path "$(grep -Eio '/etc/shadow' <<< "${text}" | head -n1 || true)" \
                '{path:$path}'
            ;;
    esac
}

record_row() {
    local action_number="$1"
    local action="$2"
    local source="$3"
    local key="$4"
    local detail="$5"
    local status="$6"
    local key_fields="$7"

    jq -cn \
        --argjson action_number "${action_number}" \
        --arg action "${action}" \
        --arg source "${source}" \
        --arg audit_key "${key}" \
        --arg detail "${detail}" \
        --arg status "${status}" \
        --argjson key_fields "${key_fields}" \
        '{
            action_number: $action_number,
            action: $action,
            source: $source,
            audit_key: (
                if $audit_key == ""
                then null
                else $audit_key
                end
            ),
            detail: $detail,
            status: $status,
            key_fields: $key_fields
        }' >> "${ROWS_FILE}"
}

# =============================================================================
# Load Ground Truth
# =============================================================================

TOTAL_ACTIONS="$(jq '.actions | length' "${GROUND_TRUTH_FILE}")"

printf '[*] Loading ground truth (%d actions)...\n' "${TOTAL_ACTIONS}"
printf '[*] Searching telemetry...\n'

: > "${ROWS_FILE}"

CAPTURED_ACTIONS=0
MULTI_SOURCE_ACTIONS=0

# =============================================================================
# Correlation
# =============================================================================

for action_number in $(jq -r '.actions[].action_number' "${GROUND_TRUTH_FILE}"); do

    timestamp="$(
        jq -r \
            --argjson number "${action_number}" \
            '.actions[] | select(.action_number == $number) | .timestamp' \
            "${GROUND_TRUTH_FILE}"
    )"

    action="$(display_name "${action_number}")"
    audit_key="$(expected_audit_key "${action_number}")"

    event_epoch="$(iso_to_epoch "${timestamp}")"
    start_epoch=$((event_epoch - WINDOW_SECONDS))
    end_epoch=$((event_epoch + WINDOW_SECONDS))

    pattern="$(action_pattern "${action_number}")"

    audit_window="$(search_audit_window "${start_epoch}" "${end_epoch}")"
    audit_match="$(grep -Ei "${pattern}" <<< "${audit_window}" || true)"

    sources_for_action=0

    if [[ -n "${audit_match}" ]]; then

        detail="$(detail_level_audit "${action_number}" "${audit_match}")"
        key_fields="$(build_key_fields "${action_number}" "${audit_match}")"

        record_row \
            "${action_number}" \
            "${action}" \
            "auditd" \
            "${audit_key}" \
            "${detail}" \
            "[CAPTURED]" \
            "${key_fields}"

        sources_for_action=$((sources_for_action + 1))
    fi

    # -------------------------------------------------------------------------
    # auth.log
    # -------------------------------------------------------------------------

    auth_text=""

    if [[ -r "${AUTH_LOG}" ]]; then
        auth_text="$(search_text_log_window "${AUTH_LOG}" "${start_epoch}" "${end_epoch}")"
    else
        auth_text="$(search_journal_window 'useradd|sudo|sshd|authentication|pam' "${start_epoch}" "${end_epoch}")"
    fi

    auth_regex="$(auth_pattern "${action_number}")"
    auth_match="$(grep -Ei "${auth_regex}" <<< "${auth_text}" || true)"

    if [[ -n "${auth_match}" ]]; then

        key_fields="$(build_key_fields "${action_number}" "${auth_match}")"

        record_row \
            "${action_number}" \
            "${action}" \
            "auth.log" \
            "$(case "${action_number}" in 1) printf 'useradd' ;; 2) printf 'sudo' ;; *) printf '' ;; esac)" \
            "Full" \
            "[CAPTURED]" \
            "${key_fields}"

        sources_for_action=$((sources_for_action + 1))
    fi

    # -------------------------------------------------------------------------
    # syslog
    # -------------------------------------------------------------------------

    syslog_text=""

    if [[ -r "${SYSLOG}" ]]; then
        syslog_text="$(search_text_log_window "${SYSLOG}" "${start_epoch}" "${end_epoch}")"
    else
        syslog_text="$(search_journal_window 'cron|bash|kernel|systemd' "${start_epoch}" "${end_epoch}")"
    fi

    syslog_regex="$(syslog_pattern "${action_number}")"
    syslog_match="$(grep -Ei "${syslog_regex}" <<< "${syslog_text}" || true)"

    if [[ -n "${syslog_match}" ]]; then

        key_fields="$(build_key_fields "${action_number}" "${syslog_match}")"

        record_row \
            "${action_number}" \
            "${action}" \
            "syslog" \
            "" \
            "Partial" \
            "[CAPTURED]" \
            "${key_fields}"

        sources_for_action=$((sources_for_action + 1))
    fi

    # -------------------------------------------------------------------------
    # No source captured action
    # -------------------------------------------------------------------------

    if [[ "${sources_for_action}" -eq 0 ]]; then

        record_row \
            "${action_number}" \
            "${action}" \
            "-" \
            "${audit_key}" \
            "None" \
            "[MISSED]" \
            '{}'
    else
        CAPTURED_ACTIONS=$((CAPTURED_ACTIONS + 1))

        if [[ "${sources_for_action}" -gt 1 ]]; then
            MULTI_SOURCE_ACTIONS=$((MULTI_SOURCE_ACTIONS + 1))
        fi
    fi
done

# =============================================================================
# Print Detection Matrix
# =============================================================================

printf '%-26s %-14s %-16s %-9s %s\n' \
    "Action" "Source" "Key" "Detail" "Status"

printf '%-26s %-14s %-16s %-9s %s\n' \
    "------" "------" "---" "------" "------"

last_action=""

while IFS=$'\t' read -r action source key detail status; do

    action_cell="${action}"

    if [[ "${action}" == "${last_action}" ]]; then
        action_cell=""
    else
        last_action="${action}"
    fi

    [[ "${key}" == "null" || -z "${key}" ]] && key="-"

    printf '%-26s %-14s %-16s %-9s %s\n' \
        "${action_cell}" \
        "${source}" \
        "${key}" \
        "${detail}" \
        "${status}"

done < <(
    jq -rs -r '
        .[]
        | [
            .action,
            .source,
            (.audit_key // "-"),
            .detail,
            .status
        ]
        | @tsv
    ' "${ROWS_FILE}"
)

# =============================================================================
# Build Structured JSON Report
# =============================================================================

DETECTIONS_JSON="$(jq -s '.' "${ROWS_FILE}")"

CAPTURE_PERCENT="$(
    awk \
        -v captured="${CAPTURED_ACTIONS}" \
        -v total="${TOTAL_ACTIONS}" \
        'BEGIN {
            if (total == 0) {
                print 0
            } else {
                printf "%.0f", (captured / total) * 100
            }
        }'
)"

jq -n \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg ground_truth_file "${GROUND_TRUTH_FILE}" \
    --argjson window_seconds "${WINDOW_SECONDS}" \
    --argjson total_actions "${TOTAL_ACTIONS}" \
    --argjson captured_actions "${CAPTURED_ACTIONS}" \
    --argjson capture_rate_percent "${CAPTURE_PERCENT}" \
    --argjson multi_source_actions "${MULTI_SOURCE_ACTIONS}" \
    --argjson detections "${DETECTIONS_JSON}" \
    '{
        metadata: {
            generated_at_utc: $generated_at,
            ground_truth_file: $ground_truth_file,
            window_seconds: $window_seconds,
            total_actions: $total_actions,
            captured_actions: $captured_actions,
            capture_rate_percent: $capture_rate_percent,
            multi_source_actions: $multi_source_actions
        },
        detections: $detections
    }' > "${OUTPUT_FILE}"

if ! jq empty "${OUTPUT_FILE}" >/dev/null 2>&1; then
    printf '[FAIL] linux_detection_matrix.json is invalid JSON.\n'
    exit 1
fi

# =============================================================================
# Summary
# =============================================================================

printf 'Actions: %d | Captured: %d/%d (%d%%) | Multi-source: %d\n' \
    "${TOTAL_ACTIONS}" \
    "${CAPTURED_ACTIONS}" \
    "${TOTAL_ACTIONS}" \
    "${CAPTURE_PERCENT}" \
    "${MULTI_SOURCE_ACTIONS}"

printf 'Report saved to: linux_detection_matrix.json\n'

exit 0