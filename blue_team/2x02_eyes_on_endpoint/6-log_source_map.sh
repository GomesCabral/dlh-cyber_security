#!/bin/bash

# name: 6-log_source_map.sh
# purpose: Discover and inventory active Linux log sources, formats, rotation policies, event rates and security relevance.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 6 - Linux Log Source Mapping
#
# Required sources:
# - auth.log
# - syslog
# - audit.log
# - kern.log
# - dpkg.log
# - apache2 access log
# - apache2 error log
# - other security-relevant sources
#
# Required metadata:
# - file path
# - format type: syslog, JSON, audit, custom
# - rotation policy from logrotate
# - current file size
# - estimated events per hour
# - security relevance: critical, high, medium, low
#
# The script also identifies expected sources that are missing
# or not generating events.
#
# Safety:
# READ-ONLY.
# This script does not modify log files or logging configuration.

set -e
set -u
set -o pipefail

# =============================================================================
# Configuration
# =============================================================================

FOUND_COUNT=0
MISSING_COUNT=0

EXPECTED_WINDOW_HOURS=24

TMP_DIR="$(mktemp -d)"
RESULT_FILE="${TMP_DIR}/results.tsv"

trap 'rm -rf "${TMP_DIR}"' EXIT

# =============================================================================
# Helper functions
# =============================================================================

format_size() {
    local file_path="$1"

    if [[ ! -f "${file_path}" ]]; then
        printf '%s' "-"
        return
    fi

    du -h "${file_path}" 2>/dev/null |
        awk '{print $1}'
}


estimate_events_per_hour() {
    local file_path="$1"
    local line_count=0
    local modified_epoch=0
    local current_epoch=0
    local age_hours=0
    local estimate=0

    if [[ ! -f "${file_path}" ]]; then
        printf '%s' "0"
        return
    fi

    line_count="$(
        wc -l < "${file_path}" 2>/dev/null || printf '0'
    )"

    if [[ "${line_count}" -eq 0 ]]; then
        printf '%s' "0"
        return
    fi

    modified_epoch="$(
        stat -c '%Y' "${file_path}" 2>/dev/null || printf '0'
    )"

    current_epoch="$(date +%s)"

    if [[ "${modified_epoch}" -le 0 ]]; then
        printf '%s' "<1"
        return
    fi

    age_hours="$(
        awk -v now="${current_epoch}" \
            -v mod="${modified_epoch}" \
            'BEGIN {
                age=(now-mod)/3600;
                if (age < 1) {
                    age=1;
                }
                print int(age);
            }'
    )"

    # Do not estimate using more than the requested observation window.
    if [[ "${age_hours}" -gt "${EXPECTED_WINDOW_HOURS}" ]]; then
        age_hours="${EXPECTED_WINDOW_HOURS}"
    fi

    estimate="$(
        awk -v lines="${line_count}" \
            -v hours="${age_hours}" \
            'BEGIN {
                if (hours <= 0) {
                    print 0;
                } else {
                    rate=lines/hours;
                    if (rate > 0 && rate < 1) {
                        print "<1";
                    } else {
                        printf "%.0f", rate;
                    }
                }
            }'
    )"

    printf '%s' "${estimate}"
}


find_logrotate_config() {
    local file_path="$1"
    local config=""
    local base_name=""

    base_name="$(basename "${file_path}")"

    if [[ -d "/etc/logrotate.d" ]]; then
        config="$(
            grep -RFl -- "${file_path}" /etc/logrotate.d 2>/dev/null |
                head -n 1 || true
        )"

        if [[ -z "${config}" ]]; then
            config="$(
                grep -RFl -- "${base_name}" /etc/logrotate.d 2>/dev/null |
                    head -n 1 || true
            )"
        fi
    fi

    if [[ -n "${config}" ]]; then
        printf '%s' "${config}"
    else
        printf '%s' "-"
    fi
}


get_rotation_policy() {
    local file_path="$1"
    local config=""
    local frequency=""
    local rotate_count=""
    local policy=""

    config="$(find_logrotate_config "${file_path}")"

    if [[ "${config}" == "-" ]]; then
        printf '%s' "not found"
        return
    fi

    frequency="$(
        grep -E '^[[:space:]]*(daily|weekly|monthly|yearly)[[:space:]]*$' \
            "${config}" 2>/dev/null |
            head -n 1 |
            xargs || true
    )"

    rotate_count="$(
        grep -E '^[[:space:]]*rotate[[:space:]]+[0-9]+' \
            "${config}" 2>/dev/null |
            head -n 1 |
            awk '{print $2}' || true
    )"

    if [[ -n "${frequency}" && -n "${rotate_count}" ]]; then
        policy="${frequency}, rotate ${rotate_count}"
    elif [[ -n "${frequency}" ]]; then
        policy="${frequency}"
    elif [[ -n "${rotate_count}" ]]; then
        policy="rotate ${rotate_count}"
    else
        policy="configured"
    fi

    printf '%s' "${policy}"
}


check_activity() {
    local file_path="$1"

    if [[ ! -f "${file_path}" ]]; then
        printf '%s' "missing"
        return
    fi

    if [[ ! -s "${file_path}" ]]; then
        printf '%s' "not generating events"
        return
    fi

    printf '%s' "active"
}


add_source() {
    local source_name="$1"
    local path="$2"
    local format_type="$3"
    local relevance="$4"

    local state=""
    local rotation=""
    local size=""
    local events_per_hour=""

    state="$(check_activity "${path}")"

    if [[ "${state}" == "missing" ]]; then
        MISSING_COUNT=$((MISSING_COUNT + 1))

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${source_name}" \
            "${path}" \
            "${format_type}" \
            "-" \
            "-" \
            "${relevance}" \
            "MISSING" >> "${RESULT_FILE}"

        return
    fi

    FOUND_COUNT=$((FOUND_COUNT + 1))

    rotation="$(get_rotation_policy "${path}")"
    size="$(format_size "${path}")"
    events_per_hour="$(estimate_events_per_hour "${path}")"

    if [[ "${state}" == "not generating events" ]]; then
        events_per_hour="0"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${source_name}" \
        "${path}" \
        "${format_type}" \
        "${rotation}" \
        "${events_per_hour}" \
        "${relevance}" \
        "${state} (${size})" >> "${RESULT_FILE}"
}


discover_optional_logs() {
    local optional_path=""

    for optional_path in \
        /var/log/fail2ban.log \
        /var/log/ufw.log \
        /var/log/nginx/access.log \
        /var/log/nginx/error.log
    do

        if [[ -f "${optional_path}" ]]; then

            case "${optional_path}" in

                /var/log/fail2ban.log)
                    add_source \
                        "fail2ban" \
                        "${optional_path}" \
                        "custom" \
                        "high"
                    ;;

                /var/log/ufw.log)
                    add_source \
                        "ufw" \
                        "${optional_path}" \
                        "syslog" \
                        "high"
                    ;;

                /var/log/nginx/access.log)
                    add_source \
                        "nginx access" \
                        "${optional_path}" \
                        "custom" \
                        "high"
                    ;;

                /var/log/nginx/error.log)
                    add_source \
                        "nginx error" \
                        "${optional_path}" \
                        "custom" \
                        "high"
                    ;;
            esac
        fi
    done
}

# =============================================================================
# Start
# =============================================================================

printf '\n'
printf '==============================================\n'
printf 'MedDefense Linux Log Source Mapping\n'
printf '==============================================\n'
printf '\n'

printf '[*] Discovering log sources...\n'

: > "${RESULT_FILE}"

# =============================================================================
# Expected Log Sources
# =============================================================================

# auth.log
# Authentication, SSH, sudo and account-related telemetry.
add_source \
    "auth.log" \
    "/var/log/auth.log" \
    "syslog" \
    "critical"

# audit.log
# Structured Linux Audit Framework records.
add_source \
    "audit.log" \
    "/var/log/audit/audit.log" \
    "audit" \
    "critical"

# syslog
# General system and service telemetry.
add_source \
    "syslog" \
    "/var/log/syslog" \
    "syslog" \
    "high"

# kern.log
# Kernel-level events.
add_source \
    "kern.log" \
    "/var/log/kern.log" \
    "syslog" \
    "medium"

# dpkg.log
# Software package installation/removal activity.
add_source \
    "dpkg.log" \
    "/var/log/dpkg.log" \
    "custom" \
    "medium"

# Apache access log.
add_source \
    "apache2 access" \
    "/var/log/apache2/access.log" \
    "custom" \
    "high"

# Apache error log.
add_source \
    "apache2 error" \
    "/var/log/apache2/error.log" \
    "custom" \
    "high"

# =============================================================================
# Other Security-Relevant Sources
# =============================================================================

discover_optional_logs

# =============================================================================
# Output Table
# =============================================================================

printf '\n'

printf '%-18s %-34s %-9s %-20s %-12s %-10s %s\n' \
    "Source" \
    "Path" \
    "Format" \
    "Rotation" \
    "Events/hr" \
    "Relevance" \
    "State"

printf '%-18s %-34s %-9s %-20s %-12s %-10s %s\n' \
    "------" \
    "----" \
    "------" \
    "--------" \
    "---------" \
    "---------" \
    "-----"

while IFS=$'\t' read -r \
    source_name \
    path \
    format_type \
    rotation \
    events_per_hour \
    relevance \
    state
do

    printf '%-18s %-34s %-9s %-20s %-12s %-10s %s\n' \
        "${source_name}" \
        "${path}" \
        "${format_type}" \
        "${rotation}" \
        "${events_per_hour}" \
        "${relevance}" \
        "${state}"

done < "${RESULT_FILE}"

# =============================================================================
# Missing / inactive source assessment
# =============================================================================

printf '\n'
printf '[*] Checking expected sources for missing or inactive telemetry...\n'

while IFS=$'\t' read -r \
    source_name \
    path \
    format_type \
    rotation \
    events_per_hour \
    relevance \
    state
do

    : "${format_type}"
    : "${rotation}"
    : "${relevance}"

    if [[ "${state}" == "MISSING" ]]; then

        printf '    [MISSING] %s -> %s\n' \
            "${source_name}" \
            "${path}"

    elif [[ "${events_per_hour}" == "0" ]]; then

        printf '    [INACTIVE] %s -> not generating events\n' \
            "${source_name}"
    fi

done < "${RESULT_FILE}"

# =============================================================================
# Summary
# =============================================================================

printf '\n'
printf 'Sources found: %d | Missing: %d\n' \
    "${FOUND_COUNT}" \
    "${MISSING_COUNT}"

printf '\n'
printf '[*] Log source inventory complete.\n'