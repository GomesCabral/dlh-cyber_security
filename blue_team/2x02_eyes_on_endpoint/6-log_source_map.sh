#!/bin/bash

# name: 6-log_source_map.sh
# purpose: Inventory active Linux log sources, formats, rotation policies, file sizes, event rates, security relevance, and missing or inactive sources.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 6 - Linux Log Source Mapping
#
# Required sources:
# auth.log
# syslog
# audit.log
# kern.log
# dpkg.log
# apache2 access log
# apache2 error log
#
# Required format types:
# syslog
# JSON
# audit
# custom
#
# Required metadata:
# file path
# format
# rotation policy
# current file size
# estimated events per hour
# security relevance
#
# Relevance levels:
# critical
# high
# medium
# low
#
# Missing or inactive sources are explicitly reported.
#
# Rotation policy is discovered from:
# /etc/logrotate.conf
# /etc/logrotate.d/
#
# Safety:
# READ-ONLY.
# The script does not change system logging configuration.

set -e
set -u
set -o pipefail

# =============================================================================
# Configuration
# =============================================================================

FOUND_COUNT=0
MISSING_COUNT=0
INACTIVE_COUNT=0

TMP_FILE="$(mktemp)"

trap 'rm -f "${TMP_FILE}"' EXIT

# =============================================================================
# File Size
# =============================================================================

get_file_size() {
    local path="$1"

    if [[ ! -f "${path}" ]]; then
        printf '%s' "-"
        return
    fi

    du -h "${path}" 2>/dev/null |
        awk '{print $1}'
}

# =============================================================================
# Logrotate Configuration
# =============================================================================

find_logrotate_config() {
    local path="$1"
    local basename_value=""
    local result=""

    basename_value="$(basename "${path}")"

    if [[ -f "/etc/logrotate.conf" ]]; then

        if grep -Fq "${path}" /etc/logrotate.conf 2>/dev/null; then
            printf '%s' "/etc/logrotate.conf"
            return
        fi
    fi

    if [[ -d "/etc/logrotate.d" ]]; then

        result="$(
            grep -RFl \
                "${path}" \
                /etc/logrotate.d \
                2>/dev/null |
                head -n 1 || true
        )"

        if [[ -z "${result}" ]]; then

            result="$(
                grep -RFl \
                    "${basename_value}" \
                    /etc/logrotate.d \
                    2>/dev/null |
                    head -n 1 || true
            )"
        fi
    fi

    if [[ -n "${result}" ]]; then
        printf '%s' "${result}"
    else
        printf '%s' ""
    fi
}

# =============================================================================
# Rotation Policy
# =============================================================================

get_rotation_policy() {
    local path="$1"
    local config=""
    local frequency=""
    local rotate_count=""

    config="$(find_logrotate_config "${path}")"

    if [[ -z "${config}" ]]; then
        printf '%s' "not found"
        return
    fi

    frequency="$(
        grep -E \
            '^[[:space:]]*(hourly|daily|weekly|monthly|yearly)[[:space:]]*$' \
            "${config}" \
            2>/dev/null |
            head -n 1 |
            xargs || true
    )"

    rotate_count="$(
        grep -E \
            '^[[:space:]]*rotate[[:space:]]+[0-9]+' \
            "${config}" \
            2>/dev/null |
            head -n 1 |
            awk '{print $2}' || true
    )"

    if [[ -n "${frequency}" && -n "${rotate_count}" ]]; then

        printf '%s, rotate %s' \
            "${frequency}" \
            "${rotate_count}"

    elif [[ -n "${frequency}" ]]; then

        printf '%s' "${frequency}"

    elif [[ -n "${rotate_count}" ]]; then

        printf 'rotate %s' "${rotate_count}"

    else

        printf '%s' "configured"
    fi
}

# =============================================================================
# Events Per Hour
#
# This is an estimate.
#
# For logs modified within the last hour, the number of lines in the current
# log provides a simple activity estimate.
#
# For older logs, the rate is normalized using file age, capped at 24 hours.
# =============================================================================

estimate_events_per_hour() {
    local path="$1"
    local lines=0
    local now_epoch=0
    local modified_epoch=0
    local age_seconds=0
    local age_hours=0
    local rate=""

    if [[ ! -f "${path}" ]]; then
        printf '%s' "-"
        return
    fi

    if [[ ! -s "${path}" ]]; then
        printf '%s' "0"
        return
    fi

    lines="$(
        wc -l < "${path}" 2>/dev/null || printf '0'
    )"

    if [[ "${lines}" -eq 0 ]]; then
        printf '%s' "0"
        return
    fi

    now_epoch="$(date +%s)"

    modified_epoch="$(
        stat -c '%Y' "${path}" 2>/dev/null || printf '0'
    )"

    if [[ "${modified_epoch}" -eq 0 ]]; then
        printf '%s' "<1"
        return
    fi

    age_seconds=$((now_epoch - modified_epoch))

    # Modified during last hour.
    if [[ "${age_seconds}" -le 3600 ]]; then

        rate="${lines}"

    else

        age_hours=$((age_seconds / 3600))

        if [[ "${age_hours}" -lt 1 ]]; then
            age_hours=1
        fi

        if [[ "${age_hours}" -gt 24 ]]; then
            age_hours=24
        fi

        rate="$(
            awk \
                -v lines="${lines}" \
                -v hours="${age_hours}" \
                'BEGIN {
                    result=lines/hours;

                    if (result > 0 && result < 1) {
                        print "<1";
                    } else {
                        printf "%.0f", result;
                    }
                }'
        )"
    fi

    printf '%s' "${rate}"
}

# =============================================================================
# Source State
# =============================================================================

get_source_state() {
    local path="$1"

    if [[ ! -e "${path}" ]]; then
        printf '%s' "MISSING"
        return
    fi

    if [[ ! -s "${path}" ]]; then
        printf '%s' "INACTIVE"
        return
    fi

    printf '%s' "ACTIVE"
}

# =============================================================================
# Register Log Source
# =============================================================================

add_source() {
    local source="$1"
    local path="$2"
    local format="$3"
    local relevance="$4"

    local rotation="-"
    local size="-"
    local events_per_hour="-"
    local state=""

    state="$(get_source_state "${path}")"

    case "${state}" in

        ACTIVE)
            FOUND_COUNT=$((FOUND_COUNT + 1))

            rotation="$(get_rotation_policy "${path}")"
            size="$(get_file_size "${path}")"
            events_per_hour="$(estimate_events_per_hour "${path}")"
            ;;

        INACTIVE)
            FOUND_COUNT=$((FOUND_COUNT + 1))
            INACTIVE_COUNT=$((INACTIVE_COUNT + 1))

            rotation="$(get_rotation_policy "${path}")"
            size="$(get_file_size "${path}")"
            events_per_hour="0"
            ;;

        MISSING)
            MISSING_COUNT=$((MISSING_COUNT + 1))
            ;;
    esac

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${source}" \
        "${path}" \
        "${format}" \
        "${rotation}" \
        "${size}" \
        "${events_per_hour}" \
        "${relevance}" \
        "${state}" \
        >> "${TMP_FILE}"
}

# =============================================================================
# Discover Other Security-Relevant Sources
# =============================================================================

discover_additional_sources() {

    if [[ -e "/var/log/fail2ban.log" ]]; then

        add_source \
            "fail2ban" \
            "/var/log/fail2ban.log" \
            "custom" \
            "high"
    fi

    if [[ -e "/var/log/ufw.log" ]]; then

        add_source \
            "ufw.log" \
            "/var/log/ufw.log" \
            "syslog" \
            "high"
    fi

    if [[ -e "/var/log/nginx/access.log" ]]; then

        add_source \
            "nginx access" \
            "/var/log/nginx/access.log" \
            "custom" \
            "high"
    fi

    if [[ -e "/var/log/nginx/error.log" ]]; then

        add_source \
            "nginx error" \
            "/var/log/nginx/error.log" \
            "custom" \
            "high"
    fi
}

# =============================================================================
# Discover Log Sources
# =============================================================================

printf '\n'
printf '==============================================\n'
printf 'MedDefense Linux Log Source Mapping\n'
printf '==============================================\n'
printf '\n'

printf '[*] Discovering log sources...\n'

# auth.log
add_source \
    "auth.log" \
    "/var/log/auth.log" \
    "syslog" \
    "critical"

# audit.log
add_source \
    "audit.log" \
    "/var/log/audit/audit.log" \
    "audit" \
    "critical"

# syslog
add_source \
    "syslog" \
    "/var/log/syslog" \
    "syslog" \
    "high"

# kern.log
add_source \
    "kern.log" \
    "/var/log/kern.log" \
    "syslog" \
    "medium"

# apache2 access log
#
# Apache normally uses the "combined" access-log format.
# For the normalized inventory classification this is an application-specific
# custom log format.
add_source \
    "apache2 access" \
    "/var/log/apache2/access.log" \
    "custom" \
    "high"

# apache2 error log
add_source \
    "apache2 error" \
    "/var/log/apache2/error.log" \
    "custom" \
    "high"

# dpkg.log
add_source \
    "dpkg.log" \
    "/var/log/dpkg.log" \
    "custom" \
    "medium"

# Other security-relevant sources
discover_additional_sources

# =============================================================================
# Display Inventory
# =============================================================================

printf '\n'

printf '%-18s %-34s %-8s %-22s %-9s %-10s %-10s %s\n' \
    "Source" \
    "Path" \
    "Format" \
    "Rotation" \
    "Size" \
    "Events/hr" \
    "Relevance" \
    "State"

printf '%-18s %-34s %-8s %-22s %-9s %-10s %-10s %s\n' \
    "------" \
    "----" \
    "------" \
    "--------" \
    "----" \
    "---------" \
    "---------" \
    "-----"

while IFS=$'\t' read -r \
    source \
    path \
    format \
    rotation \
    size \
    events_per_hour \
    relevance \
    state
do

    printf '%-18s %-34s %-8s %-22s %-9s %-10s %-10s %s\n' \
        "${source}" \
        "${path}" \
        "${format}" \
        "${rotation}" \
        "${size}" \
        "${events_per_hour}" \
        "${relevance}" \
        "${state}"

done < "${TMP_FILE}"

# =============================================================================
# Missing or Inactive Expected Sources
# =============================================================================

printf '\n'
printf '[*] Checking expected sources for missing or inactive telemetry...\n'

while IFS=$'\t' read -r \
    source \
    path \
    format \
    rotation \
    size \
    events_per_hour \
    relevance \
    state
do

    # Variables are read because the TSV schema contains all required fields.
    : "${format}"
    : "${rotation}"
    : "${size}"
    : "${events_per_hour}"
    : "${relevance}"

    case "${state}" in

        MISSING)

            printf '    [MISSING] %s -> %s\n' \
                "${source}" \
                "${path}"
            ;;

        INACTIVE)

            printf '    [INACTIVE] %s -> not generating events\n' \
                "${source}"
            ;;

        ACTIVE)
            ;;
    esac

done < "${TMP_FILE}"

# =============================================================================
# Summary
# =============================================================================

printf '\n'

printf 'Sources found: %d | Missing: %d' \
    "${FOUND_COUNT}" \
    "${MISSING_COUNT}"

if [[ "${INACTIVE_COUNT}" -gt 0 ]]; then
    printf ' | Inactive: %d' "${INACTIVE_COUNT}"
fi

printf '\n'

printf '\n'
printf '[PASS] Linux log source inventory complete.\n'