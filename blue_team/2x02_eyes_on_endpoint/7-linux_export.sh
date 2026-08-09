#!/bin/bash

# name: 7-linux_export.sh
# purpose: Export security-relevant Linux auth.log, audit.log and syslog telemetry to normalized JSON using ISO 8601 UTC timestamps.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 7 - Linux Event Export
#
# Sources:
# - /var/log/auth.log
# - /var/log/audit/audit.log
# - /var/log/syslog
#
# auth.log parsing:
# - SSH login success
# - SSH login failure
# - source IP
# - user
# - sudo events
# - sudo command
# - su events
# - PAM events
#
# auditd parsing:
# - syscall
# - execve
# - command line
# - file access
# - path
# - network socket creation
# - destination
#
# syslog parsing:
# - service start
# - service stop
# - error conditions
#
# Normalized fields:
# - timestamp
# - hostname
# - platform
# - source_type
# - event_category
# - raw_message
#
# Timestamp format:
# ISO 8601 UTC
#
# Output:
# - linux_events_export.json
#
# Default time window:
# - last 24 hours
#
# Safety:
# READ-ONLY with respect to system logs.
# The script only reads telemetry and writes linux_events_export.json.

set -e
set -u
set -o pipefail

# =============================================================================
# Configuration
# =============================================================================

AUTH_LOG="/var/log/auth.log"
AUDIT_LOG="/var/log/audit/audit.log"
SYSLOG="/var/log/syslog"

OUTPUT_FILE="linux_events_export.json"

HOURS="${HOURS:-24}"

HOSTNAME_VALUE="$(hostname)"

PLATFORM="Linux"

END_TIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
START_TIME="$(date -u -d "${HOURS} hours ago" '+%Y-%m-%dT%H:%M:%SZ')"

START_EPOCH="$(date -u -d "${START_TIME}" '+%s')"
END_EPOCH="$(date -u -d "${END_TIME}" '+%s')"

TMP_DIR="$(mktemp -d)"

AUTH_JSON="${TMP_DIR}/auth.jsonl"
AUDIT_JSON="${TMP_DIR}/audit.jsonl"
SYSLOG_JSON="${TMP_DIR}/syslog.jsonl"

touch "${AUTH_JSON}" "${AUDIT_JSON}" "${SYSLOG_JSON}"

trap 'rm -rf "${TMP_DIR}"' EXIT

# =============================================================================
# Counters
# =============================================================================

AUTH_TOTAL=0
SSH_COUNT=0
SUDO_COUNT=0
SU_COUNT=0
PAM_COUNT=0

AUDIT_TOTAL=0
EXECVE_COUNT=0
FILE_ACCESS_COUNT=0
NETWORK_COUNT=0
AUDIT_OTHER_COUNT=0

SYSLOG_TOTAL=0
SERVICE_COUNT=0
ERROR_COUNT=0
SYSLOG_OTHER_COUNT=0

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
require_command awk
require_command grep
require_command hostname

# =============================================================================
# Helpers
# =============================================================================

syslog_timestamp_to_epoch() {
    local month="$1"
    local day="$2"
    local clock="$3"
    local year=""

    year="$(date '+%Y')"

    date -d "${month} ${day} ${year} ${clock}" '+%s' 2>/dev/null || printf '0'
}


epoch_to_iso8601_utc() {
    local epoch="$1"

    date -u -d "@${epoch}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null ||
        printf '%s' ""
}


within_time_window() {
    local epoch="$1"

    [[ "${epoch}" -ge "${START_EPOCH}" &&
       "${epoch}" -le "${END_EPOCH}" ]]
}


emit_json_event() {
    local output_file="$1"
    local timestamp="$2"
    local source_type="$3"
    local event_category="$4"
    local raw_message="$5"
    shift 5

    local extra_json="{}"

    if [[ "$#" -gt 0 ]]; then
        extra_json="$1"
    fi

    jq -cn \
        --arg timestamp "${timestamp}" \
        --arg hostname "${HOSTNAME_VALUE}" \
        --arg platform "${PLATFORM}" \
        --arg source_type "${source_type}" \
        --arg event_category "${event_category}" \
        --arg raw_message "${raw_message}" \
        --argjson extra "${extra_json}" \
        '
        {
            timestamp: $timestamp,
            hostname: $hostname,
            platform: $platform,
            source_type: $source_type,
            event_category: $event_category,
            raw_message: $raw_message
        } + $extra
        ' >> "${output_file}"
}

# =============================================================================
# Parse auth.log
# =============================================================================

parse_auth_log() {

    printf '[*] Parsing auth.log... '

    if [[ ! -r "${AUTH_LOG}" ]]; then
        printf 'MISSING or unreadable\n'
        return
    fi

    while IFS= read -r line; do

        month="$(awk '{print $1}' <<< "${line}")"
        day="$(awk '{print $2}' <<< "${line}")"
        clock="$(awk '{print $3}' <<< "${line}")"

        event_epoch="$(
            syslog_timestamp_to_epoch \
                "${month}" \
                "${day}" \
                "${clock}"
        )"

        if [[ "${event_epoch}" -eq 0 ]]; then
            continue
        fi

        if ! within_time_window "${event_epoch}"; then
            continue
        fi

        timestamp="$(
            epoch_to_iso8601_utc "${event_epoch}"
        )"

        # ---------------------------------------------------------------------
        # SSH successful login
        # ---------------------------------------------------------------------

        if grep -Eq 'sshd.*Accepted (password|publickey)' <<< "${line}"; then

            user="$(
                sed -nE \
                    's/.*Accepted (password|publickey) for ([^ ]+) from ([^ ]+).*/\2/p' \
                    <<< "${line}"
            )"

            source_ip="$(
                sed -nE \
                    's/.*Accepted (password|publickey) for ([^ ]+) from ([^ ]+).*/\3/p' \
                    <<< "${line}"
            )"

            auth_method="$(
                sed -nE \
                    's/.*Accepted ([^ ]+) for .*/\1/p' \
                    <<< "${line}"
            )"

            extra="$(
                jq -cn \
                    --arg user "${user}" \
                    --arg source_ip "${source_ip}" \
                    --arg result "success" \
                    --arg auth_method "${auth_method}" \
                    '{
                        user: $user,
                        source_ip: $source_ip,
                        result: $result,
                        auth_method: $auth_method
                    }'
            )"

            emit_json_event \
                "${AUTH_JSON}" \
                "${timestamp}" \
                "auth.log" \
                "ssh_login_success" \
                "${line}" \
                "${extra}"

            AUTH_TOTAL=$((AUTH_TOTAL + 1))
            SSH_COUNT=$((SSH_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # SSH failed login
        # ---------------------------------------------------------------------

        if grep -Eq 'sshd.*Failed password' <<< "${line}"; then

            user="$(
                sed -nE \
                    's/.*Failed password for (invalid user )?([^ ]+) from ([^ ]+).*/\2/p' \
                    <<< "${line}"
            )"

            source_ip="$(
                sed -nE \
                    's/.*Failed password for (invalid user )?([^ ]+) from ([^ ]+).*/\3/p' \
                    <<< "${line}"
            )"

            extra="$(
                jq -cn \
                    --arg user "${user}" \
                    --arg source_ip "${source_ip}" \
                    --arg result "failure" \
                    '{
                        user: $user,
                        source_ip: $source_ip,
                        result: $result
                    }'
            )"

            emit_json_event \
                "${AUTH_JSON}" \
                "${timestamp}" \
                "auth.log" \
                "ssh_login_failure" \
                "${line}" \
                "${extra}"

            AUTH_TOTAL=$((AUTH_TOTAL + 1))
            SSH_COUNT=$((SSH_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # sudo
        # ---------------------------------------------------------------------

        if grep -Eq 'sudo.*COMMAND=' <<< "${line}"; then

            sudo_user="$(
                sed -nE \
                    's/.*sudo:[[:space:]]+([^ ]+)[[:space:]]*:.*/\1/p' \
                    <<< "${line}"
            )"

            sudo_command="$(
                sed -nE \
                    's/.*COMMAND=(.*)$/\1/p' \
                    <<< "${line}"
            )"

            extra="$(
                jq -cn \
                    --arg user "${sudo_user}" \
                    --arg command "${sudo_command}" \
                    '{
                        user: $user,
                        command: $command
                    }'
            )"

            emit_json_event \
                "${AUTH_JSON}" \
                "${timestamp}" \
                "auth.log" \
                "sudo" \
                "${line}" \
                "${extra}"

            AUTH_TOTAL=$((AUTH_TOTAL + 1))
            SUDO_COUNT=$((SUDO_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # su
        # ---------------------------------------------------------------------

        if grep -Eq 'su(\[|:).*session|su.*authentication' <<< "${line}"; then

            extra="$(
                jq -cn \
                    --arg action "su" \
                    '{
                        action: $action
                    }'
            )"

            emit_json_event \
                "${AUTH_JSON}" \
                "${timestamp}" \
                "auth.log" \
                "su" \
                "${line}" \
                "${extra}"

            AUTH_TOTAL=$((AUTH_TOTAL + 1))
            SU_COUNT=$((SU_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # PAM
        # ---------------------------------------------------------------------

        if grep -Eq 'pam_[a-zA-Z0-9_]+' <<< "${line}"; then

            emit_json_event \
                "${AUTH_JSON}" \
                "${timestamp}" \
                "auth.log" \
                "pam" \
                "${line}"

            AUTH_TOTAL=$((AUTH_TOTAL + 1))
            PAM_COUNT=$((PAM_COUNT + 1))
        fi

    done < "${AUTH_LOG}"

    printf '%d events\n' "${AUTH_TOTAL}"

    printf '    SSH logins: %d | sudo: %d | su: %d | PAM: %d\n' \
        "${SSH_COUNT}" \
        "${SUDO_COUNT}" \
        "${SU_COUNT}" \
        "${PAM_COUNT}"
}

# =============================================================================
# auditd helpers
# =============================================================================

audit_epoch_from_line() {
    local line="$1"

    sed -nE \
        's/.*audit\(([0-9]+)(\.[0-9]+)?:[0-9]+\).*/\1/p' \
        <<< "${line}"
}


audit_serial_from_line() {
    local line="$1"

    sed -nE \
        's/.*audit\([0-9]+(\.[0-9]+)?:([0-9]+)\).*/\2/p' \
        <<< "${line}"
}


get_audit_records_for_serial() {
    local serial="$1"

    grep -F ":${serial})" "${AUDIT_LOG}" 2>/dev/null || true
}

# =============================================================================
# Parse audit.log
# =============================================================================

parse_audit_log() {

    printf '[*] Parsing audit.log... '

    if [[ ! -r "${AUDIT_LOG}" ]]; then
        printf 'MISSING or unreadable\n'
        return
    fi

    # Process one SYSCALL record per audit event.
    while IFS= read -r syscall_line; do

        event_epoch="$(
            audit_epoch_from_line "${syscall_line}"
        )"

        if [[ -z "${event_epoch}" ]]; then
            continue
        fi

        if ! within_time_window "${event_epoch}"; then
            continue
        fi

        serial="$(
            audit_serial_from_line "${syscall_line}"
        )"

        if [[ -z "${serial}" ]]; then
            continue
        fi

        timestamp="$(
            epoch_to_iso8601_utc "${event_epoch}"
        )"

        records="$(
            get_audit_records_for_serial "${serial}"
        )"

        key="$(
            sed -nE \
                's/.* key="?([^" ]+)"?.*/\1/p' \
                <<< "${syscall_line}" |
                head -n 1
        )"

        exe="$(
            sed -nE \
                's/.* exe="([^"]+)".*/\1/p' \
                <<< "${syscall_line}" |
                head -n 1
        )"

        syscall_number="$(
            sed -nE \
                's/.* syscall=([^ ]+).*/\1/p' \
                <<< "${syscall_line}" |
                head -n 1
        )"

        # ---------------------------------------------------------------------
        # execve / process_exec
        # ---------------------------------------------------------------------

        if [[ "${key}" == "process_exec" ]] ||
           grep -q 'type=EXECVE' <<< "${records}"
        then

            command_line="$(
                grep 'type=EXECVE' <<< "${records}" |
                    head -n 1 |
                    grep -oE 'a[0-9]+="[^"]*"|a[0-9]+=[^ ]+' |
                    sed -E 's/^a[0-9]+=//' |
                    tr '\n' ' ' |
                    sed 's/[[:space:]]*$//'
            )"

            extra="$(
                jq -cn \
                    --arg syscall "execve" \
                    --arg executable "${exe}" \
                    --arg command_line "${command_line}" \
                    --arg audit_key "${key}" \
                    '{
                        syscall: $syscall,
                        executable: $executable,
                        command_line: $command_line,
                        audit_key: $audit_key
                    }'
            )"

            emit_json_event \
                "${AUDIT_JSON}" \
                "${timestamp}" \
                "auditd" \
                "execve" \
                "${records}" \
                "${extra}"

            AUDIT_TOTAL=$((AUDIT_TOTAL + 1))
            EXECVE_COUNT=$((EXECVE_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # file access
        # ---------------------------------------------------------------------

        if grep -q 'type=PATH' <<< "${records}"; then

            path="$(
                grep 'type=PATH' <<< "${records}" |
                    sed -nE 's/.* name="([^"]+)".*/\1/p' |
                    head -n 1
            )"

            extra="$(
                jq -cn \
                    --arg path "${path}" \
                    --arg syscall "${syscall_number}" \
                    --arg audit_key "${key}" \
                    '{
                        path: $path,
                        syscall: $syscall,
                        audit_key: $audit_key
                    }'
            )"

            emit_json_event \
                "${AUDIT_JSON}" \
                "${timestamp}" \
                "auditd" \
                "file_access" \
                "${records}" \
                "${extra}"

            AUDIT_TOTAL=$((AUDIT_TOTAL + 1))
            FILE_ACCESS_COUNT=$((FILE_ACCESS_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # network socket creation / connect
        # ---------------------------------------------------------------------

        if [[ "${key}" == "network_connect" ]] ||
           grep -Eq 'SOCKADDR|saddr=' <<< "${records}"
        then

            destination="$(
                grep -oE 'saddr=[0-9A-Fa-f]+' <<< "${records}" |
                    head -n 1 |
                    cut -d= -f2 || true
            )"

            extra="$(
                jq -cn \
                    --arg syscall "${syscall_number}" \
                    --arg executable "${exe}" \
                    --arg destination "${destination}" \
                    --arg audit_key "${key}" \
                    '{
                        syscall: $syscall,
                        executable: $executable,
                        destination: $destination,
                        audit_key: $audit_key
                    }'
            )"

            emit_json_event \
                "${AUDIT_JSON}" \
                "${timestamp}" \
                "auditd" \
                "network" \
                "${records}" \
                "${extra}"

            AUDIT_TOTAL=$((AUDIT_TOTAL + 1))
            NETWORK_COUNT=$((NETWORK_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # Other syscall
        # ---------------------------------------------------------------------

        extra="$(
            jq -cn \
                --arg syscall "${syscall_number}" \
                --arg executable "${exe}" \
                --arg audit_key "${key}" \
                '{
                    syscall: $syscall,
                    executable: $executable,
                    audit_key: $audit_key
                }'
        )"

        emit_json_event \
            "${AUDIT_JSON}" \
            "${timestamp}" \
            "auditd" \
            "other" \
            "${records}" \
            "${extra}"

        AUDIT_TOTAL=$((AUDIT_TOTAL + 1))
        AUDIT_OTHER_COUNT=$((AUDIT_OTHER_COUNT + 1))

    done < <(
        grep 'type=SYSCALL' "${AUDIT_LOG}" 2>/dev/null || true
    )

    printf '%d events\n' "${AUDIT_TOTAL}"

    printf '    execve: %d | file_access: %d | network: %d | other: %d\n' \
        "${EXECVE_COUNT}" \
        "${FILE_ACCESS_COUNT}" \
        "${NETWORK_COUNT}" \
        "${AUDIT_OTHER_COUNT}"
}

# =============================================================================
# Parse syslog
# =============================================================================

parse_syslog() {

    printf '[*] Parsing syslog... '

    if [[ ! -r "${SYSLOG}" ]]; then
        printf 'MISSING or unreadable\n'
        return
    fi

    while IFS= read -r line; do

        month="$(awk '{print $1}' <<< "${line}")"
        day="$(awk '{print $2}' <<< "${line}")"
        clock="$(awk '{print $3}' <<< "${line}")"

        event_epoch="$(
            syslog_timestamp_to_epoch \
                "${month}" \
                "${day}" \
                "${clock}"
        )"

        if [[ "${event_epoch}" -eq 0 ]]; then
            continue
        fi

        if ! within_time_window "${event_epoch}"; then
            continue
        fi

        timestamp="$(
            epoch_to_iso8601_utc "${event_epoch}"
        )"

        # ---------------------------------------------------------------------
        # Service start / stop
        # ---------------------------------------------------------------------

        if grep -Eqi \
            'systemd.*(Started|Starting|Stopped|Stopping|Failed)' \
            <<< "${line}"
        then

            if grep -Eqi '(Started|Starting)' <<< "${line}"; then
                action="start"
            elif grep -Eqi '(Stopped|Stopping)' <<< "${line}"; then
                action="stop"
            else
                action="failed"
            fi

            service="$(
                sed -nE \
                    's/.*systemd[^:]*:[[:space:]]*(Started|Starting|Stopped|Stopping|Failed)[[:space:]]+([^.]*)\.?.*/\2/p' \
                    <<< "${line}"
            )"

            extra="$(
                jq -cn \
                    --arg action "${action}" \
                    --arg service "${service}" \
                    '{
                        action: $action,
                        service: $service
                    }'
            )"

            emit_json_event \
                "${SYSLOG_JSON}" \
                "${timestamp}" \
                "syslog" \
                "service" \
                "${line}" \
                "${extra}"

            SYSLOG_TOTAL=$((SYSLOG_TOTAL + 1))
            SERVICE_COUNT=$((SERVICE_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # Error conditions
        # ---------------------------------------------------------------------

        if grep -Eqi \
            'error|failed|failure|critical|panic|segfault|denied|fatal' \
            <<< "${line}"
        then

            emit_json_event \
                "${SYSLOG_JSON}" \
                "${timestamp}" \
                "syslog" \
                "error" \
                "${line}"

            SYSLOG_TOTAL=$((SYSLOG_TOTAL + 1))
            ERROR_COUNT=$((ERROR_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # Other system activity
        # ---------------------------------------------------------------------

        emit_json_event \
            "${SYSLOG_JSON}" \
            "${timestamp}" \
            "syslog" \
            "other" \
            "${line}"

        SYSLOG_TOTAL=$((SYSLOG_TOTAL + 1))
        SYSLOG_OTHER_COUNT=$((SYSLOG_OTHER_COUNT + 1))

    done < "${SYSLOG}"

    printf '%d events\n' "${SYSLOG_TOTAL}"

    printf '    service: %d | error: %d | other: %d\n' \
        "${SERVICE_COUNT}" \
        "${ERROR_COUNT}" \
        "${SYSLOG_OTHER_COUNT}"
}

# =============================================================================
# Run parsers
# =============================================================================

printf '\n'
printf '==============================================\n'
printf 'MedDefense Linux Event Export\n'
printf '==============================================\n'
printf '\n'

printf '[*] Exporting security-relevant Linux telemetry...\n'
printf '    Time window: last %s hours\n' "${HOURS}"
printf '    StartTime: %s\n' "${START_TIME}"
printf '    EndTime:   %s\n' "${END_TIME}"
printf '\n'

parse_auth_log
parse_audit_log
parse_syslog

# =============================================================================
# Merge and sort all events
# =============================================================================

TOTAL_EVENTS=$(
    (
        cat "${AUTH_JSON}"
        cat "${AUDIT_JSON}"
        cat "${SYSLOG_JSON}"
    ) |
        grep -c . || true
)

# JSON document containing normalized events.
jq -s \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg start_time "${START_TIME}" \
    --arg end_time "${END_TIME}" \
    --arg hostname "${HOSTNAME_VALUE}" \
    --arg platform "${PLATFORM}" \
    --argjson hours "${HOURS}" \
    '
    sort_by(.timestamp)
    |
    {
        metadata: {
            generated_at: $generated_at,
            hostname: $hostname,
            platform: $platform,
            time_window_hours: $hours,
            StartTime: $start_time,
            EndTime: $end_time,
            timestamp_format: "ISO 8601 UTC"
        },
        events: .
    }
    ' \
    "${AUTH_JSON}" \
    "${AUDIT_JSON}" \
    "${SYSLOG_JSON}" \
    > "${OUTPUT_FILE}"

# =============================================================================
# Validate JSON
# =============================================================================

if ! jq empty "${OUTPUT_FILE}" >/dev/null 2>&1; then
    printf '[FAIL] Generated JSON is invalid.\n'
    exit 1
fi

# =============================================================================
# Summary
# =============================================================================

printf '\n'
printf 'Total events: %d\n' "${TOTAL_EVENTS}"
printf 'Time range: %s to %s\n' \
    "${START_TIME}" \
    "${END_TIME}"

printf 'Output: %s\n' "${OUTPUT_FILE}"
printf '\n'

printf '[PASS] Linux telemetry export complete.\n'