#!/bin/bash

# name: 7-linux_export.sh
# purpose: Export security-relevant Linux telemetry from auth.log, auditd, and syslog into normalized JSON.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 7 - Linux Event Export
#
# Default time window:
# - last 24 hours
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
# audit.log / auditd parsing:
# - ausearch
# - syscall
# - execve
# - command line
# - file_access
# - file path
# - network socket creation
# - connect
# - destination
#
# syslog parsing:
# - service start
# - service stop
# - service failure
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
# Timestamp:
# - ISO 8601 UTC
#
# Output:
# - linux_events_export.json
#
# Safety:
# READ-ONLY with respect to Linux logs and system configuration.

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

if ! [[ "${HOURS}" =~ ^[0-9]+$ ]] || [[ "${HOURS}" -le 0 ]]; then
    printf '[FAIL] HOURS must be a positive integer.\n'
    exit 1
fi

HOSTNAME_VALUE="$(hostname)"
PLATFORM="Linux"

END_EPOCH="$(date -u '+%s')"
START_EPOCH="$((END_EPOCH - HOURS * 3600))"

START_TIME="$(
    date -u \
        -d "@${START_EPOCH}" \
        '+%Y-%m-%dT%H:%M:%SZ'
)"

END_TIME="$(
    date -u \
        -d "@${END_EPOCH}" \
        '+%Y-%m-%dT%H:%M:%SZ'
)"

AUSEARCH_START_DATE="$(
    date -d "@${START_EPOCH}" '+%m/%d/%Y'
)"

AUSEARCH_START_CLOCK="$(
    date -d "@${START_EPOCH}" '+%H:%M:%S'
)"

AUSEARCH_END_DATE="$(
    date -d "@${END_EPOCH}" '+%m/%d/%Y'
)"

AUSEARCH_END_CLOCK="$(
    date -d "@${END_EPOCH}" '+%H:%M:%S'
)"

TMP_DIR="$(mktemp -d)"

AUTH_JSON="${TMP_DIR}/auth.jsonl"
AUDIT_JSON="${TMP_DIR}/audit.jsonl"
SYSLOG_JSON="${TMP_DIR}/syslog.jsonl"
AUSEARCH_OUTPUT="${TMP_DIR}/ausearch.log"

touch \
    "${AUTH_JSON}" \
    "${AUDIT_JSON}" \
    "${SYSLOG_JSON}" \
    "${AUSEARCH_OUTPUT}"

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
        printf '[FAIL] Required command not found: %s\n' \
            "${command_name}"
        exit 1
    fi
}

require_command jq
require_command date
require_command awk
require_command grep
require_command sed
require_command hostname
require_command ausearch

# =============================================================================
# Generic Helpers
# =============================================================================

within_time_window() {
    local event_epoch="$1"

    [[ "${event_epoch}" -ge "${START_EPOCH}" &&
       "${event_epoch}" -le "${END_EPOCH}" ]]
}


epoch_to_iso8601_utc() {
    local event_epoch="$1"

    date -u \
        -d "@${event_epoch}" \
        '+%Y-%m-%dT%H:%M:%SZ' \
        2>/dev/null || printf '%s' ""
}


syslog_timestamp_to_epoch() {
    local line="$1"
    local first_field=""
    local month=""
    local day=""
    local clock=""
    local year=""

    first_field="$(
        awk '{print $1}' <<< "${line}"
    )"

    # RFC3339 / ISO timestamp
    if [[ "${first_field}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]]; then
        date -d "${first_field}" '+%s' 2>/dev/null || printf '0'
        return
    fi

    # Traditional syslog timestamp:
    # Aug  9 10:15:32
    month="${first_field}"

    day="$(
        awk '{print $2}' <<< "${line}"
    )"

    clock="$(
        awk '{print $3}' <<< "${line}"
    )"

    year="$(date '+%Y')"

    date \
        -d "${month} ${day} ${year} ${clock}" \
        '+%s' \
        2>/dev/null || printf '0'
}


emit_json_event() {
    local output_file="$1"
    local timestamp="$2"
    local source_type="$3"
    local event_category="$4"
    local raw_message="$5"

    local extra_json='{}'

    if [[ "$#" -ge 6 ]] && [[ -n "${6}" ]]; then
        extra_json="$6"
    fi

    # Defensive validation before using --argjson.
    if ! jq -e . >/dev/null 2>&1 <<< "${extra_json}"; then
        printf '[WARN] Invalid enrichment JSON for category %s; using empty object.\n' \
            "${event_category}" >&2

        extra_json='{}'
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
# auth.log Parser
# =============================================================================

parse_auth_log() {
    local line=""
    local event_epoch=""
    local timestamp=""
    local user=""
    local source_ip=""
    local auth_method=""
    local sudo_user=""
    local sudo_command=""
    local extra=""

    printf '[*] Parsing auth.log... '

    if [[ ! -r "${AUTH_LOG}" ]]; then
        printf 'MISSING or unreadable\n'
        return
    fi

    while IFS= read -r line; do

        event_epoch="$(
            syslog_timestamp_to_epoch "${line}"
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
        # SSH login success
        # ---------------------------------------------------------------------

        if grep -Eq \
            'sshd.*Accepted (password|publickey|keyboard-interactive)' \
            <<< "${line}"
        then

            user="$(
                sed -nE \
                    's/.*Accepted [^ ]+ for ([^ ]+) from ([^ ]+).*/\1/p' \
                    <<< "${line}"
            )"

            source_ip="$(
                sed -nE \
                    's/.*Accepted [^ ]+ for ([^ ]+) from ([^ ]+).*/\2/p' \
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
        # SSH login failure
        # ---------------------------------------------------------------------

        if grep -Eq \
            'sshd.*Failed (password|publickey|keyboard-interactive)' \
            <<< "${line}"
        then

            user="$(
                sed -nE \
                    's/.*Failed [^ ]+ for (invalid user )?([^ ]+) from ([^ ]+).*/\2/p' \
                    <<< "${line}"
            )"

            source_ip="$(
                sed -nE \
                    's/.*Failed [^ ]+ for (invalid user )?([^ ]+) from ([^ ]+).*/\3/p' \
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

        if grep -Eq '(^|[[:space:]])su(\[|:).*' <<< "${line}"; then

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

        if grep -Eq 'pam_[A-Za-z0-9_]+' <<< "${line}"; then

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
# auditd / ausearch Helpers
# =============================================================================

audit_epoch_from_block() {
    local block="$1"

    sed -nE \
        's/.*msg=audit\(([0-9]+)(\.[0-9]+)?:[0-9]+\).*/\1/p' \
        <<< "${block}" |
        head -n 1
}


get_audit_key() {
    local block="$1"

    sed -nE \
        's/.*key="?([^" ]+)"?.*/\1/p' \
        <<< "${block}" |
        head -n 1
}


get_audit_executable() {
    local block="$1"

    sed -nE \
        's/.*exe="([^"]+)".*/\1/p' \
        <<< "${block}" |
        head -n 1
}


get_audit_syscall() {
    local block="$1"

    sed -nE \
        's/.*syscall=([^ ]+).*/\1/p' \
        <<< "${block}" |
        head -n 1
}


get_execve_command_line() {
    local block="$1"

    grep 'type=EXECVE' <<< "${block}" |
        head -n 1 |
        grep -oE 'a[0-9]+="[^"]*"|a[0-9]+=[^ ]+' |
        sed -E 's/^a[0-9]+=//' |
        tr '\n' ' ' |
        sed 's/[[:space:]]*$//' || true
}


get_file_path() {
    local block="$1"

    grep 'type=PATH' <<< "${block}" |
        sed -nE \
            's/.*name="([^"]+)".*/\1/p' |
        head -n 1
}


decode_ipv4_sockaddr() {
    local sockaddr="$1"
    local family=""
    local port_hex=""
    local ip_hex=""
    local port=""
    local a=""
    local b=""
    local c=""
    local d=""

    if [[ "${#sockaddr}" -lt 16 ]]; then
        printf '%s' "${sockaddr}"
        return
    fi

    family="${sockaddr:0:4}"

    if [[ "${family}" != "0200" ]]; then
        printf '%s' "${sockaddr}"
        return
    fi

    port_hex="${sockaddr:4:4}"
    ip_hex="${sockaddr:8:8}"

    port="$((16#${port_hex}))"

    a="$((16#${ip_hex:0:2}))"
    b="$((16#${ip_hex:2:2}))"
    c="$((16#${ip_hex:4:2}))"
    d="$((16#${ip_hex:6:2}))"

    printf '%s:%s' \
        "${a}.${b}.${c}.${d}" \
        "${port}"
}


get_network_destination() {
    local block="$1"
    local address=""
    local port=""
    local raw_sockaddr=""

    address="$(
        grep -oE \
            '(daddr|laddr|addr)=[^ ,}]+' \
            <<< "${block}" |
            head -n 1 |
            cut -d= -f2 || true
    )"

    port="$(
        grep -oE \
            '(dport|lport|port)=[0-9]+' \
            <<< "${block}" |
            head -n 1 |
            cut -d= -f2 || true
    )"

    if [[ -n "${address}" ]]; then

        if [[ -n "${port}" ]]; then
            printf '%s:%s' "${address}" "${port}"
        else
            printf '%s' "${address}"
        fi

        return
    fi

    raw_sockaddr="$(
        grep -oE \
            'saddr=[0-9A-Fa-f]+' \
            <<< "${block}" |
            head -n 1 |
            cut -d= -f2 || true
    )"

    if [[ -n "${raw_sockaddr}" ]]; then
        decode_ipv4_sockaddr "${raw_sockaddr}"
        return
    fi

    printf '%s' ""
}

# =============================================================================
# Parse audit.log using ausearch
# =============================================================================

parse_audit_log() {
    local block=""
    local event_epoch=""
    local timestamp=""
    local audit_key=""
    local executable=""
    local syscall=""
    local command_line=""
    local path=""
    local destination=""
    local extra=""

    printf '[*] Parsing audit.log... '

    if [[ ! -r "${AUDIT_LOG}" ]]; then
        printf 'MISSING or unreadable\n'
        return
    fi

    # ausearch is the native auditd search utility.
    #
    # It correlates SYSCALL, EXECVE, PATH and SOCKADDR records.
    #
    # Example:
    # ausearch -k process_exec
    # ausearch -k network_connect
    #
    # Time-window query:
    # ausearch -ts START_DATE START_TIME -te END_DATE END_TIME -i

    ausearch \
        -ts "${AUSEARCH_START_DATE}" "${AUSEARCH_START_CLOCK}" \
        -te "${AUSEARCH_END_DATE}" "${AUSEARCH_END_CLOCK}" \
        -i \
        > "${AUSEARCH_OUTPUT}" \
        2>/dev/null || true

    if [[ ! -s "${AUSEARCH_OUTPUT}" ]]; then

        printf '0 events\n'
        printf '    execve: 0 | file_access: 0 | network: 0 | other: 0\n'

        return
    fi

    while IFS= read -r -d '' block; do

        if [[ -z "${block}" ]]; then
            continue
        fi

        event_epoch="$(
            audit_epoch_from_block "${block}"
        )"

        if [[ -z "${event_epoch}" ]]; then
            continue
        fi

        if ! within_time_window "${event_epoch}"; then
            continue
        fi

        timestamp="$(
            epoch_to_iso8601_utc "${event_epoch}"
        )"

        audit_key="$(
            get_audit_key "${block}"
        )"

        executable="$(
            get_audit_executable "${block}"
        )"

        syscall="$(
            get_audit_syscall "${block}"
        )"

        # ---------------------------------------------------------------------
        # execve
        # ---------------------------------------------------------------------

        if grep -q 'type=EXECVE' <<< "${block}" ||
           [[ "${syscall}" == "execve" ]] ||
           [[ "${audit_key}" == "process_exec" ]]
        then

            command_line="$(
                get_execve_command_line "${block}"
            )"

            extra="$(
                jq -cn \
                    --arg syscall "execve" \
                    --arg executable "${executable}" \
                    --arg command_line "${command_line}" \
                    --arg audit_key "${audit_key}" \
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
                "${block}" \
                "${extra}"

            AUDIT_TOTAL=$((AUDIT_TOTAL + 1))
            EXECVE_COUNT=$((EXECVE_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # network
        # ---------------------------------------------------------------------

        if [[ "${audit_key}" == "network_connect" ]] ||
           [[ "${syscall}" == "socket" ]] ||
           [[ "${syscall}" == "connect" ]] ||
           grep -q 'type=SOCKADDR' <<< "${block}"
        then

            destination="$(
                get_network_destination "${block}"
            )"

            extra="$(
                jq -cn \
                    --arg syscall "${syscall}" \
                    --arg executable "${executable}" \
                    --arg destination "${destination}" \
                    --arg audit_key "${audit_key}" \
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
                "${block}" \
                "${extra}"

            AUDIT_TOTAL=$((AUDIT_TOTAL + 1))
            NETWORK_COUNT=$((NETWORK_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # file_access
        # ---------------------------------------------------------------------

        if grep -q 'type=PATH' <<< "${block}"; then

            path="$(
                get_file_path "${block}"
            )"

            extra="$(
                jq -cn \
                    --arg syscall "${syscall}" \
                    --arg path "${path}" \
                    --arg executable "${executable}" \
                    --arg audit_key "${audit_key}" \
                    '{
                        syscall: $syscall,
                        path: $path,
                        executable: $executable,
                        audit_key: $audit_key
                    }'
            )"

            emit_json_event \
                "${AUDIT_JSON}" \
                "${timestamp}" \
                "auditd" \
                "file_access" \
                "${block}" \
                "${extra}"

            AUDIT_TOTAL=$((AUDIT_TOTAL + 1))
            FILE_ACCESS_COUNT=$((FILE_ACCESS_COUNT + 1))

            continue
        fi

        # ---------------------------------------------------------------------
        # other audit event
        # ---------------------------------------------------------------------

        extra="$(
            jq -cn \
                --arg syscall "${syscall}" \
                --arg executable "${executable}" \
                --arg audit_key "${audit_key}" \
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
            "${block}" \
            "${extra}"

        AUDIT_TOTAL=$((AUDIT_TOTAL + 1))
        AUDIT_OTHER_COUNT=$((AUDIT_OTHER_COUNT + 1))

    done < <(
        awk '
            BEGIN {
                RS="----"
                ORS="\0"
            }

            NF {
                print
            }
        ' "${AUSEARCH_OUTPUT}"
    )

    printf '%d events\n' "${AUDIT_TOTAL}"

    printf '    execve: %d | file_access: %d | network: %d | other: %d\n' \
        "${EXECVE_COUNT}" \
        "${FILE_ACCESS_COUNT}" \
        "${NETWORK_COUNT}" \
        "${AUDIT_OTHER_COUNT}"
}

# =============================================================================
# syslog Parser
# =============================================================================

parse_syslog() {
    local line=""
    local event_epoch=""
    local timestamp=""
    local action=""
    local service=""
    local extra=""

    printf '[*] Parsing syslog... '

    if [[ ! -r "${SYSLOG}" ]]; then
        printf 'MISSING or unreadable\n'
        return
    fi

    while IFS= read -r line; do

        event_epoch="$(
            syslog_timestamp_to_epoch "${line}"
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
        # service start / stop
        # ---------------------------------------------------------------------

        if grep -Eqi \
            'systemd.*(Started|Starting|Stopped|Stopping)' \
            <<< "${line}"
        then

            if grep -Eqi '(Started|Starting)' <<< "${line}"; then
                action="start"
            else
                action="stop"
            fi

            service="$(
                sed -nE \
                    's/.*(Started|Starting|Stopped|Stopping)[[:space:]]+([^.]*)\.?.*/\2/p' \
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
        # error conditions
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
        # other syslog
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
# Start
# =============================================================================

printf '\n'
printf '==============================================\n'
printf 'MedDefense Linux Event Export\n'
printf '==============================================\n'
printf '\n'

printf '[*] Exporting Linux telemetry from last %s hours...\n' \
    "${HOURS}"

printf '    StartTime: %s\n' "${START_TIME}"
printf '    EndTime:   %s\n' "${END_TIME}"
printf '\n'

parse_auth_log
parse_audit_log
parse_syslog

# =============================================================================
# Total
# =============================================================================

TOTAL_EVENTS="$(
    cat \
        "${AUTH_JSON}" \
        "${AUDIT_JSON}" \
        "${SYSLOG_JSON}" |
        wc -l
)"

# =============================================================================
# Build linux_events_export.json
# =============================================================================

jq -s \
    --arg generated_at "$(
        date -u '+%Y-%m-%dT%H:%M:%SZ'
    )" \
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
    printf '\n'
    printf '[FAIL] Generated linux_events_export.json is invalid.\n'
    exit 1
fi

# =============================================================================
# Summary
# =============================================================================

printf '\n'
printf 'Total events: %s\n' "${TOTAL_EVENTS}"

printf 'Time range: %s to %s\n' \
    "${START_TIME}" \
    "${END_TIME}"

printf 'Output: %s\n' "${OUTPUT_FILE}"

printf '\n'
printf '[PASS] Linux telemetry export complete.\n'