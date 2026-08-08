#!/bin/bash

# name: 5-auditd_refine.sh
# purpose: Refine auditd telemetry with detection-focused process execution, network, SSH key, cron and sudoers rules and validate each rule.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 5 - auditd Rule Refinement
#
# Required detection-focused rules:
#
# Process execution via execve:
# -a always,exit -F arch=b64 -S execve -k process_exec
#
# Network socket creation:
# -a always,exit -F arch=b64 -S socket -S connect -k network_connect
#
# SSH key file access:
# -w /home/*/.ssh/ -p rwa -k ssh_keys
#
# Cron directory modifications:
# -w /etc/cron.d/ -p wa -k cron_persist
# -w /var/spool/cron/ -p wa -k cron_persist
#
# sudo configuration access:
# -w /etc/sudoers.d/ -p wa -k sudoers
#
# Validation:
# ausearch -k process_exec
# ausearch -k network_connect
# ausearch -k ssh_keys
# ausearch -k cron_persist
# ausearch -k sudoers
#
# Safety:
# Controlled validation artifacts are removed after testing.
# Existing audit rules are preserved.

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

RULES_FILE="/etc/audit/rules.d/meddefense-telemetry.rules"

PROCESS_KEY="process_exec"
NETWORK_KEY="network_connect"
SSH_KEY="ssh_keys"
CRON_KEY="cron_persist"
SUDOERS_KEY="sudoers"

RULE_GROUPS_ADDED=0
VALIDATION_PASS=0
VALIDATION_FAIL=0
TOTAL_VALIDATIONS=5

TEST_ID="meddefense_audit_test_$$"

CRON_TEST_FILE="/etc/cron.d/${TEST_ID}"
SUDOERS_TEST_FILE="/etc/sudoers.d/${TEST_ID}"

# =============================================================================
# Helper functions
# =============================================================================

log_info() {
    printf '[*] %s\n' "$1"
}

log_added() {
    printf '    %-40s [ADDED]\n' "$1"
}

log_present() {
    printf '    %-40s [PRESENT]\n' "$1"
}

log_warn() {
    printf '    %-40s [WARN]\n' "$1"
}

validation_pass() {
    printf '    %-68s [CAPTURED]\n' "$1"
    VALIDATION_PASS=$((VALIDATION_PASS + 1))
}

validation_fail() {
    printf '    %-68s [MISSED]\n' "$1"
    VALIDATION_FAIL=$((VALIDATION_FAIL + 1))
}

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "[FAIL] This script must be run with sudo/root privileges."
        echo "       Example: sudo ./5-auditd_refine.sh"
        exit 1
    fi
}

require_command() {
    local command_name="$1"

    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "[FAIL] Required command not found: ${command_name}"
        exit 1
    fi
}

rule_exists_in_file() {
    local rule="$1"

    grep -Fqx -- "${rule}" "${RULES_FILE}" 2>/dev/null
}

add_rule() {
    local rule="$1"

    if ! rule_exists_in_file "${rule}"; then
        printf '%s\n' "${rule}" >> "${RULES_FILE}"
        return 0
    fi

    return 1
}

search_audit_key() {
    local key="$1"

    ausearch \
        -k "${key}" \
        -ts recent \
        --interpret \
        2>/dev/null || true
}

cleanup() {
    rm -f "${CRON_TEST_FILE}" 2>/dev/null || true
    rm -f "${SUDOERS_TEST_FILE}" 2>/dev/null || true

    if [[ -n "${SSH_TEST_FILE:-}" ]]; then
        rm -f "${SSH_TEST_FILE}" 2>/dev/null || true
    fi
}

trap cleanup EXIT

# =============================================================================
# Prerequisites
# =============================================================================

require_root

require_command auditctl
require_command augenrules
require_command ausearch
require_command systemctl
require_command id
require_command touch
require_command getent

if ! systemctl is-active --quiet auditd; then
    echo "[FAIL] auditd service is not running."
    exit 1
fi

if [[ ! -d "/etc/audit/rules.d" ]]; then
    echo "[FAIL] /etc/audit/rules.d does not exist."
    exit 1
fi

touch "${RULES_FILE}"

chmod 0600 "${RULES_FILE}"

# =============================================================================
# Current auditd rule count
# =============================================================================

CURRENT_RULE_COUNT="$(
    auditctl -l 2>/dev/null |
        grep -cve '^[[:space:]]*$' || true
)"

log_info "Current auditd rules: ${CURRENT_RULE_COUNT}"

# =============================================================================
# Add detection-focused rules
# =============================================================================

log_info "Adding detection-focused rules..."

# -----------------------------------------------------------------------------
# Rule group 1: execve
# Linux equivalent of process creation telemetry.
# -----------------------------------------------------------------------------

PROCESS_RULE="-a always,exit -F arch=b64 -S execve -k process_exec"

if add_rule "${PROCESS_RULE}"; then
    log_added "execve syscall tracking"
else
    log_present "execve syscall tracking"
fi

RULE_GROUPS_ADDED=$((RULE_GROUPS_ADDED + 1))

# -----------------------------------------------------------------------------
# Rule group 2: socket/connect
# Detect network socket creation and outbound connection attempts.
# -----------------------------------------------------------------------------

NETWORK_RULE="-a always,exit -F arch=b64 -S socket -S connect -k network_connect"

if add_rule "${NETWORK_RULE}"; then
    log_added "socket/connect syscall tracking"
else
    log_present "socket/connect syscall tracking"
fi

RULE_GROUPS_ADDED=$((RULE_GROUPS_ADDED + 1))

# -----------------------------------------------------------------------------
# Rule group 3: SSH key monitoring
#
# Required project pattern:
# -w /home/*/.ssh/ -p rwa -k ssh_keys
#
# auditd watch paths do not expand shell wildcards. Therefore every existing
# /home/<user>/.ssh directory is converted into an explicit audit watch.
# -----------------------------------------------------------------------------

SSH_RULE_CREATED=false

while IFS=: read -r _ _ user_id _ _ home_dir _; do

    if [[ "${user_id}" -lt 1000 ]]; then
        continue
    fi

    ssh_dir="${home_dir}/.ssh"

    if [[ -d "${ssh_dir}" ]]; then

        ssh_rule="-w ${ssh_dir}/ -p rwa -k ssh_keys"

        if add_rule "${ssh_rule}"; then
            SSH_RULE_CREATED=true
        fi
    fi

done < /etc/passwd

# Also monitor root SSH keys if present.
if [[ -d "/root/.ssh" ]]; then

    if add_rule "-w /root/.ssh/ -p rwa -k ssh_keys"; then
        SSH_RULE_CREATED=true
    fi
fi

if [[ "${SSH_RULE_CREATED}" == "true" ]]; then
    log_added "SSH key file monitoring"
else
    log_present "SSH key file monitoring"
fi

RULE_GROUPS_ADDED=$((RULE_GROUPS_ADDED + 1))

# -----------------------------------------------------------------------------
# Rule group 4: cron persistence
# -----------------------------------------------------------------------------

CRON_RULE_CREATED=false

if [[ -d "/etc/cron.d" ]]; then

    if add_rule "-w /etc/cron.d/ -p wa -k cron_persist"; then
        CRON_RULE_CREATED=true
    fi
else
    log_warn "/etc/cron.d/ does not exist"
fi

if [[ -d "/var/spool/cron" ]]; then

    if add_rule "-w /var/spool/cron/ -p wa -k cron_persist"; then
        CRON_RULE_CREATED=true
    fi
else
    log_warn "/var/spool/cron/ does not exist"
fi

if [[ "${CRON_RULE_CREATED}" == "true" ]]; then
    log_added "Cron directory monitoring"
else
    log_present "Cron directory monitoring"
fi

RULE_GROUPS_ADDED=$((RULE_GROUPS_ADDED + 1))

# -----------------------------------------------------------------------------
# Rule group 5: sudoers configuration
# -----------------------------------------------------------------------------

if [[ -d "/etc/sudoers.d" ]]; then

    if add_rule "-w /etc/sudoers.d/ -p wa -k sudoers"; then
        log_added "sudoers.d monitoring"
    else
        log_present "sudoers.d monitoring"
    fi
else
    echo "[FAIL] /etc/sudoers.d/ does not exist."
    exit 1
fi

RULE_GROUPS_ADDED=$((RULE_GROUPS_ADDED + 1))

# =============================================================================
# Load updated rules
# =============================================================================

log_info "Loading rules..."

if augenrules --load >/dev/null 2>&1; then
    echo "    augenrules --load: OK"
else
    echo "    augenrules --load: FAILED"
    exit 1
fi

sleep 2

TOTAL_RULE_COUNT="$(
    auditctl -l 2>/dev/null |
        grep -cve '^[[:space:]]*$' || true
)"

log_info "Total rules: ${TOTAL_RULE_COUNT}"

# =============================================================================
# Confirm required keys are loaded
# =============================================================================

for required_key in \
    "${PROCESS_KEY}" \
    "${NETWORK_KEY}" \
    "${SSH_KEY}" \
    "${CRON_KEY}" \
    "${SUDOERS_KEY}"
do

    if ! auditctl -l | grep -Fq -- "-k ${required_key}"; then

        # auditctl may display keys in key= form depending on version.
        if ! auditctl -l | grep -Fq -- "key=${required_key}"; then
            log_warn "Loaded rule not found for key: ${required_key}"
        fi
    fi
done

# =============================================================================
# Validation
# =============================================================================

log_info "Validating new rules..."

# -----------------------------------------------------------------------------
# Test 1: execve
#
# Trigger:
# /usr/bin/id
#
# Search:
# ausearch -k process_exec
# -----------------------------------------------------------------------------

EXEC_TEST_START="$(date '+%H:%M:%S')"

/usr/bin/id >/dev/null

sleep 2

PROCESS_RESULTS="$(search_audit_key "${PROCESS_KEY}")"

if grep -Fq "/usr/bin/id" <<< "${PROCESS_RESULTS}" ||
   grep -Fq "comm=id" <<< "${PROCESS_RESULTS}"; then

    validation_pass \
        "execve: ran /usr/bin/id -> ausearch -k process_exec"
else

    validation_fail \
        "execve: ran /usr/bin/id -> ausearch -k process_exec"
fi

# Prevent shellcheck from considering the timestamp unused.
: "${EXEC_TEST_START}"

# -----------------------------------------------------------------------------
# Test 2: socket/connect
#
# Required project trigger:
# curl localhost
#
# This creates socket/connect activity without requiring Internet access.
# -----------------------------------------------------------------------------

if command -v curl >/dev/null 2>&1; then

    curl \
        --max-time 3 \
        --silent \
        --output /dev/null \
        http://127.0.0.1/ \
        2>/dev/null || true

else

    # Safe fallback if curl is unavailable.
    timeout 2 bash -c \
        'exec 3<>/dev/tcp/127.0.0.1/80' \
        >/dev/null 2>&1 || true
fi

sleep 2

NETWORK_RESULTS="$(search_audit_key "${NETWORK_KEY}")"

if grep -Eq 'comm="?curl"?|exe="/usr/bin/curl"|syscall=(socket|connect)' \
    <<< "${NETWORK_RESULTS}"; then

    validation_pass \
        "socket: curl localhost -> ausearch -k network_connect"
else

    validation_fail \
        "socket: curl localhost -> ausearch -k network_connect"
fi

# -----------------------------------------------------------------------------
# Test 3: SSH key access
#
# Required project trigger:
# touch ~/.ssh/test
# -----------------------------------------------------------------------------

TEST_USER="${SUDO_USER:-root}"

TEST_HOME="$(
    getent passwd "${TEST_USER}" |
        cut -d: -f6
)"

if [[ -z "${TEST_HOME}" ]]; then
    TEST_HOME="/root"
fi

SSH_TEST_DIR="${TEST_HOME}/.ssh"

# Only validate if this directory already exists and therefore has a watch.
if [[ -d "${SSH_TEST_DIR}" ]]; then

    SSH_TEST_FILE="${SSH_TEST_DIR}/${TEST_ID}"

    touch "${SSH_TEST_FILE}"

    # Generate read + attribute/write activity.
    cat "${SSH_TEST_FILE}" >/dev/null
    chmod 0600 "${SSH_TEST_FILE}"

    sleep 2

    SSH_RESULTS="$(search_audit_key "${SSH_KEY}")"

    if grep -Fq "${TEST_ID}" <<< "${SSH_RESULTS}"; then

        validation_pass \
            "ssh_keys: touch ~/.ssh/test -> ausearch -k ssh_keys"
    else

        validation_fail \
            "ssh_keys: touch ~/.ssh/test -> ausearch -k ssh_keys"
    fi

else

    validation_fail \
        "ssh_keys: touch ~/.ssh/test -> ausearch -k ssh_keys"
fi

# -----------------------------------------------------------------------------
# Test 4: cron persistence
#
# Required project trigger:
# touch /etc/cron.d/test
# -----------------------------------------------------------------------------

if [[ -d "/etc/cron.d" ]]; then

    touch "${CRON_TEST_FILE}"

    sleep 2

    CRON_RESULTS="$(search_audit_key "${CRON_KEY}")"

    if grep -Fq "${TEST_ID}" <<< "${CRON_RESULTS}"; then

        validation_pass \
            "cron: touch /etc/cron.d/test -> ausearch -k cron_persist"
    else

        validation_fail \
            "cron: touch /etc/cron.d/test -> ausearch -k cron_persist"
    fi

else

    validation_fail \
        "cron: touch /etc/cron.d/test -> ausearch -k cron_persist"
fi

# -----------------------------------------------------------------------------
# Test 5: sudo configuration
#
# Required project trigger:
# touch /etc/sudoers.d/test
# -----------------------------------------------------------------------------

touch "${SUDOERS_TEST_FILE}"

sleep 2

SUDOERS_RESULTS="$(search_audit_key "${SUDOERS_KEY}")"

if grep -Fq "${TEST_ID}" <<< "${SUDOERS_RESULTS}"; then

    validation_pass \
        "sudoers: touch /etc/sudoers.d/test -> ausearch -k sudoers"
else

    validation_fail \
        "sudoers: touch /etc/sudoers.d/test -> ausearch -k sudoers"
fi

# =============================================================================
# Cleanup
# =============================================================================

log_info "Cleanup: removing controlled test artifacts..."

cleanup

# =============================================================================
# Summary
# =============================================================================

echo
echo "Rules added: ${RULE_GROUPS_ADDED} | Validation: ${VALIDATION_PASS}/${TOTAL_VALIDATIONS} PASS"

if [[ "${VALIDATION_FAIL}" -eq 0 &&
      "${VALIDATION_PASS}" -eq "${TOTAL_VALIDATIONS}" ]]; then

    echo "[PASS] auditd detection-focused telemetry validation complete."
    exit 0
fi

echo "[FAIL] ${VALIDATION_FAIL} auditd validation test(s) were MISSED."
exit 1