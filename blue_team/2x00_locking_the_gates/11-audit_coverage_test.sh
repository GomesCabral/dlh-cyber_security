#!/bin/bash

# MedDefense Health Systems - Audit Telemetry Coverage Test
#
# Purpose:
# Prove that Linux audit telemetry captures security-relevant actions used
# by the MedDefense SOC.
#
# Permanent Task 10 rules are tested where possible:
# - sudo execution       -> priv_esc
# - curl/wget execution  -> suspicious_download
#
# Read-only and test-artifact scenarios use temporary validation rules
# because Task 10 intentionally watches some sensitive files only for
# write/attribute changes.
#
# All temporary rules and files are removed during cleanup.

set -euo pipefail

export LC_ALL=C

OUTPUT_FILE="audit_validation.json"

TEST_DIR="/var/tmp/meddefense-audit-validation"
TEST_FILE="${TEST_DIR}/controlled-write.txt"
CRON_TEST_FILE="/etc/cron.d/meddefense-audit-validation"

TEMP_RESULT_FILE="$(mktemp)"

TEST_USER="meddefense-audit-test"

TEMP_RULES_ADDED=()

cleanup() {
    echo "[*] Cleaning test artifacts..."

    # Remove controlled test files and directories.
    rm -f "$TEST_FILE"
    rmdir "$TEST_DIR" 2>/dev/null || true

    # Remove the temporary cron validation file.
    rm -f "$CRON_TEST_FILE"

    # Defensive cleanup for any temporary audit test account.
    # The current validation workflow does not require creating this user,
    # but if a future test creates it, it must never remain on the system.
    if id "$TEST_USER" >/dev/null 2>&1; then
        userdel -r "$TEST_USER" >/dev/null 2>&1 || true
    fi

    # Remove only temporary validation audit rules created by this script.
    auditctl -W /etc/shadow \
        -p r \
        -k meddefense_shadow_read_test \
        >/dev/null 2>&1 || true

    auditctl -W /etc/ssh/sshd_config \
        -p r \
        -k meddefense_sshd_read_test \
        >/dev/null 2>&1 || true

    auditctl -W "$TEST_DIR" \
        -p wa \
        -k meddefense_file_test \
        >/dev/null 2>&1 || true

    auditctl -W /etc/cron.d \
        -p wa \
        -k meddefense_cron_test \
        >/dev/null 2>&1 || true

    rm -f "$TEMP_RESULT_FILE"
}

trap cleanup EXIT

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: run this script with sudo." >&2
    exit 1
fi

for command_name in auditctl ausearch python3; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Error: required command not found: ${command_name}" >&2
        exit 1
    fi
done

if ! systemctl is-active --quiet auditd; then
    echo "Error: auditd is not running." >&2
    exit 1
fi

echo "[*] Running audit telemetry coverage tests..."

# ---------------------------------------------------------------------------
# Confirm Task 10 permanent rules are present.
# ---------------------------------------------------------------------------

ACTIVE_RULES="$(auditctl -l)"

if ! grep -Fq "/usr/bin/sudo" <<< "$ACTIVE_RULES"; then
    echo "Error: Task 10 sudo audit rule is not loaded." >&2
    echo "Run Task 10 before Task 11." >&2
    exit 1
fi

DOWNLOAD_TOOL=""

if command -v curl >/dev/null 2>&1; then
    DOWNLOAD_TOOL="/usr/bin/curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOAD_TOOL="/usr/bin/wget"
else
    echo "Error: neither curl nor wget is available." >&2
    exit 1
fi

if ! grep -Fq "$DOWNLOAD_TOOL" <<< "$ACTIVE_RULES"; then
    echo "Error: Task 10 download-tool audit rule is not loaded." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Safe temporary validation rules.
# ---------------------------------------------------------------------------

mkdir -p "$TEST_DIR"
chmod 700 "$TEST_DIR"

# Task 10 watches /etc/shadow for writes/attribute changes.
# Add a temporary read rule so the requested read-access test does not
# modify the sensitive shadow file.
auditctl \
    -w /etc/shadow \
    -p r \
    -k meddefense_shadow_read_test

# Same principle for sshd_config: test read/metadata access without writing.
auditctl \
    -w /etc/ssh/sshd_config \
    -p r \
    -k meddefense_sshd_read_test

# Controlled test location. This avoids modifying production application data.
auditctl \
    -w "$TEST_DIR" \
    -p wa \
    -k meddefense_file_test

# Watch cron configuration only for the duration of the controlled test.
auditctl \
    -w /etc/cron.d \
    -p wa \
    -k meddefense_cron_test

# ---------------------------------------------------------------------------
# Result helper.
# ---------------------------------------------------------------------------

record_test() {
    local number="$1"
    local name="$2"
    local key="$3"
    local command_text="$4"
    local timestamp="$5"
    local rule_source="$6"

    # Give auditd a short period to flush the event.
    sleep 1

    local raw_events
    local event_count
    local excerpt
    local status

    raw_events="$(
        ausearch \
            -k "$key" \
            -ts "$timestamp" \
            --raw \
            2>/dev/null || true
    )"

    event_count="$(
        grep -c '^type=' <<< "$raw_events" || true
    )"

    if (( event_count > 0 )); then
        status="captured"

        excerpt="$(
            grep -E '^type=(SYSCALL|PATH|EXECVE|PROCTITLE)' \
                <<< "$raw_events" |
            head -n 2 |
            tr '\n' ' ' ||
            true
        )"
    else
        status="missed"
        excerpt=""
    fi

    python3 - \
        "$number" \
        "$name" \
        "$key" \
        "$command_text" \
        "$timestamp" \
        "$status" \
        "$event_count" \
        "$excerpt" \
        "$rule_source" \
        >> "$TEMP_RESULT_FILE" <<'PYTHON'
import json
import sys

(
    number,
    name,
    key,
    command,
    timestamp,
    status,
    count,
    excerpt,
    rule_source,
) = sys.argv[1:]

record = {
    "test_number": int(number),
    "test_name": name,
    "expected_audit_key": key,
    "command_executed": command,
    "timestamp": timestamp,
    "capture_status": status,
    "matching_event_count": int(count),
    "event_excerpt": excerpt,
    "rule_source": rule_source,
}

print(json.dumps(record))
PYTHON

    if [[ "$status" == "captured" ]]; then
        printf '[%s/6] %-32s [CAPTURED]\n' \
            "$number" \
            "$name"
    else
        printf '[%s/6] %-32s [MISSED]\n' \
            "$number" \
            "$name"
    fi
}

# ---------------------------------------------------------------------------
# Test 1 - privileged command execution through sudo
# Uses permanent Task 10 key: priv_esc
# ---------------------------------------------------------------------------

TEST_TIMESTAMP="$(date '+%H:%M:%S')"

sudo /usr/bin/true

record_test \
    "1" \
    "sudo execution" \
    "priv_esc" \
    "sudo /usr/bin/true" \
    "$TEST_TIMESTAMP" \
    "task10_permanent_rule"

# ---------------------------------------------------------------------------
# Test 2 - controlled /etc/shadow read
# ---------------------------------------------------------------------------

TEST_TIMESTAMP="$(date '+%H:%M:%S')"

head -c 1 /etc/shadow >/dev/null

record_test \
    "2" \
    "shadow access" \
    "meddefense_shadow_read_test" \
    "head -c 1 /etc/shadow >/dev/null" \
    "$TEST_TIMESTAMP" \
    "temporary_validation_rule"

# ---------------------------------------------------------------------------
# Test 3 - suspicious download utility execution
# Uses permanent Task 10 key: suspicious_download
# ---------------------------------------------------------------------------

TEST_TIMESTAMP="$(date '+%H:%M:%S')"

if [[ "$DOWNLOAD_TOOL" == "/usr/bin/curl" ]]; then
    curl --version >/dev/null
    DOWNLOAD_COMMAND="curl --version >/dev/null"
else
    wget --version >/dev/null
    DOWNLOAD_COMMAND="wget --version >/dev/null"
fi

record_test \
    "3" \
    "suspicious download tool" \
    "suspicious_download" \
    "$DOWNLOAD_COMMAND" \
    "$TEST_TIMESTAMP" \
    "task10_permanent_rule"

# ---------------------------------------------------------------------------
# Test 4 - read/metadata access to SSH configuration
# ---------------------------------------------------------------------------

TEST_TIMESTAMP="$(date '+%H:%M:%S')"

stat /etc/ssh/sshd_config >/dev/null

record_test \
    "4" \
    "sshd config read" \
    "meddefense_sshd_read_test" \
    "stat /etc/ssh/sshd_config >/dev/null" \
    "$TEST_TIMESTAMP" \
    "temporary_validation_rule"

# ---------------------------------------------------------------------------
# Test 5 - controlled write to monitored temporary location
# ---------------------------------------------------------------------------

TEST_TIMESTAMP="$(date '+%H:%M:%S')"

printf '%s\n' \
    "MedDefense controlled audit validation event" \
    > "$TEST_FILE"

record_test \
    "5" \
    "monitored test file write" \
    "meddefense_file_test" \
    "write controlled file under /var/tmp/meddefense-audit-validation" \
    "$TEST_TIMESTAMP" \
    "temporary_validation_rule"

# ---------------------------------------------------------------------------
# Test 6 - controlled cron configuration action
#
# This file contains only a comment. It does NOT create an executable cron
# job and is deleted automatically during cleanup.
# ---------------------------------------------------------------------------

TEST_TIMESTAMP="$(date '+%H:%M:%S')"

printf '%s\n' \
    "# MedDefense audit validation only - no cron command" \
    > "$CRON_TEST_FILE"

chmod 600 "$CRON_TEST_FILE"

record_test \
    "6" \
    "cron configuration check" \
    "meddefense_cron_test" \
    "create harmless comment-only /etc/cron.d validation file" \
    "$TEST_TIMESTAMP" \
    "temporary_validation_rule"

# ---------------------------------------------------------------------------
# Generate structured JSON report.
# ---------------------------------------------------------------------------

python3 - "$TEMP_RESULT_FILE" "$OUTPUT_FILE" <<'PYTHON'
import json
import sys
from pathlib import Path

input_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])

tests = []

for line in input_path.read_text(
    encoding="utf-8",
    errors="replace",
).splitlines():

    if line.strip():
        tests.append(json.loads(line))

captured = sum(
    test["capture_status"] == "captured"
    for test in tests
)

missed = len(tests) - captured

report = {
    "task": "11 - Audit Telemetry Coverage Test",
    "tests_executed": len(tests),
    "captured": captured,
    "missed": missed,
    "all_tests_passed": missed == 0,
    "tests": tests,
}

output_path.write_text(
    json.dumps(report, indent=2) + "\n",
    encoding="utf-8",
)
PYTHON

CAPTURED="$(
    python3 -c \
        'import json; print(json.load(open("audit_validation.json"))["captured"])'
)"

MISSED="$(
    python3 -c \
        'import json; print(json.load(open("audit_validation.json"))["missed"])'
)"

echo "Tests executed: 6"
echo "Captured: ${CAPTURED}"
echo "Missed: ${MISSED}"
echo "Report saved to: ${OUTPUT_FILE}"

if (( MISSED > 0 )); then
    exit 1
fi
