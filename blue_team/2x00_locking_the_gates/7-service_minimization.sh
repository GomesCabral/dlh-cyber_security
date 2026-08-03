#!/bin/bash

# MedDefense Health Systems - Service Minimizer
#
# Goal:
# Reduce the enabled service attack surface to only what is required by the
# MedDefense billing server role.
#
# Threat mapping:
# - Unnecessary services increase the number of reachable attack paths.
# - Addresses CIS Section 2 service minimization.
# - Supports remediation of 1x02 Finding 006: unnecessary network exposure.
#
# Safety:
# Use AUDIT_ONLY=1 when testing this Ubuntu 22.04 server profile on another OS.
#
# Example:
# sudo AUDIT_ONLY=1 ./7-service_minimization.sh
#
# Idempotency:
# Re-running the script leaves already-disabled services disabled and does
# not alter required services unnecessarily.

set -euo pipefail

export LC_ALL=C

AUDIT_ONLY="${AUDIT_ONLY:-0}"

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: run this script with sudo." >&2
    exit 1
fi

if [[ "$AUDIT_ONLY" != "0" && "$AUDIT_ONLY" != "1" ]]; then
    echo "Error: AUDIT_ONLY must be 0 or 1." >&2
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "Error: systemctl is required." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# MedDefense billing server service whitelist
# ---------------------------------------------------------------------------
#
# ssh.service
# Required for secure remote administration by approved administrators.
#
# apache2.service
# Required to provide the MedDefense billing web application.
#
# mysql.service
# Required for billing application database operations.
# Network exposure must still be restricted separately.
#
# ufw.service
# Required for host-based firewall enforcement.
#
# auditd.service
# Required for security auditing and privileged-action visibility.
#
# apparmor.service
# Required for mandatory access control and application confinement.
#
# cron.service
# Required for approved scheduled administrative and application tasks.
#
# rsyslog.service
# Required for local and centralized security logging.
#
# systemd-timesyncd.service
# Required for accurate system time, log correlation and incident analysis.
# ---------------------------------------------------------------------------

REQUIRED_SERVICES=(
    "ssh.service"
    "apache2.service"
    "mysql.service"
    "ufw.service"
    "auditd.service"
    "apparmor.service"
    "cron.service"
    "rsyslog.service"
    "systemd-timesyncd.service"
)

TEMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

BEFORE_FILE="${TEMP_DIR}/before.txt"
AFTER_FILE="${TEMP_DIR}/after.txt"

is_required_service() {
    local service="$1"
    local required

    for required in "${REQUIRED_SERVICES[@]}"; do
        if [[ "$service" == "$required" ]]; then
            return 0
        fi
    done

    return 1
}

echo "[*] Scanning enabled services..."

systemctl list-unit-files \
    --type=service \
    --state=enabled \
    --no-legend \
    --no-pager |
    awk '{print $1}' |
    sort -u > "$BEFORE_FILE"

BEFORE_COUNT="$(wc -l < "$BEFORE_FILE" | tr -d ' ')"

echo "    Enabled services found: ${BEFORE_COUNT}"
echo "[*] Comparing against MedDefense whitelist (${#REQUIRED_SERVICES[@]} required services)..."

DISABLED_COUNT=0

while IFS= read -r service; do
    [[ -n "$service" ]] || continue

    if is_required_service "$service"; then
        continue
    fi

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        printf '  %-28s [WOULD STOP] [WOULD DISABLE]\n' "$service"
        continue
    fi

    STOP_RESULT="[ALREADY STOPPED]"
    DISABLE_RESULT="[ALREADY DISABLED]"

    if systemctl is-active --quiet "$service"; then
        systemctl stop "$service"
        STOP_RESULT="[STOPPED]"
    fi

    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        systemctl disable "$service" >/dev/null
        DISABLE_RESULT="[DISABLED]"
        DISABLED_COUNT=$((DISABLED_COUNT + 1))
    fi

    printf '  %-28s %s %s\n' \
        "$service" \
        "$STOP_RESULT" \
        "$DISABLE_RESULT"

done < "$BEFORE_FILE"

echo "[*] Verifying required services..."

REQUIRED_FAILURES=0

for service in "${REQUIRED_SERVICES[@]}"; do

    if ! systemctl list-unit-files "$service" \
        --no-legend 2>/dev/null |
        grep -q "^${service}"; then

        printf '  %-28s [NOT INSTALLED]\n' "$service"
        REQUIRED_FAILURES=$((REQUIRED_FAILURES + 1))
        continue
    fi

    if systemctl is-active --quiet "$service"; then
        printf '  %-28s [ACTIVE]\n' "$service"
        continue
    fi

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        printf '  %-28s [INACTIVE]\n' "$service"
        REQUIRED_FAILURES=$((REQUIRED_FAILURES + 1))
        continue
    fi

    if systemctl start "$service"; then
        if systemctl is-active --quiet "$service"; then
            printf '  %-28s [STARTED] [ACTIVE]\n' "$service"
        else
            printf '  %-28s [FAILED]\n' "$service"
            REQUIRED_FAILURES=$((REQUIRED_FAILURES + 1))
        fi
    else
        printf '  %-28s [FAILED]\n' "$service"
        REQUIRED_FAILURES=$((REQUIRED_FAILURES + 1))
    fi

done

if [[ "$AUDIT_ONLY" == "1" ]]; then
    AFTER_COUNT="$BEFORE_COUNT"
else
    systemctl list-unit-files \
        --type=service \
        --state=enabled \
        --no-legend \
        --no-pager |
        awk '{print $1}' |
        sort -u > "$AFTER_FILE"

    AFTER_COUNT="$(wc -l < "$AFTER_FILE" | tr -d ' ')"
fi

echo
echo "Before: ${BEFORE_COUNT} | After: ${AFTER_COUNT} | Disabled: ${DISABLED_COUNT}"

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo "Mode: AUDIT ONLY - no services were changed"
fi

if (( REQUIRED_FAILURES > 0 )); then
    echo "Required service validation failures: ${REQUIRED_FAILURES}" >&2
fi
