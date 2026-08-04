#!/bin/bash

# MedDefense Health Systems - Firewall Baseline
#
# Configures a host-based firewall using UFW.
#
# Threat mappings:
# - Default-deny inbound reduces externally reachable attack surface.
# - SSH is restricted to the management network to limit administrative
#   exposure and Crimson Tide-style lateral movement.
# - MySQL is restricted to the application network to address exposed
#   database services such as Finding 006.
# - HTTP/HTTPS remain reachable for the MedDefense web application.
# - Denied connections are logged for SOC visibility.
#
# Safety:
# The MedDefense network policy assumes:
# - Management network: 10.10.1.0/24
# - Application network: 10.10.2.0/24
#
# Test safely on another lab host with:
# sudo AUDIT_ONLY=1 ./13-firewall_baseline.sh
#
# Idempotency:
# Existing MedDefense UFW rules are checked before being added.

set -euo pipefail

export LC_ALL=C

AUDIT_ONLY="${AUDIT_ONLY:-0}"

MANAGEMENT_NET="10.10.1.0/24"
APPLICATION_NET="10.10.2.0/24"

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: run this script with sudo." >&2
    exit 1
fi

if [[ "$AUDIT_ONLY" != "0" && "$AUDIT_ONLY" != "1" ]]; then
    echo "Error: AUDIT_ONLY must be 0 or 1." >&2
    exit 1
fi

echo "[*] Checking firewall tooling..."

if command -v ufw >/dev/null 2>&1; then
    echo "    UFW: installed"
else
    if [[ "$AUDIT_ONLY" == "1" ]]; then
        echo "    UFW [WOULD INSTALL]"
    else
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
        echo "    UFW [INSTALLED]"
    fi
fi

echo "[*] Configuring UFW..."

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo "    Default incoming: deny    [WOULD SET]"
    echo "    Default outgoing: allow  [WOULD SET]"
else
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null

    echo "    Default incoming: deny"
    echo "    Default outgoing: allow"
fi

rule_exists() {
    local pattern="$1"

    ufw status numbered 2>/dev/null |
        grep -Fq "$pattern"
}

add_rule() {
    local description="$1"
    shift

    local check_pattern="$1"
    shift

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        printf '    %-42s [WOULD ADD]\n' "$description"
        return
    fi

    if rule_exists "$check_pattern"; then
        printf '    %-42s [EXISTS]\n' "$description"
        return
    fi

    ufw "$@" >/dev/null

    printf '    %-42s [ADDED]\n' "$description"
}

echo "[*] Adding allow rules..."

add_rule \
    "22/tcp from ${MANAGEMENT_NET} SSH - management only" \
    "22/tcp" \
    allow from "$MANAGEMENT_NET" to any port 22 proto tcp

add_rule \
    "80/tcp HTTP" \
    "80/tcp" \
    allow 80/tcp

add_rule \
    "443/tcp HTTPS" \
    "443/tcp" \
    allow 443/tcp

add_rule \
    "3306/tcp from ${APPLICATION_NET} MySQL - app network only" \
    "3306/tcp" \
    allow from "$APPLICATION_NET" to any port 3306 proto tcp

echo "[*] Enabling logging..."

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo "    Logging: on (low) [WOULD SET]"
else
    ufw logging low >/dev/null
    echo "    Logging: on (low)"
fi

echo "[*] Activating firewall..."

if [[ "$AUDIT_ONLY" == "1" ]]; then
    if ufw status 2>/dev/null | grep -q '^Status: active'; then
        echo "    UFW: active"
    else
        echo "    UFW: inactive [WOULD ENABLE]"
    fi
else
    ufw --force enable >/dev/null

    if ufw status | grep -q '^Status: active'; then
        echo "    UFW: active"
    else
        echo "Error: UFW failed to become active." >&2
        exit 1
    fi
fi

echo "[*] Validating active ruleset..."

if command -v ufw >/dev/null 2>&1; then
    ufw status verbose || true
fi

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo
    echo "Mode: AUDIT ONLY - firewall configuration was not modified"
else
    ALLOW_COUNT="$(
        ufw status |
        grep -c 'ALLOW' || true
    )"

    echo
    echo "Rules: ${ALLOW_COUNT} allow, default deny"
fi
