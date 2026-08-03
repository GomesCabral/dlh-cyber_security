#!/bin/bash

# MedDefense Health Systems - Kernel Shield
#
# Hardens the Linux network stack and memory protections using sysctl.
#
# Threat mappings:
# - Disable IP forwarding to prevent a compromised server becoming a pivot
#   router during Crimson Tide Phase 3 lateral movement.
# - Reject ICMP redirects and source-routed packets to prevent traffic
#   manipulation and malicious route changes.
# - Enable SYN cookies to reduce exposure to SYN flood denial-of-service.
# - Enable ASLR and restrict kernel information exposure to make memory
#   corruption and local privilege-escalation attacks less reliable.
#
# Operational note:
# IPv6 is disabled because this project defines an IPv4-only MedDefense
# server profile. If production requires IPv6, this setting must be documented
# as a CIS deviation and protected with equivalent IPv6 firewall controls.
#
# Idempotency:
# A managed configuration block is replaced rather than duplicated.
# Running this script repeatedly produces the same final configuration.

set -euo pipefail

export LC_ALL=C

SYSCTL_FILE="/etc/sysctl.conf"
BACKUP_FILE="/etc/sysctl.conf.bak"

BEGIN_MARKER="# BEGIN MEDDEFENSE KERNEL HARDENING"
END_MARKER="# END MEDDEFENSE KERNEL HARDENING"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: this script must be run with sudo." >&2
    echo "Usage: sudo ./5-sysctl_hardening.sh" >&2
    exit 1
fi

if [[ ! -e "$SYSCTL_FILE" ]]; then
    echo "[*] ${SYSCTL_FILE} does not exist; creating it."
    install -o root -g root -m 644 /dev/null "$SYSCTL_FILE"
fi

if ! command -v sysctl >/dev/null 2>&1; then
    echo "Error: sysctl is not installed." >&2
    exit 1
fi

# The order is intentional and matches the project expected output.
PARAMETERS=(
    "net.ipv4.ip_forward=0"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.conf.all.log_martians=1"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    "net.ipv6.conf.all.disable_ipv6=1"
    "net.ipv6.conf.default.disable_ipv6=1"
    "kernel.randomize_va_space=2"
    "fs.suid_dumpable=0"
    "kernel.dmesg_restrict=1"
    "kernel.kptr_restrict=2"
)

ROLLBACK_FILE="$(mktemp)"

cleanup() {
    rm -f "$ROLLBACK_FILE"
}

rollback() {
    echo "[!] Restoring the previous sysctl configuration..." >&2
    cp -a "$ROLLBACK_FILE" "$SYSCTL_FILE"

    # Best-effort restoration of the previous runtime values.
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "[*] Backing up /etc/sysctl.conf"

# Preserve the original backup. Re-running the script must not overwrite it
# with an already hardened configuration.
if [[ ! -f "$BACKUP_FILE" ]]; then
    cp -a "$SYSCTL_FILE" "$BACKUP_FILE"
fi

# This temporary copy represents the state immediately before this run and
# is used for automatic rollback if applying the configuration fails.
cp -a "$SYSCTL_FILE" "$ROLLBACK_FILE"

echo "[*] Applying kernel hardening parameters..."

# Remove the previous managed block so the script remains idempotent.
sed -i \
    "/^${BEGIN_MARKER}$/,/^${END_MARKER}$/d" \
    "$SYSCTL_FILE"

cat >> "$SYSCTL_FILE" <<'EOF'

# BEGIN MEDDEFENSE KERNEL HARDENING

# Prevent this server from routing attacker traffic between network segments.
# Addresses Crimson Tide Phase 3 pivoting and lateral movement.
net.ipv4.ip_forward = 0

# Reject ICMP redirects to prevent malicious route manipulation.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Production servers must not advertise ICMP redirects.
net.ipv4.conf.all.send_redirects = 0

# Reject source-routed packets that allow senders to influence network paths.
net.ipv4.conf.all.accept_source_route = 0

# Log packets with impossible or suspicious source addresses.
net.ipv4.conf.all.log_martians = 1

# Protect the TCP stack against SYN flood resource exhaustion.
net.ipv4.tcp_syncookies = 1

# Ignore broadcast ICMP echo requests to prevent Smurf-style amplification.
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable IPv6 for the MedDefense IPv4-only server profile.
# Compensating control if IPv6 is required: retain IPv6 and enforce equivalent
# IPv6 firewall, redirect and source-route protections.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Enable full ASLR to make memory-corruption exploitation less predictable.
kernel.randomize_va_space = 2

# Prevent privileged SUID processes from generating sensitive core dumps.
fs.suid_dumpable = 0

# Restrict unprivileged access to kernel diagnostic messages.
kernel.dmesg_restrict = 1

# Hide kernel pointer addresses from unprivileged users.
kernel.kptr_restrict = 2

# END MEDDEFENSE KERNEL HARDENING
EOF

# Apply /etc/sysctl.conf immediately as required by the task.
if ! sysctl -p "$SYSCTL_FILE" >/dev/null; then
    echo "Error: sysctl -p failed." >&2
    rollback
    exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

verify_parameter() {
    local parameter="$1"
    local expected_value="$2"
    local proc_path
    local actual_value

    proc_path="/proc/sys/${parameter//./\/}"

    if [[ -r "$proc_path" ]]; then
        actual_value="$(<"$proc_path")"
        actual_value="${actual_value//$'\n'/}"
    else
        actual_value="unavailable"
    fi

    if [[ "$actual_value" == "$expected_value" ]]; then
        printf '%-47s [PASS]\n' \
            "${parameter} = ${expected_value}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf '%-47s [FAIL: actual=%s]\n' \
            "${parameter} = ${expected_value}" \
            "$actual_value"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

for parameter_entry in "${PARAMETERS[@]}"; do
    parameter="${parameter_entry%%=*}"
    expected_value="${parameter_entry#*=}"

    verify_parameter "$parameter" "$expected_value"
done

echo "Parameters applied: ${#PARAMETERS[@]}"
echo "Verified PASS: ${PASS_COUNT}"
echo "Verified FAIL: ${FAIL_COUNT}"

if (( FAIL_COUNT > 0 )); then
    echo "Error: one or more kernel parameters failed validation." >&2
    rollback
    exit 1
fi
