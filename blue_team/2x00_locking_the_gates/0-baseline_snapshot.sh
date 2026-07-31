#!/bin/bash

# MedDefense Health Systems - Linux Security Baseline
#
# Captures the system state before hardening.
# This baseline provides the evidence required to measure the security delta.
#
# Threat context:
# - Finding 009: SSH password authentication enabled
# - Finding 011: Unsupported Ubuntu installation
# - Finding 026: Outdated kernel with known CVEs
# - Crimson Tide: Initial access through exposed and misconfigured services
#
# This script is read-only and does not modify system configuration.

set -euo pipefail

export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/0-baseline_snapshot.json"
TEMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: this script must be run with sudo."
    echo "Usage: sudo ./0-baseline_snapshot.sh"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required to generate structured JSON output."
    exit 1
fi

echo "Capturing MedDefense Linux security baseline..."

# ---------------------------------------------------------------------------
# System identification
# Establishes which server and software versions were assessed.
# Addresses Finding 011 and Finding 026 by recording OS and kernel versions.
# ---------------------------------------------------------------------------

HOSTNAME_VALUE="$(hostname 2>/dev/null || echo "unknown")"

if [[ -r /etc/os-release ]]; then
    OS_VALUE="$(
        . /etc/os-release
        printf '%s' "${PRETTY_NAME:-unknown}"
    )"
else
    OS_VALUE="unknown"
fi

KERNEL_VALUE="$(uname -r 2>/dev/null || echo "unknown")"
UPTIME_VALUE="$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo "unknown")"
ARCHITECTURE_VALUE="$(uname -m 2>/dev/null || echo "unknown")"

# ---------------------------------------------------------------------------
# Running services
# Identifies unnecessary or exposed services that could provide an attacker
# with initial access, as observed in the Crimson Tide campaign.
# ---------------------------------------------------------------------------

if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units \
        --type=service \
        --state=running \
        --no-legend \
        --no-pager \
        > "${TEMP_DIR}/running_services.txt" 2>/dev/null || true
else
    service --status-all \
        > "${TEMP_DIR}/running_services.txt" 2>/dev/null || true
fi

# Remove blank lines without failing when the file is empty.
sed -i '/^[[:space:]]*$/d' "${TEMP_DIR}/running_services.txt"

# ---------------------------------------------------------------------------
# Open ports and listening sockets
# Detects services reachable by attackers and supports later attack-surface
# reduction for the patient portal, billing server and log server.
# ---------------------------------------------------------------------------

if command -v ss >/dev/null 2>&1; then
    ss -H -lntup > "${TEMP_DIR}/open_ports.txt" 2>/dev/null || true
elif command -v netstat >/dev/null 2>&1; then
    netstat -lntup > "${TEMP_DIR}/open_ports.txt" 2>/dev/null || true
else
    : > "${TEMP_DIR}/open_ports.txt"
fi

sed -i '/^[[:space:]]*$/d' "${TEMP_DIR}/open_ports.txt"

# ---------------------------------------------------------------------------
# SUID binaries
# SUID programs execute with the file owner's privileges and may be abused
# for local privilege escalation after an attacker gains initial access.
# ---------------------------------------------------------------------------

find / \
    \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune \
    -o -type f -perm -4000 -print \
    > "${TEMP_DIR}/suid_binaries.txt" 2>/dev/null || true

sort -u -o "${TEMP_DIR}/suid_binaries.txt" \
    "${TEMP_DIR}/suid_binaries.txt"

# ---------------------------------------------------------------------------
# SGID binaries
# SGID programs can provide elevated group privileges and must be reviewed
# as part of the MedDefense privilege-escalation attack surface.
# ---------------------------------------------------------------------------

find / \
    \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune \
    -o -type f -perm -2000 -print \
    > "${TEMP_DIR}/sgid_binaries.txt" 2>/dev/null || true

sort -u -o "${TEMP_DIR}/sgid_binaries.txt" \
    "${TEMP_DIR}/sgid_binaries.txt"

# ---------------------------------------------------------------------------
# World-writable files
# World-writable files may allow unauthorized modification, persistence or
# tampering with application data and scripts.
# /proc, /sys and /dev are excluded as required by the task.
# ---------------------------------------------------------------------------

find / \
    \( -path /proc -o -path '/proc/*' \
       -o -path /sys -o -path '/sys/*' \
       -o -path /dev -o -path '/dev/*' \) -prune \
    -o -type f -perm -0002 -print \
    > "${TEMP_DIR}/world_writable_files.txt" 2>/dev/null || true

sort -u -o "${TEMP_DIR}/world_writable_files.txt" \
    "${TEMP_DIR}/world_writable_files.txt"

# ---------------------------------------------------------------------------
# Security-relevant sysctl parameters
# Captures kernel-level protections for spoofing, redirects, source routing,
# memory protection and traffic forwarding.
# ---------------------------------------------------------------------------

SYSCTL_PARAMETERS=(
    "kernel.randomize_va_space"
    "kernel.kptr_restrict"
    "kernel.dmesg_restrict"
    "kernel.yama.ptrace_scope"
    "kernel.unprivileged_bpf_disabled"
    "kernel.sysrq"
    "fs.suid_dumpable"
    "fs.protected_hardlinks"
    "fs.protected_symlinks"
    "fs.protected_fifos"
    "fs.protected_regular"
    "net.ipv4.ip_forward"
    "net.ipv4.conf.all.send_redirects"
    "net.ipv4.conf.default.send_redirects"
    "net.ipv4.conf.all.accept_redirects"
    "net.ipv4.conf.default.accept_redirects"
    "net.ipv4.conf.all.secure_redirects"
    "net.ipv4.conf.default.secure_redirects"
    "net.ipv4.conf.all.accept_source_route"
    "net.ipv4.conf.default.accept_source_route"
    "net.ipv4.conf.all.rp_filter"
    "net.ipv4.conf.default.rp_filter"
    "net.ipv4.conf.all.log_martians"
    "net.ipv4.conf.default.log_martians"
    "net.ipv4.tcp_syncookies"
    "net.ipv6.conf.all.accept_redirects"
    "net.ipv6.conf.default.accept_redirects"
    "net.ipv6.conf.all.accept_source_route"
    "net.ipv6.conf.default.accept_source_route"
)

: > "${TEMP_DIR}/sysctl_parameters.txt"

for parameter in "${SYSCTL_PARAMETERS[@]}"; do
    if sysctl "$parameter" >/dev/null 2>&1; then
        sysctl "$parameter" >> "${TEMP_DIR}/sysctl_parameters.txt"
    else
        printf '%s = unavailable\n' "$parameter" \
            >> "${TEMP_DIR}/sysctl_parameters.txt"
    fi
done

# ---------------------------------------------------------------------------
# Effective SSH configuration
# Records whether password authentication, root login and other dangerous
# settings remain enabled.
# Addresses Finding 009 and Crimson Tide SSH lateral movement.
# ---------------------------------------------------------------------------

: > "${TEMP_DIR}/ssh_configuration.txt"

if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null | grep -E \
        '^(port|listenaddress|addressfamily|permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|kbdinteractiveauthentication|challengeresponseauthentication|maxauthtries|maxsessions|x11forwarding|allowtcpforwarding|allowagentforwarding|clientaliveinterval|clientalivecountmax|loglevel|usepam) ' \
        > "${TEMP_DIR}/ssh_configuration.txt" || true
fi

# Fallback if sshd -T is unavailable or returns no configuration.
if [[ ! -s "${TEMP_DIR}/ssh_configuration.txt" ]]; then
    if [[ -r /etc/ssh/sshd_config ]]; then
        grep -Ei \
            '^[[:space:]]*(Port|ListenAddress|AddressFamily|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|KbdInteractiveAuthentication|ChallengeResponseAuthentication|MaxAuthTries|MaxSessions|X11Forwarding|AllowTcpForwarding|AllowAgentForwarding|ClientAliveInterval|ClientAliveCountMax|LogLevel|UsePAM)[[:space:]]+' \
            /etc/ssh/sshd_config \
            > "${TEMP_DIR}/ssh_configuration.txt" || true
    fi
fi

# ---------------------------------------------------------------------------
# Active local user accounts
# Accounts with an interactive login shell represent identities that could
# be targeted, compromised or abused for persistence.
# ---------------------------------------------------------------------------

getent passwd | awk -F: '
    $7 !~ /(nologin|false|sync|shutdown|halt)$/ {
        print $1 ":" $3 ":" $4 ":" $6 ":" $7
    }
' > "${TEMP_DIR}/active_user_accounts.txt"

# Record users currently logged into the server.
who > "${TEMP_DIR}/logged_in_users.txt" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Sudo group membership
# Members of the sudo group possess administrative privileges and are
# high-value targets for credential theft and privilege escalation.
# ---------------------------------------------------------------------------

{
    getent group sudo | awk -F: '
        {
            count = split($4, users, ",")
            for (i = 1; i <= count; i++) {
                if (users[i] != "") {
                    print users[i]
                }
            }
        }
    '

    getent passwd | while IFS=: read -r username _ _ gid _; do
        primary_group="$(getent group "$gid" | cut -d: -f1)"

        if [[ "$primary_group" == "sudo" ]]; then
            printf '%s\n' "$username"
        fi
    done
} | sort -u > "${TEMP_DIR}/sudo_members.txt"

# ---------------------------------------------------------------------------
# Package and security control status
# Provides additional evidence about defensive services already installed.
# ---------------------------------------------------------------------------

{
    for service_name in auditd apparmor ufw fail2ban ssh apache2 nginx mysql; do
        if systemctl list-unit-files "${service_name}.service" \
            --no-legend 2>/dev/null | grep -q "^${service_name}.service"; then

            active_state="$(systemctl is-active "$service_name" 2>/dev/null || true)"
            enabled_state="$(systemctl is-enabled "$service_name" 2>/dev/null || true)"

            printf '%s|%s|%s\n' \
                "$service_name" \
                "${active_state:-unknown}" \
                "${enabled_state:-unknown}"
        fi
    done
} > "${TEMP_DIR}/security_services.txt"

# ---------------------------------------------------------------------------
# Generate machine-readable JSON output.
# Python is used only for safe JSON encoding; all collection logic remains
# inside this Bash hardening and assessment script.
# ---------------------------------------------------------------------------

export BASELINE_TEMP_DIR="$TEMP_DIR"
export BASELINE_OUTPUT_FILE="$OUTPUT_FILE"
export BASELINE_HOSTNAME="$HOSTNAME_VALUE"
export BASELINE_OS="$OS_VALUE"
export BASELINE_KERNEL="$KERNEL_VALUE"
export BASELINE_UPTIME="$UPTIME_VALUE"
export BASELINE_ARCHITECTURE="$ARCHITECTURE_VALUE"

python3 <<'PYTHON'
import datetime
import json
import os
from pathlib import Path

temp_dir = Path(os.environ["BASELINE_TEMP_DIR"])
output_file = Path(os.environ["BASELINE_OUTPUT_FILE"])


def read_lines(filename):
    path = temp_dir / filename

    if not path.exists():
        return []

    return [
        line.rstrip("\n")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def parse_key_value_lines(filename):
    result = {}

    for line in read_lines(filename):
        if " = " in line:
            key, value = line.split(" = ", 1)
        elif " " in line:
            key, value = line.split(None, 1)
        else:
            key, value = line, ""

        result[key.strip()] = value.strip()

    return result


def parse_accounts():
    accounts = []

    for line in read_lines("active_user_accounts.txt"):
        fields = line.split(":", 4)

        if len(fields) == 5:
            username, uid, gid, home, shell = fields

            accounts.append(
                {
                    "username": username,
                    "uid": int(uid) if uid.isdigit() else uid,
                    "gid": int(gid) if gid.isdigit() else gid,
                    "home_directory": home,
                    "login_shell": shell,
                }
            )

    return accounts


def parse_security_services():
    services = []

    for line in read_lines("security_services.txt"):
        fields = line.split("|", 2)

        if len(fields) == 3:
            name, active, enabled = fields
            services.append(
                {
                    "service": name,
                    "active_state": active,
                    "enabled_state": enabled,
                }
            )

    return services


running_services = read_lines("running_services.txt")
open_ports = read_lines("open_ports.txt")
suid_binaries = read_lines("suid_binaries.txt")
sgid_binaries = read_lines("sgid_binaries.txt")
world_writable_files = read_lines("world_writable_files.txt")
sudo_members = read_lines("sudo_members.txt")

baseline = {
    "metadata": {
        "project": "MedDefense Linux Hardening",
        "task": "0 - The Baseline Snapshot",
        "generated_at_utc": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
        "read_only_assessment": True,
        "output_file": str(output_file),
    },
    "system_identification": {
        "hostname": os.environ.get("BASELINE_HOSTNAME", "unknown"),
        "operating_system": os.environ.get("BASELINE_OS", "unknown"),
        "kernel_version": os.environ.get("BASELINE_KERNEL", "unknown"),
        "architecture": os.environ.get("BASELINE_ARCHITECTURE", "unknown"),
        "uptime": os.environ.get("BASELINE_UPTIME", "unknown"),
    },
    "summary": {
        "running_services": len(running_services),
        "open_listening_sockets": len(open_ports),
        "suid_binaries": len(suid_binaries),
        "sgid_binaries": len(sgid_binaries),
        "world_writable_files": len(world_writable_files),
        "active_local_accounts": len(parse_accounts()),
        "sudo_group_members": len(sudo_members),
    },
    "running_services": running_services,
    "open_ports_and_listening_sockets": open_ports,
    "privileged_binaries": {
        "suid": suid_binaries,
        "sgid": sgid_binaries,
    },
    "world_writable_files": world_writable_files,
    "sysctl_security_parameters": parse_key_value_lines(
        "sysctl_parameters.txt"
    ),
    "ssh_configuration": parse_key_value_lines(
        "ssh_configuration.txt"
    ),
    "identity_and_access": {
        "active_local_accounts": parse_accounts(),
        "currently_logged_in_users": read_lines(
            "logged_in_users.txt"
        ),
        "sudo_group_members": sudo_members,
    },
    "security_service_status": parse_security_services(),
}

output_file.write_text(
    json.dumps(baseline, indent=4, sort_keys=False) + "\n",
    encoding="utf-8",
)
PYTHON

if [[ ! -s "$OUTPUT_FILE" ]]; then
    echo "Error: the JSON baseline was not created."
    exit 1
fi

RUNNING_SERVICES_COUNT="$(
    wc -l < "${TEMP_DIR}/running_services.txt" | tr -d ' '
)"
OPEN_PORTS_COUNT="$(
    wc -l < "${TEMP_DIR}/open_ports.txt" | tr -d ' '
)"
SUID_COUNT="$(
    wc -l < "${TEMP_DIR}/suid_binaries.txt" | tr -d ' '
)"
SGID_COUNT="$(
    wc -l < "${TEMP_DIR}/sgid_binaries.txt" | tr -d ' '
)"
WORLD_WRITABLE_COUNT="$(
    wc -l < "${TEMP_DIR}/world_writable_files.txt" | tr -d ' '
)"

echo
echo "Hostname: ${HOSTNAME_VALUE}"
echo "OS: ${OS_VALUE}"
echo "Running services: ${RUNNING_SERVICES_COUNT}"
echo "Open ports: ${OPEN_PORTS_COUNT}"
echo "SUID binaries: ${SUID_COUNT}"
echo "SGID binaries: ${SGID_COUNT}"
echo "World-writable files: ${WORLD_WRITABLE_COUNT}"
echo
echo "Structured baseline saved to: ${OUTPUT_FILE}"
