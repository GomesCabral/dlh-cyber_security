#!/bin/bash

# MedDefense Health Systems - Filesystem Permission Hardening
#
# Threat mappings:
# - Unexpected SUID/SGID binaries may enable local privilege escalation
#   after Crimson Tide Phase 3 initial shell access.
# - World-writable files may allow attackers to modify scripts or
#   configurations executed by privileged services.
# - noexec, nosuid and nodev reduce abuse of temporary filesystems.
#
# Operational deviation:
# The SUID and SGID whitelist is based on a minimal Ubuntu 22.04 server.
# Package-specific privileged binaries must be reviewed before being added.
#
# Safety:
# Run first with:
# sudo AUDIT_ONLY=1 ./6-filesystem_hardening.sh
#
# Idempotency:
# Repeated execution does not duplicate fstab or cron configuration and
# produces the same final permissions and mount state.

set -euo pipefail

export LC_ALL=C

AUDIT_ONLY="${AUDIT_ONLY:-0}"

FSTAB="/etc/fstab"
FSTAB_BACKUP="/etc/fstab.bak"
CRON_ALLOW="/etc/cron.allow"
REPORT_FILE="6-filesystem_hardening.json"

BEGIN_FSTAB="# BEGIN MEDDEFENSE TEMP MOUNT HARDENING"
END_FSTAB="# END MEDDEFENSE TEMP MOUNT HARDENING"

OS_ID="unknown"
OS_VERSION="unknown"

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
fi

if [[ "$OS_ID" != "ubuntu" || "$OS_VERSION" != "22.04" ]]; then
    echo "[!] WARNING: This whitelist targets Ubuntu 22.04."
    echo "[!] Detected system: ${OS_ID} ${OS_VERSION}"

    if [[ "$AUDIT_ONLY" != "1" ]]; then
        echo "Error: remediation refused on a non-Ubuntu 22.04 system." >&2
        echo "Run safely with:" >&2
        echo "sudo AUDIT_ONLY=1 ./6-filesystem_hardening.sh" >&2
        exit 1
    fi
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: run this script with sudo." >&2
    exit 1
fi

for command_name in find stat chmod findmnt mount python3; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Error: required command not found: $command_name" >&2
        exit 1
    fi
done

if [[ "$AUDIT_ONLY" != "0" && "$AUDIT_ONLY" != "1" ]]; then
    echo "Error: AUDIT_ONLY must be 0 or 1." >&2
    exit 1
fi

TEMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

SUID_ALL="${TEMP_DIR}/suid_all.txt"
SUID_UNEXPECTED="${TEMP_DIR}/suid_unexpected.txt"
SGID_ALL="${TEMP_DIR}/sgid_all.txt"
SGID_UNEXPECTED="${TEMP_DIR}/sgid_unexpected.txt"
WORLD_WRITABLE="${TEMP_DIR}/world_writable.txt"
WORLD_FIXED="${TEMP_DIR}/world_fixed.txt"
MOUNT_RESULTS="${TEMP_DIR}/mount_results.txt"

touch \
    "$SUID_ALL" \
    "$SUID_UNEXPECTED" \
    "$SGID_ALL" \
    "$SGID_UNEXPECTED" \
    "$WORLD_WRITABLE" \
    "$WORLD_FIXED" \
    "$MOUNT_RESULTS"

# Known-safe SUID binaries for a minimal Ubuntu 22.04 server.
SUID_WHITELIST=(
    "/usr/bin/chfn"
    "/usr/bin/chsh"
    "/usr/bin/fusermount"
    "/usr/bin/fusermount3"
    "/usr/bin/gpasswd"
    "/usr/bin/mount"
    "/usr/bin/newgrp"
    "/usr/bin/passwd"
    "/usr/bin/pkexec"
    "/usr/bin/su"
    "/usr/bin/sudo"
    "/usr/bin/umount"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/polkit-1/polkit-agent-helper-1"
    "/usr/lib/snapd/snap-confine"
    "/usr/sbin/mount.cifs"
    "/usr/sbin/pppd"
)

# Known-safe SGID binaries for a minimal Ubuntu 22.04 server.
SGID_WHITELIST=(
    "/usr/bin/chage"
    "/usr/bin/crontab"
    "/usr/bin/expiry"
    "/usr/bin/ssh-agent"
    "/usr/bin/wall"
    "/usr/bin/write"
    "/usr/bin/write.ul"
    "/usr/lib/x86_64-linux-gnu/utempter/utempter"
    "/usr/sbin/pam_extrausers_chkpwd"
    "/usr/sbin/unix_chkpwd"
    "/usr/sbin/postdrop"
    "/usr/sbin/postqueue"
)

array_contains() {
    local expected="$1"
    shift

    local item

    for item in "$@"; do
        if [[ "$item" == "$expected" ]]; then
            return 0
        fi
    done

    return 1
}

echo "[*] Searching for SUID binaries..."

find / \
    \( -path /proc -o -path "/proc/*" \
   -o -path /sys -o -path "/sys/*" \
   -o -path /dev -o -path "/dev/*" \
   -o -path /run -o -path "/run/*" \
   -o -path /var/lib/docker -o -path "/var/lib/docker/*" \) -prune \
    -o -type f -perm -4000 -print \
    2>/dev/null |
    sort -u > "$SUID_ALL"

SUID_TOTAL="$(wc -l < "$SUID_ALL" | tr -d ' ')"
SUID_WHITELISTED=0
SUID_REMEDIATED=0

while IFS= read -r binary; do
    [[ -n "$binary" ]] || continue

    if array_contains "$binary" "${SUID_WHITELIST[@]}"; then
        SUID_WHITELISTED=$((SUID_WHITELISTED + 1))
    else
        printf '%s\n' "$binary" >> "$SUID_UNEXPECTED"
    fi
done < "$SUID_ALL"

SUID_NON_WHITELISTED="$(
    wc -l < "$SUID_UNEXPECTED" | tr -d ' '
)"

echo "Found ${SUID_TOTAL} SUID binaries"
echo "Whitelisted: ${SUID_WHITELISTED}"
echo "Non-whitelisted: ${SUID_NON_WHITELISTED}"

while IFS= read -r binary; do
    [[ -n "$binary" ]] || continue

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        printf '  %s [WOULD REMOVE SUID]\n' "$binary"
    else
        chmod u-s -- "$binary"

        if [[ ! -u "$binary" ]]; then
            printf '  %s [SUID REMOVED]\n' "$binary"
            SUID_REMEDIATED=$((SUID_REMEDIATED + 1))
        else
            printf '  %s [FAILED]\n' "$binary"
        fi
    fi
done < "$SUID_UNEXPECTED"

echo "[*] Searching for SGID binaries..."

find / \
    \( -path /proc -o -path "/proc/*" \
   -o -path /sys -o -path "/sys/*" \
   -o -path /dev -o -path "/dev/*" \
   -o -path /run -o -path "/run/*" \
   -o -path /var/lib/docker -o -path "/var/lib/docker/*" \) -prune \
    -o -type f -perm -2000 -print \
    2>/dev/null |
    sort -u > "$SGID_ALL"

SGID_TOTAL="$(wc -l < "$SGID_ALL" | tr -d ' ')"
SGID_WHITELISTED=0
SGID_REMEDIATED=0

while IFS= read -r binary; do
    [[ -n "$binary" ]] || continue

    if array_contains "$binary" "${SGID_WHITELIST[@]}"; then
        SGID_WHITELISTED=$((SGID_WHITELISTED + 1))
    else
        printf '%s\n' "$binary" >> "$SGID_UNEXPECTED"
    fi
done < "$SGID_ALL"

SGID_NON_WHITELISTED="$(
    wc -l < "$SGID_UNEXPECTED" | tr -d ' '
)"

echo "Found ${SGID_TOTAL} SGID binaries"
echo "Whitelisted: ${SGID_WHITELISTED}"
echo "Non-whitelisted: ${SGID_NON_WHITELISTED}"

while IFS= read -r binary; do
    [[ -n "$binary" ]] || continue

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        printf '  %s [WOULD REMOVE SGID]\n' "$binary"
    else
        chmod g-s -- "$binary"

        if [[ ! -g "$binary" ]]; then
            printf '  %s [SGID REMOVED]\n' "$binary"
            SGID_REMEDIATED=$((SGID_REMEDIATED + 1))
        else
            printf '  %s [FAILED]\n' "$binary"
        fi
    fi
done < "$SGID_UNEXPECTED"

echo "[*] Searching for world-writable files and directories..."

# Files are always assessed.
#
# Directories are assessed when world-writable and missing the sticky bit.
# /tmp, /var/tmp and /dev/shm mount roots are handled separately below.
find / \
    \( -path /proc -o -path "/proc/*" \
       -o -path /sys -o -path "/sys/*" \
       -o -path /dev -o -path "/dev/*" \
       -o -path /run -o -path "/run/*" \) -prune \
    -o \( \
        -type f -perm -0002 \
        -o \
        -type d -perm -0002 ! -perm -1000 \
    \) \
    ! -path /tmp \
    ! -path /var/tmp \
    ! -path /dev/shm \
    -print \
    2>/dev/null |
    sort -u > "$WORLD_WRITABLE"

WORLD_TOTAL="$(wc -l < "$WORLD_WRITABLE" | tr -d ' ')"
WORLD_FIXED_COUNT=0

echo "Found ${WORLD_TOTAL} unsafe world-writable entries"

while IFS= read -r path; do
    [[ -n "$path" ]] || continue

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        printf '  %s [WOULD FIX]\n' "$path"
        continue
    fi

    chmod o-w -- "$path"

    if [[ -d "$path" ]]; then
        # A shared directory that must remain world-writable should instead
        # be documented as an exception and protected with the sticky bit.
        :
    fi

    if [[ ! -w "$path" || ! -O "$path" ]]; then
        printf '  %s [FIXED]\n' "$path"
        printf '%s\n' "$path" >> "$WORLD_FIXED"
        WORLD_FIXED_COUNT=$((WORLD_FIXED_COUNT + 1))
    else
        # Confirm via numeric mode because root's write checks can be broad.
        mode="$(stat -c '%a' "$path")"
        other_digit="${mode: -1}"

        if (( (10#$other_digit & 2) == 0 )); then
            printf '  %s [FIXED]\n' "$path"
            printf '%s\n' "$path" >> "$WORLD_FIXED"
            WORLD_FIXED_COUNT=$((WORLD_FIXED_COUNT + 1))
        else
            printf '  %s [FAILED]\n' "$path"
        fi
    fi
done < "$WORLD_WRITABLE"

ensure_runtime_mount_options() {
    local target="$1"
    local current_options
    local missing_options=()
    local option

    if [[ ! -d "$target" ]]; then
        mkdir -p "$target"
        chmod 1777 "$target"
    fi

    if ! mountpoint -q "$target"; then
        if [[ "$AUDIT_ONLY" == "1" ]]; then
            printf '%-10s noexec,nosuid,nodev [WOULD APPLY]\n' "${target}:"
            printf '%s|would_apply\n' "$target" >> "$MOUNT_RESULTS"
            return
        fi

        mount --bind "$target" "$target"
    fi

    current_options="$(findmnt -no OPTIONS --target "$target" || true)"

    for option in noexec nosuid nodev; do
        if [[ ",${current_options}," != *",${option},"* ]]; then
            missing_options+=("$option")
        fi
    done

    if (( ${#missing_options[@]} == 0 )); then
        printf '%-10s noexec,nosuid,nodev [OK]\n' "${target}:"
        printf '%s|ok\n' "$target" >> "$MOUNT_RESULTS"
        return
    fi

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        printf '%-10s noexec,nosuid,nodev [WOULD APPLY]\n' "${target}:"
        printf '%s|would_apply\n' "$target" >> "$MOUNT_RESULTS"
        return
    fi

    mount -o remount,bind,noexec,nosuid,nodev "$target"

    current_options="$(findmnt -no OPTIONS --target "$target" || true)"

    if [[ ",${current_options}," == *",noexec,"* \
       && ",${current_options}," == *",nosuid,"* \
       && ",${current_options}," == *",nodev,"* ]]; then

        printf '%-10s noexec,nosuid,nodev [APPLIED]\n' "${target}:"
        printf '%s|applied\n' "$target" >> "$MOUNT_RESULTS"
    else
        printf '%-10s noexec,nosuid,nodev [FAILED]\n' "${target}:"
        printf '%s|failed\n' "$target" >> "$MOUNT_RESULTS"
        return 1
    fi
}

configure_persistent_mounts() {
    if [[ "$AUDIT_ONLY" == "1" ]]; then
        return
    fi

    if [[ ! -e "$FSTAB" ]]; then
        install -o root -g root -m 644 /dev/null "$FSTAB"
    fi

    if [[ ! -f "$FSTAB_BACKUP" ]]; then
        cp -a "$FSTAB" "$FSTAB_BACKUP"
    fi

    sed -i \
        "/^${BEGIN_FSTAB}$/,/^${END_FSTAB}$/d" \
        "$FSTAB"

    cat >> "$FSTAB" <<'EOF'

# BEGIN MEDDEFENSE TEMP MOUNT HARDENING

# Prevent execution, device creation and SUID/SGID privilege changes from
# temporary filesystems used by untrusted or compromised processes.
/tmp /tmp none bind 0 0
/tmp /tmp none remount,bind,noexec,nosuid,nodev 0 0

/var/tmp /var/tmp none bind 0 0
/var/tmp /var/tmp none remount,bind,noexec,nosuid,nodev 0 0

tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0

# END MEDDEFENSE TEMP MOUNT HARDENING
EOF

    if command -v findmnt >/dev/null 2>&1; then
        if ! findmnt --verify --tab-file "$FSTAB" >/dev/null; then
            echo "Error: generated /etc/fstab failed validation." >&2
            cp -a "$FSTAB_BACKUP" "$FSTAB"
            exit 1
        fi
    fi
}

echo "[*] Checking temporary filesystem mount options..."

ensure_runtime_mount_options "/tmp"
ensure_runtime_mount_options "/var/tmp"
ensure_runtime_mount_options "/dev/shm"

configure_persistent_mounts

echo "[*] Restricting cron access..."

AUTHORIZED_CRON_USERS=(
    "root"
    "medadmin"
    "sysadmin"
)

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    AUTHORIZED_CRON_USERS+=("$SUDO_USER")
fi

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo "  /etc/cron.allow [WOULD CONFIGURE]"
else
    CRON_TEMP="$(mktemp)"

    for user_name in "${AUTHORIZED_CRON_USERS[@]}"; do
        if getent passwd "$user_name" >/dev/null 2>&1; then
            printf '%s\n' "$user_name" >> "$CRON_TEMP"
        fi
    done

    sort -u "$CRON_TEMP" > "$CRON_ALLOW"
    rm -f "$CRON_TEMP"

    chown root:root "$CRON_ALLOW"
    chmod 600 "$CRON_ALLOW"

    # cron.deny is unnecessary once a strict allowlist is present.
    rm -f /etc/cron.deny

    echo "  /etc/cron.allow [CONFIGURED]"
fi

export REPORT_FILE
export AUDIT_ONLY
export SUID_TOTAL
export SUID_WHITELISTED
export SUID_NON_WHITELISTED
export SUID_REMEDIATED
export SGID_TOTAL
export SGID_WHITELISTED
export SGID_NON_WHITELISTED
export SGID_REMEDIATED
export WORLD_TOTAL
export WORLD_FIXED_COUNT
export SUID_UNEXPECTED
export SGID_UNEXPECTED
export WORLD_WRITABLE
export WORLD_FIXED
export MOUNT_RESULTS

python3 <<'PYTHON'
import json
import os
from pathlib import Path


def read_lines(environment_name):
    path = Path(os.environ[environment_name])

    if not path.exists():
        return []

    return [
        line
        for line in path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
        if line.strip()
    ]


mount_results = []

for line in read_lines("MOUNT_RESULTS"):
    target, status = line.split("|", 1)
    mount_results.append(
        {
            "mount_point": target,
            "status": status,
            "required_options": [
                "noexec",
                "nosuid",
                "nodev",
            ],
        }
    )

report = {
    "task": "6 - The Permission Sweep",
    "audit_only": os.environ["AUDIT_ONLY"] == "1",
    "suid": {
        "found": int(os.environ["SUID_TOTAL"]),
        "whitelisted": int(os.environ["SUID_WHITELISTED"]),
        "non_whitelisted": int(
            os.environ["SUID_NON_WHITELISTED"]
        ),
        "remediated": int(os.environ["SUID_REMEDIATED"]),
        "unexpected_binaries": read_lines("SUID_UNEXPECTED"),
    },
    "sgid": {
        "found": int(os.environ["SGID_TOTAL"]),
        "whitelisted": int(os.environ["SGID_WHITELISTED"]),
        "non_whitelisted": int(
            os.environ["SGID_NON_WHITELISTED"]
        ),
        "remediated": int(os.environ["SGID_REMEDIATED"]),
        "unexpected_binaries": read_lines("SGID_UNEXPECTED"),
    },
    "world_writable": {
        "found": int(os.environ["WORLD_TOTAL"]),
        "fixed": int(os.environ["WORLD_FIXED_COUNT"]),
        "identified_entries": read_lines("WORLD_WRITABLE"),
        "remediated_entries": read_lines("WORLD_FIXED"),
    },
    "temporary_mounts": mount_results,
    "cron_access": {
        "configuration_file": "/etc/cron.allow",
    },
}

Path(os.environ["REPORT_FILE"]).write_text(
    json.dumps(report, indent=2) + "\n",
    encoding="utf-8",
)
PYTHON

echo
echo "SUID remediated: ${SUID_REMEDIATED} | SGID remediated: ${SGID_REMEDIATED} | World-writable fixed: ${WORLD_FIXED_COUNT}"

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo "Mode: AUDIT ONLY - no changes were applied"
else
    echo "Mode: REMEDIATION"
fi

echo "JSON report: ${REPORT_FILE}"
