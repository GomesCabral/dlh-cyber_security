#!/bin/bash

# MedDefense Health Systems - AppArmor Enforcer
#
# Goal:
# Enforce Mandatory Access Control for network-exposed services and create
# a dedicated confinement profile for the MedDefense billing application.
#
# Threat mapping:
# - Limits filesystem access after Apache/application compromise.
# - Reduces the blast radius of zero-days in exposed services.
# - Prevents a compromised web process from freely accessing unrelated
#   patient, system or administrative data.
#
# Safety:
# AppArmor policies are highly application-specific. Test first with:
#
# sudo AUDIT_ONLY=1 ./9-apparmor_config.sh
#
# Target platform:
# Ubuntu 22.04 with AppArmor enabled.
#
# Idempotency:
# The custom profile is replaced deterministically and existing enforce
# profiles remain in enforce mode.

set -euo pipefail

export LC_ALL=C

AUDIT_ONLY="${AUDIT_ONLY:-0}"

CUSTOM_APP="/opt/meddefense/billing-app"
CUSTOM_PROFILE="/etc/apparmor.d/opt.meddefense.billing-app"

APACHE_PROFILE="/etc/apparmor.d/usr.sbin.apache2"
MYSQL_PROFILE="/etc/apparmor.d/usr.sbin.mysqld"

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: run this script with sudo." >&2
    exit 1
fi

if [[ "$AUDIT_ONLY" != "0" && "$AUDIT_ONLY" != "1" ]]; then
    echo "Error: AUDIT_ONLY must be 0 or 1." >&2
    exit 1
fi

OS_ID="unknown"
OS_VERSION="unknown"

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
fi

echo "[*] Detected platform: ${OS_ID} ${OS_VERSION}"

if [[ "$OS_ID" != "ubuntu" || "$OS_VERSION" != "22.04" ]]; then
    echo "[!] CIS deviation: AppArmor profile targets Ubuntu 22.04."

    if [[ "$AUDIT_ONLY" != "1" ]]; then
        echo "Error: refusing automatic AppArmor remediation on ${OS_ID} ${OS_VERSION}." >&2
        echo "Use AUDIT_ONLY=1 for safe inspection." >&2
        exit 1
    fi
fi

echo "[*] Checking AppArmor status..."

if ! command -v aa-status >/dev/null 2>&1; then
    echo "    AppArmor tools: NOT INSTALLED"

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        echo "    apparmor [WOULD INSTALL]"
        echo "    apparmor-utils [WOULD INSTALL]"
    else
        apt-get update
        DEBIAN_FRONTEND=noninteractive \
            apt-get install -y apparmor apparmor-utils
    fi
fi

if [[ -r /sys/module/apparmor/parameters/enabled ]]; then
    APPARMOR_KERNEL_STATUS="$(cat /sys/module/apparmor/parameters/enabled)"

    if [[ "$APPARMOR_KERNEL_STATUS" =~ [Yy] ]]; then
        echo "    AppArmor module: loaded"
    else
        echo "    AppArmor module: not enabled"
    fi
else
    echo "    AppArmor module: unavailable"
fi

if systemctl is-active --quiet apparmor 2>/dev/null; then
    echo "    AppArmor service: active"
else
    echo "    AppArmor service: inactive"

    if [[ "$AUDIT_ONLY" != "1" ]]; then
        systemctl enable --now apparmor
    fi
fi

echo "[*] Current AppArmor profiles..."

if command -v aa-status >/dev/null 2>&1; then
    aa-status || true
fi

profile_mode() {
    local profile_name="$1"

    if ! command -v aa-status >/dev/null 2>&1; then
        echo "unknown"
        return
    fi

    if aa-status 2>/dev/null |
        sed -n '/profiles are in enforce mode/,/profiles are in complain mode/p' |
        grep -Fq "$profile_name"; then

        echo "enforce"
        return
    fi

    if aa-status 2>/dev/null |
        sed -n '/profiles are in complain mode/,/processes have profiles defined/p' |
        grep -Fq "$profile_name"; then

        echo "complain"
        return
    fi

    echo "not_loaded"
}

enforce_profile() {
    local profile_path="$1"
    local display_name="$2"

    if [[ ! -f "$profile_path" ]]; then
        printf '    %-28s [PROFILE NOT FOUND]\n' "$display_name"
        return
    fi

    local current_mode
    current_mode="$(profile_mode "$display_name")"

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        if [[ "$current_mode" == "complain" ]]; then
            printf '    %-28s complain -> enforce [WOULD ENFORCE]\n' \
                "$display_name"
        elif [[ "$current_mode" == "enforce" ]]; then
            printf '    %-28s enforce [OK]\n' "$display_name"
        else
            printf '    %-28s %s [WOULD LOAD/ENFORCE]\n' \
                "$display_name" \
                "$current_mode"
        fi

        return
    fi

    aa-enforce "$profile_path" >/dev/null
    apparmor_parser -r "$profile_path"

    current_mode="$(profile_mode "$display_name")"

    if [[ "$current_mode" == "enforce" ]]; then
        printf '    %-28s [ENFORCED]\n' "$display_name"
    else
        printf '    %-28s [FAILED]\n' "$display_name"
    fi
}

echo "[*] Profile enforcement:"

enforce_profile "$APACHE_PROFILE" "/usr/sbin/apache2"
enforce_profile "$MYSQL_PROFILE" "/usr/sbin/mysqld"

if [[ "$AUDIT_ONLY" == "1" ]]; then
    if [[ -f "/etc/apparmor.d/usr.sbin.sshd" ]]; then
        SSH_MODE="$(profile_mode "/usr/sbin/sshd")"
        printf '    %-28s %s\n' "/usr/sbin/sshd" "$SSH_MODE"
    fi
fi

echo "[*] Custom profile: ${CUSTOM_APP}"

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo "    ${CUSTOM_PROFILE} [WOULD CREATE]"
else
    mkdir -p /opt/meddefense
    mkdir -p /var/log/meddefense
    mkdir -p /var/lib/meddefense
    mkdir -p /etc/meddefense

    cat > "$CUSTOM_PROFILE" <<'EOF'
#include <tunables/global>

/opt/meddefense/billing-app {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Allow execution of the MedDefense billing application.
  /opt/meddefense/billing-app rix,

  # Allow read-only access to application code and configuration.
  /opt/meddefense/** r,
  /etc/meddefense/** r,

  # Allow application runtime data only inside its dedicated data directory.
  /var/lib/meddefense/** rwk,

  # Allow application logging only inside its dedicated log directory.
  /var/log/meddefense/** rwk,

  # Allow required system libraries.
  /usr/lib/** mr,
  /lib/** mr,
  /lib64/** mr,

  # DNS and basic resolver access.
  /etc/hosts r,
  /etc/resolv.conf r,
  /etc/nsswitch.conf r,

  # Deny direct access to sensitive account databases.
  deny /etc/shadow r,
  deny /etc/gshadow r,

  # Deny access to home directories.
  deny /home/** rwklx,

  # Deny access to root-owned private data.
  deny /root/** rwklx,

  # Deny access to unrelated patient-data areas.
  deny /srv/patient-data/** rwklx,

  # Network access required by the application.
  network inet stream,
  network inet6 stream,
}
EOF

    chmod 644 "$CUSTOM_PROFILE"
    chown root:root "$CUSTOM_PROFILE"

    if apparmor_parser -Q "$CUSTOM_PROFILE"; then
        echo "    Syntax validation [PASS]"
    else
        echo "Error: custom AppArmor profile syntax is invalid." >&2
        exit 1
    fi

    apparmor_parser -r "$CUSTOM_PROFILE"

    if command -v aa-enforce >/dev/null 2>&1; then
        aa-enforce "$CUSTOM_PROFILE" >/dev/null
    fi

    echo "    ${CUSTOM_PROFILE} [CREATED] [ENFORCED]"
fi

echo "[*] Unconfined network-exposed processes:"

UNCONFINED_COUNT=0

while IFS= read -r pid process; do
    [[ -n "$pid" ]] || continue

    PROFILE_STATE=""

    if [[ -r "/proc/${pid}/attr/current" ]]; then
        PROFILE_STATE="$(cat "/proc/${pid}/attr/current" 2>/dev/null || true)"
    fi

    if [[ "$PROFILE_STATE" == "unconfined" || -z "$PROFILE_STATE" ]]; then
        printf '    %-28s [UNCONFINED - Profile recommended]\n' "$process"
        UNCONFINED_COUNT=$((UNCONFINED_COUNT + 1))
    fi
done < <(
    ss -lntupH 2>/dev/null |
        awk '
        {
            if (match($0, /pid=[0-9]+/)) {
                pid = substr($0, RSTART + 4, RLENGTH - 4)
            } else {
                next
            }

            if (match($0, /\("[^"]+"/)) {
                process = substr($0, RSTART + 2, RLENGTH - 3)
            } else {
                process = "unknown"
            }

            print pid, process
        }
        ' |
        sort -u
)

ENFORCE_COUNT=0
COMPLAIN_COUNT=0

if command -v aa-status >/dev/null 2>&1; then
    ENFORCE_COUNT="$(
        aa-status 2>/dev/null |
        awk '/profiles are in enforce mode/ {print $1; exit}'
    )"

    COMPLAIN_COUNT="$(
        aa-status 2>/dev/null |
        awk '/profiles are in complain mode/ {print $1; exit}'
    )"
fi

ENFORCE_COUNT="${ENFORCE_COUNT:-0}"
COMPLAIN_COUNT="${COMPLAIN_COUNT:-0}"

echo
echo "Profiles in enforce: ${ENFORCE_COUNT} | Complain: ${COMPLAIN_COUNT} | Unconfined: ${UNCONFINED_COUNT}"

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo "Mode: AUDIT ONLY - no AppArmor configuration was changed"
fi
