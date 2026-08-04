#!/bin/bash

# MedDefense Health Systems - Post-Hardening Validator
#
# Purpose:
# Independently verifies the security controls implemented by Tasks 4-13.
#
# This script is READ-ONLY.
# It must never modify system configuration.
#
# Security objective:
# Detect configuration drift after the MedDefense Linux hardening baseline
# has been deployed.
#
# Exit codes:
#   0 = all validation checks passed
#   1 = one or more validation checks failed

set -euo pipefail

export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

# ---------------------------------------------------------------------------
# Generic validation helpers
# ---------------------------------------------------------------------------

pass_check() {
    local message="$1"

    echo "[PASS] ${message}"

    PASS_COUNT=$((PASS_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
}

fail_check() {
    local message="$1"

    echo "[FAIL] ${message}"

    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
}

compare_value() {
    local name="$1"
    local actual="$2"
    local expected="$3"

    if [[ "$actual" == "$expected" ]]; then
        pass_check "${name} = ${actual}"
    else
        fail_check "${name} = ${actual:-not_set} (expected: ${expected})"
    fi
}

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: run this validator with sudo." >&2
    exit 1
fi

echo "[*] MedDefense post-hardening validation"
echo

# ===========================================================================
# Task 4 - SSH hardening
# ===========================================================================

echo "[*] Task 4 - SSH hardening"

if command -v sshd >/dev/null 2>&1; then

    SSH_EFFECTIVE="$(sshd -T 2>/dev/null || true)"

    get_ssh_setting() {
        local setting="$1"

        awk -v key="$setting" '
            tolower($1) == tolower(key) {
                print $2
                exit
            }
        ' <<< "$SSH_EFFECTIVE"
    }

    compare_value \
        "PermitRootLogin" \
        "$(get_ssh_setting permitrootlogin)" \
        "no"

    compare_value \
        "PasswordAuthentication" \
        "$(get_ssh_setting passwordauthentication)" \
        "no"

    compare_value \
        "PermitEmptyPasswords" \
        "$(get_ssh_setting permitemptypasswords)" \
        "no"

    compare_value \
        "X11Forwarding" \
        "$(get_ssh_setting x11forwarding)" \
        "no"

    compare_value \
        "MaxAuthTries" \
        "$(get_ssh_setting maxauthtries)" \
        "3"

    compare_value \
        "ClientAliveInterval" \
        "$(get_ssh_setting clientaliveinterval)" \
        "300"

    compare_value \
        "ClientAliveCountMax" \
        "$(get_ssh_setting clientalivecountmax)" \
        "2"

    compare_value \
        "LoginGraceTime" \
        "$(get_ssh_setting logingracetime)" \
        "60"

    compare_value \
        "Banner" \
        "$(get_ssh_setting banner)" \
        "/etc/issue.net"

    ALLOW_USERS="$(
        awk '
            tolower($1) == "allowusers" {
                $1=""
                sub(/^[[:space:]]+/, "")
                print
                exit
            }
        ' <<< "$SSH_EFFECTIVE"
    )"

    compare_value \
        "AllowUsers" \
        "$ALLOW_USERS" \
        "medadmin sysadmin"

    # Modern OpenSSH implements SSH protocol 2 only.
    # The legacy "Protocol 2" directive may therefore not appear in sshd -T.
    if ssh -V 2>&1 | grep -qi "OpenSSH"; then
        pass_check "SSH Protocol = 2 only (modern OpenSSH)"
    else
        fail_check "SSH Protocol could not be verified"
    fi

else
    fail_check "sshd command unavailable"
fi

echo

# ===========================================================================
# Task 5 - Kernel/sysctl hardening
# ===========================================================================

echo "[*] Task 5 - Kernel/sysctl hardening"

SYSCTL_CHECKS=(
    "net.ipv4.ip_forward|0"
    "net.ipv4.conf.all.accept_redirects|0"
    "net.ipv4.conf.default.accept_redirects|0"
    "net.ipv4.conf.all.send_redirects|0"
    "net.ipv4.conf.all.accept_source_route|0"
    "net.ipv4.conf.all.log_martians|1"
    "net.ipv4.tcp_syncookies|1"
    "net.ipv4.icmp_echo_ignore_broadcasts|1"
    "net.ipv6.conf.all.disable_ipv6|1"
    "net.ipv6.conf.default.disable_ipv6|1"
    "kernel.randomize_va_space|2"
    "fs.suid_dumpable|0"
    "kernel.dmesg_restrict|1"
    "kernel.kptr_restrict|2"
)

for entry in "${SYSCTL_CHECKS[@]}"; do

    key="${entry%%|*}"
    expected="${entry##*|}"

    actual="$(sysctl -n "$key" 2>/dev/null || echo "unavailable")"

    compare_value "$key" "$actual" "$expected"
done

echo

# ===========================================================================
# Task 6 - Filesystem hardening
# ===========================================================================

echo "[*] Task 6 - Filesystem hardening"

check_mount_options() {
    local mount_point="$1"

    local options

    options="$(
        findmnt -n -o OPTIONS "$mount_point" 2>/dev/null ||
        true
    )"

    if [[ -z "$options" ]]; then
        fail_check "${mount_point} mount options unavailable"
        return
    fi

    for required_option in noexec nosuid nodev; do
        if grep -qw "$required_option" <<< "${options//,/ }"; then
            pass_check "${mount_point} contains ${required_option}"
        else
            fail_check \
                "${mount_point} missing ${required_option} (actual: ${options})"
        fi
    done
}

check_mount_options "/tmp"
check_mount_options "/var/tmp"
check_mount_options "/dev/shm"

if [[ -f /etc/cron.allow ]]; then
    pass_check "cron access restriction = /etc/cron.allow present"
else
    fail_check "cron access restriction = /etc/cron.allow missing"
fi

echo

# ===========================================================================
# Task 7 - Service minimization
# ===========================================================================

echo "[*] Task 7 - Service minimization"

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

for service_name in "${REQUIRED_SERVICES[@]}"; do

    if systemctl is-active --quiet "$service_name" 2>/dev/null; then
        pass_check "${service_name} = active"
    else
        fail_check "${service_name} = inactive (expected: active)"
    fi
done

echo

# ===========================================================================
# Task 8 - PAM hardening
# ===========================================================================

echo "[*] Task 8 - PAM hardening"

PWQUALITY_FILE="/etc/security/pwquality.conf"

check_config_setting() {
    local file="$1"
    local setting="$2"
    local expected="$3"

    if [[ ! -r "$file" ]]; then
        fail_check "${setting} = configuration file unavailable"
        return
    fi

    local actual

    actual="$(
        awk -F= -v key="$setting" '
            /^[[:space:]]*#/ {
                next
            }

            {
                left=$1
                gsub(/[[:space:]]/, "", left)

                if (left == key) {
                    value=$2
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                    print value
                    exit
                }
            }
        ' "$file"
    )"

    compare_value "$setting" "$actual" "$expected"
}

check_config_setting "$PWQUALITY_FILE" "minlen" "14"
check_config_setting "$PWQUALITY_FILE" "dcredit" "-1"
check_config_setting "$PWQUALITY_FILE" "ucredit" "-1"
check_config_setting "$PWQUALITY_FILE" "lcredit" "-1"
check_config_setting "$PWQUALITY_FILE" "ocredit" "-1"
check_config_setting "$PWQUALITY_FILE" "maxrepeat" "3"

if grep -Eq \
    '^[[:space:]]*reject_username([[:space:]]*=[[:space:]]*[1Yy][Ee][Ss]|[[:space:]]*)$' \
    "$PWQUALITY_FILE" 2>/dev/null; then

    pass_check "reject_username = enabled"
else
    fail_check "reject_username = not enabled"
fi

FAILLOCK_FILE="/etc/security/faillock.conf"

check_config_setting "$FAILLOCK_FILE" "deny" "5"
check_config_setting "$FAILLOCK_FILE" "unlock_time" "900"
check_config_setting "$FAILLOCK_FILE" "fail_interval" "900"

if grep -Eq \
    'pam_pwhistory\.so.*remember=12|remember=12.*pam_pwhistory\.so' \
    /etc/pam.d/common-password 2>/dev/null; then

    pass_check "Password history remember = 12"
else
    fail_check "Password history remember != 12"
fi

echo

# ===========================================================================
# Task 9 - AppArmor
# ===========================================================================

echo "[*] Task 9 - AppArmor"

if systemctl is-active --quiet apparmor 2>/dev/null; then
    pass_check "apparmor.service = active"
else
    fail_check "apparmor.service = inactive (expected: active)"
fi

if command -v aa-status >/dev/null 2>&1; then

    if aa-status --enabled >/dev/null 2>&1; then
        pass_check "AppArmor module = enabled"
    else
        fail_check "AppArmor module = disabled"
    fi

    ENFORCE_COUNT="$(
        aa-status 2>/dev/null |
        awk '/profiles are in enforce mode/ {print $1; exit}'
    )"

    if [[ "${ENFORCE_COUNT:-0}" =~ ^[0-9]+$ ]] &&
       (( ENFORCE_COUNT > 0 )); then

        pass_check "AppArmor enforce profiles = ${ENFORCE_COUNT}"
    else
        fail_check "AppArmor enforce profiles = 0"
    fi

else
    fail_check "aa-status command unavailable"
fi

echo

# ===========================================================================
# Task 10 + 11 - auditd and audit telemetry
# ===========================================================================

echo "[*] Tasks 10-11 - Audit telemetry"

if systemctl is-active --quiet auditd 2>/dev/null; then
    pass_check "auditd.service = active"
else
    fail_check "auditd.service = inactive (expected: active)"
fi

if command -v auditctl >/dev/null 2>&1; then

    AUDIT_RULES="$(auditctl -l 2>/dev/null || true)"

    REQUIRED_AUDIT_KEYS=(
        "identity"
        "pam_config"
        "sshd_config"
        "priv_esc"
        "sudoers"
        "suspicious_download"
        "meddefense_db"
        "meddefense_web"
        "startup_scripts"
    )

    for audit_key in "${REQUIRED_AUDIT_KEYS[@]}"; do

        if grep -Eq \
            "(-k[[:space:]]+${audit_key}|key=${audit_key})" \
            <<< "$AUDIT_RULES"; then

            pass_check "audit key ${audit_key} = loaded"
        else
            fail_check "audit key ${audit_key} = missing"
        fi
    done

else
    fail_check "auditctl command unavailable"
fi

if [[ -f "${SCRIPT_DIR:-.}/audit_validation.json" ]]; then

    if command -v jq >/dev/null 2>&1 &&
       jq -e '
           (.missed // 0) == 0
       ' "${SCRIPT_DIR:-.}/audit_validation.json" \
       >/dev/null 2>&1; then

        pass_check "audit coverage validation = no missed tests"
    else
        fail_check "audit coverage validation = failed or incomplete"
    fi
else
    fail_check "audit_validation.json = missing"
fi

echo

# ===========================================================================
# Task 12 - Logging
# ===========================================================================

echo "[*] Task 12 - Logging"

if systemctl is-active --quiet rsyslog 2>/dev/null; then
    pass_check "rsyslog.service = active"
else
    fail_check "rsyslog.service = inactive (expected: active)"
fi

for logfile in /var/log/auth.log /var/log/syslog; do

    if [[ -f "$logfile" ]]; then
        pass_check "${logfile} = present"

        actual_mode="$(stat -c '%a' "$logfile")"
        actual_owner="$(stat -c '%U:%G' "$logfile")"

        compare_value \
            "${logfile} permissions" \
            "$actual_mode" \
            "640"

        compare_value \
            "${logfile} ownership" \
            "$actual_owner" \
            "root:adm"
    else
        fail_check "${logfile} = missing"
    fi
done

RSYSLOG_CONFIG="/etc/rsyslog.d/30-meddefense.conf"

if [[ -r "$RSYSLOG_CONFIG" ]] &&
   grep -Fq '/var/log/auth.log' "$RSYSLOG_CONFIG"; then

    pass_check "auth.log rsyslog routing = configured"
else
    fail_check "auth.log rsyslog routing = missing"
fi

if [[ -r "$RSYSLOG_CONFIG" ]] &&
   grep -Fq '/var/log/syslog' "$RSYSLOG_CONFIG"; then

    pass_check "syslog rsyslog routing = configured"
else
    fail_check "syslog rsyslog routing = missing"
fi

LOGROTATE_CONFIG="/etc/logrotate.d/meddefense"

if [[ -r "$LOGROTATE_CONFIG" ]]; then

    if grep -Eq '^[[:space:]]*rotate[[:space:]]+90' \
        "$LOGROTATE_CONFIG"; then
        pass_check "auth.log retention = 90 rotations"
    else
        fail_check "auth.log retention = expected 90 rotations"
    fi

    if grep -Eq '^[[:space:]]*rotate[[:space:]]+60' \
        "$LOGROTATE_CONFIG"; then
        pass_check "syslog retention = 60 rotations"
    else
        fail_check "syslog retention = expected 60 rotations"
    fi

    if grep -Eq '^[[:space:]]*compress[[:space:]]*$' \
        "$LOGROTATE_CONFIG"; then
        pass_check "log compression = enabled"
    else
        fail_check "log compression = disabled"
    fi

else
    fail_check "MedDefense logrotate configuration = missing"
fi

echo

# ===========================================================================
# Task 13 - Firewall
# ===========================================================================

echo "[*] Task 13 - Firewall"

if command -v ufw >/dev/null 2>&1; then

    UFW_STATUS="$(ufw status verbose 2>/dev/null || true)"

    if grep -Fq "Status: active" <<< "$UFW_STATUS"; then
        pass_check "UFW status = active"
    else
        fail_check "UFW status = inactive (expected: active)"
    fi

    if grep -Eq \
        'Default: deny \(incoming\), allow \(outgoing\)' \
        <<< "$UFW_STATUS"; then

        pass_check "Default incoming = deny"
        pass_check "Default outgoing = allow"
    else
        fail_check "UFW default policy does not match expected baseline"
    fi

    if grep -Eq \
        '22/tcp.*ALLOW.*10\.10\.1\.0/24' \
        <<< "$UFW_STATUS"; then

        pass_check "SSH firewall rule = management network only"
    else
        fail_check \
            "SSH firewall rule = expected 10.10.1.0/24 -> 22/tcp"
    fi

    if grep -Eq \
        '80/tcp.*ALLOW' \
        <<< "$UFW_STATUS"; then

        pass_check "HTTP firewall rule = allowed"
    else
        fail_check "HTTP firewall rule = missing"
    fi

    if grep -Eq \
        '443/tcp.*ALLOW' \
        <<< "$UFW_STATUS"; then

        pass_check "HTTPS firewall rule = allowed"
    else
        fail_check "HTTPS firewall rule = missing"
    fi

    if grep -Eq \
        '3306/tcp.*ALLOW.*10\.10\.2\.0/24' \
        <<< "$UFW_STATUS"; then

        pass_check "MySQL firewall rule = application network only"
    else
        fail_check \
            "MySQL firewall rule = expected 10.10.2.0/24 -> 3306/tcp"
    fi

    if grep -Eq \
        'Logging:[[:space:]]+on' \
        <<< "$UFW_STATUS"; then

        pass_check "UFW logging = enabled"
    else
        fail_check "UFW logging = disabled"
    fi

else
    fail_check "UFW command unavailable"
fi

# ===========================================================================
# Final result
# ===========================================================================

echo
echo "=============================================="
echo "MedDefense Post-Hardening Validation Summary"
echo "=============================================="
echo "Checks executed: ${TOTAL_COUNT}"
echo "PASS: ${PASS_COUNT}"
echo "FAIL: ${FAIL_COUNT}"

if (( FAIL_COUNT == 0 )); then
    echo "Overall status: PASS"
    exit 0
else
    echo "Overall status: FAIL"
    exit 1
fi
