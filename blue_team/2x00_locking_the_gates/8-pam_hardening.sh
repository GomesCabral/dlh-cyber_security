#!/bin/bash

# MedDefense Health Systems - PAM Fortress
#
# Hardens Linux authentication through PAM.
#
# Threat mappings:
# - Weak passwords increase the likelihood of successful credential attacks.
# - Crimson Tide Phase 2 used harvested credentials.
# - Crimson Tide Phase 3 used compromised credentials for lateral movement.
# - Account lockout limits repeated password guessing.
# - Password history prevents users from immediately reusing old passwords.
#
# Target platform:
# Ubuntu 22.04 / Debian PAM stack.
#
# Safety:
# PAM errors may prevent login or sudo access.
# Test first with:
#
# sudo AUDIT_ONLY=1 ./8-pam_hardening.sh
#
# Idempotency:
# Managed configuration files are updated by replacing existing settings
# rather than appending duplicate directives.

set -euo pipefail

export LC_ALL=C

AUDIT_ONLY="${AUDIT_ONLY:-0}"

PWQUALITY_FILE="/etc/security/pwquality.conf"
FAILLOCK_FILE="/etc/security/faillock.conf"
PWHISTORY_FILE="/etc/security/pwhistory.conf"

COMMON_AUTH="/etc/pam.d/common-auth"
COMMON_ACCOUNT="/etc/pam.d/common-account"
COMMON_PASSWORD="/etc/pam.d/common-password"

BACKUP_DIR="/etc/pam.d/meddefense-backup"

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: run this script with sudo." >&2
    exit 1
fi

if [[ "$AUDIT_ONLY" != "0" && "$AUDIT_ONLY" != "1" ]]; then
    echo "Error: AUDIT_ONLY must be 0 or 1." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

set_config_value() {
    local file="$1"
    local key="$2"
    local value="$3"

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        printf '    %-32s [WOULD SET]\n' "${key} = ${value}"
        return
    fi

    touch "$file"

    if grep -Eq "^[[:space:]#]*${key}[[:space:]]*=" "$file"; then

        sed -Ei \
            "s|^[[:space:]#]*${key}[[:space:]]*=.*|${key} = ${value}|" \
            "$file"

    else

        printf '%s = %s\n' "$key" "$value" >> "$file"

    fi

    printf '    %-32s [SET]\n' "${key} = ${value}"
}

set_config_flag() {
    local file="$1"
    local key="$2"

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        printf '    %-32s [WOULD SET]\n' "$key"
        return
    fi

    touch "$file"

    sed -Ei \
        "/^[[:space:]#]*${key}([[:space:]]|$)/d" \
        "$file"

    printf '%s\n' "$key" >> "$file"

    printf '    %-32s [SET]\n' "$key"
}

backup_file() {
    local file="$1"

    [[ -f "$file" ]] || return

    local destination

    destination="${BACKUP_DIR}/$(basename "$file").bak"

    if [[ ! -f "$destination" ]]; then
        cp -a "$file" "$destination"
    fi
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

OS_ID="unknown"
OS_VERSION="unknown"

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release

    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
fi

echo "[*] Detected platform: ${OS_ID} ${OS_VERSION}"

if [[ "$OS_ID" != "ubuntu" || "$OS_VERSION" != "22.04" ]]; then

    echo "[!] CIS deviation: this PAM profile targets Ubuntu 22.04."

    if [[ "$AUDIT_ONLY" != "1" ]]; then
        echo "[!] Current system: ${OS_ID} ${OS_VERSION}" >&2
        echo "[!] Refusing automatic PAM remediation on a different OS." >&2
        echo "[!] Use AUDIT_ONLY=1 for safe validation." >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# libpam-pwquality
# ---------------------------------------------------------------------------

echo "[*] Checking libpam-pwquality..."

if dpkg-query \
    -W \
    -f='${Status}' \
    libpam-pwquality 2>/dev/null |
    grep -q "install ok installed"; then

    PACKAGE_VERSION="$(
        dpkg-query \
            -W \
            -f='${Version}' \
            libpam-pwquality
    )"

    echo "    Already installed: libpam-pwquality ${PACKAGE_VERSION}"

else

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        echo "    libpam-pwquality [WOULD INSTALL]"
    else
        echo "    Installing libpam-pwquality..."

        apt-get update
        DEBIAN_FRONTEND=noninteractive \
            apt-get install -y libpam-pwquality

        echo "    libpam-pwquality [INSTALLED]"
    fi
fi

# ---------------------------------------------------------------------------
# Backup PAM configuration
# ---------------------------------------------------------------------------

if [[ "$AUDIT_ONLY" != "1" ]]; then
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    backup_file "$PWQUALITY_FILE"
    backup_file "$FAILLOCK_FILE"
    backup_file "$PWHISTORY_FILE"
    backup_file "$COMMON_AUTH"
    backup_file "$COMMON_ACCOUNT"
    backup_file "$COMMON_PASSWORD"
fi

# ---------------------------------------------------------------------------
# Password quality
# ---------------------------------------------------------------------------

echo "[*] Configuring password quality (/etc/security/pwquality.conf)..."

# Minimum password length.
set_config_value "$PWQUALITY_FILE" "minlen" "14"

# Require at least one digit.
set_config_value "$PWQUALITY_FILE" "dcredit" "-1"

# Require at least one uppercase character.
set_config_value "$PWQUALITY_FILE" "ucredit" "-1"

# Require at least one lowercase character.
set_config_value "$PWQUALITY_FILE" "lcredit" "-1"

# Require at least one non-alphanumeric/special character.
set_config_value "$PWQUALITY_FILE" "ocredit" "-1"

# Prevent excessive repetition such as aaaaa or 11111.
set_config_value "$PWQUALITY_FILE" "maxrepeat" "3"

# Prevent passwords containing the username.
set_config_flag "$PWQUALITY_FILE" "reject_username"

# ---------------------------------------------------------------------------
# Account lockout - pam_faillock
# ---------------------------------------------------------------------------

echo "[*] Configuring account lockout (pam_faillock)..."

# Lock the account after five failed authentication attempts.
set_config_value "$FAILLOCK_FILE" "deny" "5"

# Keep the account locked for 900 seconds (15 minutes).
set_config_value "$FAILLOCK_FILE" "unlock_time" "900"

# Count failures occurring inside a 900-second interval.
set_config_value "$FAILLOCK_FILE" "fail_interval" "900"

# ---------------------------------------------------------------------------
# Password history
# ---------------------------------------------------------------------------

echo "[*] Configuring password history..."

# Prevent reuse of the previous 12 passwords.
set_config_value "$PWHISTORY_FILE" "remember" "12"

# ---------------------------------------------------------------------------
# Ensure PAM modules are present in the appropriate stacks.
# ---------------------------------------------------------------------------

if [[ "$AUDIT_ONLY" == "1" ]]; then

    echo "[*] Checking PAM module integration..."

    grep -q "pam_pwquality.so" "$COMMON_PASSWORD" 2>/dev/null \
        && echo "    pam_pwquality.so [PRESENT]" \
        || echo "    pam_pwquality.so [MISSING]"

    grep -q "pam_pwhistory.so" "$COMMON_PASSWORD" 2>/dev/null \
        && echo "    pam_pwhistory.so [PRESENT]" \
        || echo "    pam_pwhistory.so [MISSING]"

    grep -q "pam_faillock.so" "$COMMON_AUTH" 2>/dev/null \
        && echo "    pam_faillock.so [PRESENT]" \
        || echo "    pam_faillock.so [MISSING]"

else

    # pwquality should execute before pam_unix changes a password.
    if ! grep -q "pam_pwquality.so" "$COMMON_PASSWORD"; then

        sed -i \
            '/pam_unix.so/i password requisite pam_pwquality.so retry=3' \
            "$COMMON_PASSWORD"
    fi

    # Password history must also execute before pam_unix stores the new
    # password so reuse of previous passwords is rejected.
    if ! grep -q "pam_pwhistory.so" "$COMMON_PASSWORD"; then

        sed -i \
            '/pam_unix.so/i password required pam_pwhistory.so use_authtok remember=12' \
            "$COMMON_PASSWORD"
    fi

    # pam_faillock pre-auth checks whether the account is already locked.
    if ! grep -q "pam_faillock.so preauth" "$COMMON_AUTH"; then

        sed -i \
            '1i auth required pam_faillock.so preauth silent' \
            "$COMMON_AUTH"
    fi

    # authfail records unsuccessful authentication attempts.
    if ! grep -q "pam_faillock.so authfail" "$COMMON_AUTH"; then

        printf '\nauth required pam_faillock.so authfail\n' \
            >> "$COMMON_AUTH"
    fi

    # Account phase applies faillock restrictions.
    if ! grep -q "pam_faillock.so" "$COMMON_ACCOUNT"; then

        printf '\naccount required pam_faillock.so\n' \
            >> "$COMMON_ACCOUNT"
    fi
fi

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

echo "[*] Validating PAM configuration..."

VALIDATION_FAILURES=0

validate_value() {
    local file="$1"
    local key="$2"
    local expected="$3"

    if grep -Eq \
        "^[[:space:]]*${key}[[:space:]]*=[[:space:]]*${expected}([[:space:]]|$)" \
        "$file" 2>/dev/null; then

        printf '    %-32s [PASS]\n' "${key} = ${expected}"

    else

        printf '    %-32s [FAIL]\n' "${key} = ${expected}"
        VALIDATION_FAILURES=$((VALIDATION_FAILURES + 1))

    fi
}

if [[ "$AUDIT_ONLY" != "1" ]]; then

    validate_value "$PWQUALITY_FILE" "minlen" "14"
    validate_value "$PWQUALITY_FILE" "dcredit" "-1"
    validate_value "$PWQUALITY_FILE" "ucredit" "-1"
    validate_value "$PWQUALITY_FILE" "lcredit" "-1"
    validate_value "$PWQUALITY_FILE" "ocredit" "-1"
    validate_value "$PWQUALITY_FILE" "maxrepeat" "3"

    if grep -Eq \
        '^[[:space:]]*reject_username([[:space:]]|$)' \
        "$PWQUALITY_FILE"; then

        echo "    reject_username                  [PASS]"
    else
        echo "    reject_username                  [FAIL]"
        VALIDATION_FAILURES=$((VALIDATION_FAILURES + 1))
    fi

    validate_value "$FAILLOCK_FILE" "deny" "5"
    validate_value "$FAILLOCK_FILE" "unlock_time" "900"
    validate_value "$FAILLOCK_FILE" "fail_interval" "900"

    validate_value "$PWHISTORY_FILE" "remember" "12"

    if grep -q "pam_pwquality.so" "$COMMON_PASSWORD"; then
        echo "    pam_pwquality.so                 [PASS]"
    else
        echo "    pam_pwquality.so                 [FAIL]"
        VALIDATION_FAILURES=$((VALIDATION_FAILURES + 1))
    fi

    if grep -q "pam_pwhistory.so" "$COMMON_PASSWORD"; then
        echo "    pam_pwhistory.so                 [PASS]"
    else
        echo "    pam_pwhistory.so                 [FAIL]"
        VALIDATION_FAILURES=$((VALIDATION_FAILURES + 1))
    fi

    if grep -q "pam_faillock.so" "$COMMON_AUTH"; then
        echo "    pam_faillock.so                  [PASS]"
    else
        echo "    pam_faillock.so                  [FAIL]"
        VALIDATION_FAILURES=$((VALIDATION_FAILURES + 1))
    fi

fi

echo
echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12"

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo "Mode: AUDIT ONLY - PAM configuration was not modified"
else
    echo "Validation failures: ${VALIDATION_FAILURES}"

    if (( VALIDATION_FAILURES > 0 )); then
        exit 1
    fi
fi
