#!/bin/bash

# MedDefense Health Systems - Log Architect
#
# Configures rsyslog routing, log formatting, retention and permissions.
#
# Threat context:
# - Authentication failures, PAM events and service failures must remain
#   available for investigation.
# - Missing or short-lived logs contributed to poor visibility during the
#   previous MedDefense incident.
#
# Safety:
# The production target is Ubuntu 22.04.
# Validate first on a different platform with:
#
# sudo AUDIT_ONLY=1 ./12-log_config.sh
#
# Idempotency:
# Managed rsyslog and logrotate files are regenerated rather than appended.

set -euo pipefail

export LC_ALL=C

AUDIT_ONLY="${AUDIT_ONLY:-0}"

RSYSLOG_FILE="/etc/rsyslog.d/30-meddefense.conf"
LOGROTATE_FILE="/etc/logrotate.d/meddefense"

AUTH_LOG="/var/log/auth.log"
SYSLOG_FILE="/var/log/syslog"

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
    echo "[!] CIS deviation: logging profile targets Ubuntu 22.04."

    if [[ "$AUDIT_ONLY" != "1" ]]; then
        echo "Error: refusing automatic logging remediation on ${OS_ID} ${OS_VERSION}." >&2
        echo "Use AUDIT_ONLY=1 for safe inspection." >&2
        exit 1
    fi
fi

echo "[*] Checking rsyslog..."

if command -v rsyslogd >/dev/null 2>&1; then
    echo "    rsyslog: installed"
else
    if [[ "$AUDIT_ONLY" == "1" ]]; then
        echo "    rsyslog [WOULD INSTALL]"
    else
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog
        echo "    rsyslog [INSTALLED]"
    fi
fi

if [[ "$AUDIT_ONLY" != "1" ]]; then
    systemctl enable --now rsyslog
fi

echo "[*] Configuring rsyslog..."

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo "    auth,authpriv.* -> /var/log/auth.log     [WOULD CONFIGURE]"
    echo "    *.info;auth.none -> /var/log/syslog      [WOULD CONFIGURE]"
else
    cat > "$RSYSLOG_FILE" <<'EOF'
# MedDefense structured logging profile

# Structured template for security-relevant events.
template(
    name="MedDefenseStructured"
    type="string"
    string="%timereported:::date-rfc3339% host=%hostname% app=%programname% pid=%procid% msg=%msg%\n"
)

# Authentication and PAM-related events.
auth,authpriv.* action(
    type="omfile"
    file="/var/log/auth.log"
    template="MedDefenseStructured"
)

# General system events excluding authentication duplication.
*.info;auth.none;authpriv.none action(
    type="omfile"
    file="/var/log/syslog"
    template="MedDefenseStructured"
)
EOF

    chown root:root "$RSYSLOG_FILE"
    chmod 640 "$RSYSLOG_FILE"

    if rsyslogd -N1 >/dev/null 2>&1; then
        echo "    rsyslog syntax validation [PASS]"
    else
        echo "Error: rsyslog configuration validation failed." >&2
        exit 1
    fi

    systemctl restart rsyslog

    echo "    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]"
    echo "    *.info;auth.none -> /var/log/syslog      [CONFIGURED]"
fi

echo "[*] Setting log rotation policies..."

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo "    /var/log/auth.log: rotate 90, compress after 7d  [WOULD SET]"
    echo "    /var/log/syslog: rotate 60, compress after 7d    [WOULD SET]"
else
    cat > "$LOGROTATE_FILE" <<'EOF'
/var/log/auth.log {
    daily
    rotate 90
    missingok
    notifempty
    delaycompress
    compress
    dateext
    create 0640 root adm
    postrotate
        systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}

/var/log/syslog {
    daily
    rotate 60
    missingok
    notifempty
    delaycompress
    compress
    dateext
    create 0640 root adm
    postrotate
        systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
EOF

    chown root:root "$LOGROTATE_FILE"
    chmod 640 "$LOGROTATE_FILE"

    if logrotate -d "$LOGROTATE_FILE" >/dev/null 2>&1; then
        echo "    /var/log/auth.log: rotate 90, compress after 7d  [SET]"
        echo "    /var/log/syslog: rotate 60, compress after 7d    [SET]"
    else
        echo "Error: logrotate validation failed." >&2
        exit 1
    fi
fi

echo "[*] Verifying log activity..."

if [[ "$AUDIT_ONLY" == "1" ]]; then
    if [[ -f "$AUTH_LOG" ]]; then
        echo "    /var/log/auth.log: exists"
    else
        echo "    /var/log/auth.log: missing"
    fi

    if [[ -f "$SYSLOG_FILE" ]]; then
        echo "    /var/log/syslog: exists"
    else
        echo "    /var/log/syslog: missing"
    fi
else
    AUTH_MARKER="MEDDEFENSE_AUTH_TEST_$(date +%s)"
    SYSLOG_MARKER="MEDDEFENSE_SYSLOG_TEST_$(date +%s)"

    logger -p auth.info "$AUTH_MARKER"
    logger -p user.info "$SYSLOG_MARKER"

    sleep 2

    if grep -Fq "$AUTH_MARKER" "$AUTH_LOG"; then
        echo "    /var/log/auth.log: receiving events       [OK]"
    else
        echo "    /var/log/auth.log: receiving events       [FAIL]"
        exit 1
    fi

    if grep -Fq "$SYSLOG_MARKER" "$SYSLOG_FILE"; then
        echo "    /var/log/syslog: receiving events         [OK]"
    else
        echo "    /var/log/syslog: receiving events         [FAIL]"
        exit 1
    fi
fi

echo "[*] Securing log file permissions..."

if [[ "$AUDIT_ONLY" == "1" ]]; then
    [[ -e "$AUTH_LOG" ]] && stat -c '    %n: %a %U:%G' "$AUTH_LOG" || true
    [[ -e "$SYSLOG_FILE" ]] && stat -c '    %n: %a %U:%G' "$SYSLOG_FILE" || true
else
    touch "$AUTH_LOG" "$SYSLOG_FILE"

    chown root:adm "$AUTH_LOG" "$SYSLOG_FILE"
    chmod 640 "$AUTH_LOG" "$SYSLOG_FILE"

    AUTH_META="$(stat -c '%a %U:%G' "$AUTH_LOG")"
    SYSLOG_META="$(stat -c '%a %U:%G' "$SYSLOG_FILE")"

    if [[ "$AUTH_META" == "640 root:adm" ]]; then
        echo "    /var/log/auth.log: 640 root:adm          [OK]"
    else
        echo "    /var/log/auth.log: ${AUTH_META}          [FAIL]"
        exit 1
    fi

    if [[ "$SYSLOG_META" == "640 root:adm" ]]; then
        echo "    /var/log/syslog: 640 root:adm            [OK]"
    else
        echo "    /var/log/syslog: ${SYSLOG_META}          [FAIL]"
        exit 1
    fi
fi

echo
echo "Log sources configured: 2 | Rotation policies: 2 | Permissions: secured"

if [[ "$AUDIT_ONLY" == "1" ]]; then
    echo "Mode: AUDIT ONLY - logging configuration was not modified"
fi
