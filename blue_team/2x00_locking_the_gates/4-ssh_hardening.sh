#!/bin/bash

# MedDefense Health Systems - SSH Hardening
#
# Addresses:
# - 1x02 Finding 009: SSH password authentication enabled
# - Crimson Tide Phase 3: SSH lateral movement using harvested credentials
#
# The script:
# - creates a backup of sshd_config
# - applies the MedDefense SSH hardening policy
# - validates the configuration before restart
# - restores the backup if validation fails
#
# Idempotency:
# - the original .bak backup is preserved
# - an existing MedDefense managed block is replaced rather than duplicated

set -euo pipefail

export LC_ALL=C

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_FILE="/etc/ssh/sshd_config.bak"
BANNER_FILE="/etc/issue.net"

BEGIN_MARKER="# BEGIN MEDDEFENSE SSH HARDENING"
END_MARKER="# END MEDDEFENSE SSH HARDENING"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: this script must be run with sudo." >&2
    echo "Usage: sudo ./4-ssh_hardening.sh" >&2
    exit 1
fi

if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG does not exist." >&2
    exit 1
fi

if ! command -v sshd >/dev/null 2>&1; then
    echo "Error: sshd is not installed." >&2
    exit 1
fi

echo "[*] Backing up /etc/ssh/sshd_config"

# Preserve the original configuration rather than overwriting the backup
# every time the idempotent script is executed.
if [[ ! -f "$BACKUP_FILE" ]]; then
    cp -a "$SSHD_CONFIG" "$BACKUP_FILE"
fi

# Create an execution-time rollback copy. Unlike the permanent .bak file,
# this represents the state immediately before this execution.
ROLLBACK_FILE="$(mktemp)"

cleanup() {
    rm -f "$ROLLBACK_FILE"
}

trap cleanup EXIT

cp -a "$SSHD_CONFIG" "$ROLLBACK_FILE"

echo "[*] Applying SSH hardening settings..."

# Remove a previously generated MedDefense block so repeated executions do
# not create duplicate configuration directives.
sed -i \
    "/^${BEGIN_MARKER}$/,/^${END_MARKER}$/d" \
    "$SSHD_CONFIG"

cat >> "$SSHD_CONFIG" <<'EOF'

# BEGIN MEDDEFENSE SSH HARDENING

# Disable direct root login - limits privileged credential abuse and
# addresses Crimson Tide SSH lateral movement.
PermitRootLogin no

# Disable password authentication - addresses 1x02 Finding 009 and prevents
# brute-force, password spraying and reuse of harvested SSH credentials.
PasswordAuthentication no

# Reject accounts with empty passwords - prevents trivial unauthorized
# authentication to MedDefense systems.
PermitEmptyPasswords no

# Disable X11 forwarding - removes an unnecessary SSH feature and reduces
# the attack surface on MedDefense servers.
X11Forwarding no

# Restrict authentication attempts - reduces online brute-force attempts
# against administrator accounts.
MaxAuthTries 3

# Disconnect inactive SSH sessions after approximately 10 minutes:
# 300 seconds x 2 unanswered keepalive checks.
# This reduces exposure from abandoned administrative sessions.
ClientAliveInterval 300
ClientAliveCountMax 2

# Restrict SSH access to approved MedDefense administrative accounts.
# This limits credential abuse and unauthorized lateral movement.
AllowUsers medadmin sysadmin

# Require SSH Protocol 2 - prevents use of the obsolete SSH protocol 1.
Protocol 2

# Limit the time available to complete login authentication.
# This reduces resource consumption from incomplete authentication sessions.
LoginGraceTime 60

# Display the authorized-use warning before authentication.
Banner /etc/issue.net

# END MEDDEFENSE SSH HARDENING
EOF

echo "    PermitRootLogin no"
echo "    PasswordAuthentication no"
echo "    PermitEmptyPasswords no"
echo "    X11Forwarding no"
echo "    MaxAuthTries 3"
echo "    ClientAliveInterval 300"
echo "    ClientAliveCountMax 2"
echo "    AllowUsers medadmin sysadmin"
echo "    Protocol 2"
echo "    LoginGraceTime 60"
echo "    Banner /etc/issue.net"

# Create the SSH login banner.
cat > "$BANNER_FILE" <<'EOF'
***************************************************************************
                        MEDDEFENSE HEALTH SYSTEMS

AUTHORIZED ACCESS ONLY.

This system is restricted to authorized MedDefense personnel.
All access and activity may be monitored, recorded and audited.

Unauthorized access or use is prohibited and may result in disciplinary
action, termination of access and legal proceedings.
***************************************************************************
EOF

chmod 644 "$BANNER_FILE"
chown root:root "$BANNER_FILE"

echo "[*] Validating SSH configuration..."

if sshd -t; then
    echo "    sshd -t: OK"
else
    echo "    sshd -t: FAILED"
    echo "[!] Restoring previous SSH configuration..."

    cp -a "$ROLLBACK_FILE" "$SSHD_CONFIG"

    echo "[!] Previous configuration restored."
    exit 1
fi

echo "[*] Restarting SSH service..."

if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
    systemctl restart ssh
    SSH_SERVICE="ssh"
elif systemctl list-unit-files sshd.service >/dev/null 2>&1; then
    systemctl restart sshd
    SSH_SERVICE="sshd"
else
    echo "Error: unable to identify the SSH systemd service." >&2
    cp -a "$ROLLBACK_FILE" "$SSHD_CONFIG"
    exit 1
fi

if systemctl is-active --quiet "$SSH_SERVICE"; then
    echo "    ${SSH_SERVICE}.service: active (running)"
else
    echo "Error: SSH service failed after restart." >&2
    echo "[!] Restoring previous configuration..."

    cp -a "$ROLLBACK_FILE" "$SSHD_CONFIG"

    systemctl restart "$SSH_SERVICE" || true

    exit 1
fi

echo "Settings applied: 11"
