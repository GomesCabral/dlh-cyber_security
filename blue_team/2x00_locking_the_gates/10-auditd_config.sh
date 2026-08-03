#!/bin/bash

# MedDefense Health Systems - Audit Engine
#
# Deploys Linux audit rules for security-critical activity.
#
# Threat mappings:
# - Identity-file changes may indicate account creation or persistence.
# - sudo/su execution provides visibility into privilege escalation.
# - wget/curl/nc execution may indicate payload download or attacker tooling.
# - SSH/PAM/sudoers changes may weaken authentication controls.
# - MySQL and Apache changes may affect MedDefense production workloads.
# - Startup-script changes may indicate persistence.
#
# Context:
# During the 1x00 incident, attacker activity remained undetected for five
# days. auditd provides kernel-level telemetry for future SOC monitoring.
#
# Safety:
# The production profile targets Ubuntu 22.04.
# On another platform, validate first with:
#
# sudo AUDIT_ONLY=1 ./10-auditd_config.sh
#
# Idempotency:
# The MedDefense rule file is completely regenerated on each execution,
# preventing duplicate audit rules.

set -euo pipefail

export LC_ALL=C

AUDIT_ONLY="${AUDIT_ONLY:-0}"

RULE_FILE="/etc/audit/rules.d/meddefense.rules"
AUDIT_LOG="/var/log/audit/audit.log"

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: run this script with sudo." >&2
    exit 1
fi

if [[ "$AUDIT_ONLY" != "0" && "$AUDIT_ONLY" != "1" ]]; then
    echo "Error: AUDIT_ONLY must be 0 or 1." >&2
    exit 1
fi

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
    echo "[!] CIS deviation: auditd profile targets Ubuntu 22.04."

    if [[ "$AUDIT_ONLY" != "1" ]]; then
        echo "Error: automatic remediation refused on ${OS_ID} ${OS_VERSION}." >&2
        echo "Run safely with:" >&2
        echo "sudo AUDIT_ONLY=1 ./10-auditd_config.sh" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# MedDefense audit rules
# ---------------------------------------------------------------------------

RULES=(
    "-w /etc/passwd -p wa -k identity"
    "-w /etc/shadow -p wa -k identity"
    "-w /etc/group -p wa -k identity"
    "-w /etc/pam.d/ -p wa -k pam_config"
    "-w /etc/ssh/sshd_config -p wa -k sshd_config"
    "-w /usr/bin/sudo -p x -k priv_esc"
    "-w /usr/bin/su -p x -k priv_esc"
    "-w /etc/sudoers -p wa -k sudoers"
    "-w /usr/bin/wget -p x -k suspicious_download"
    "-w /usr/bin/curl -p x -k suspicious_download"
    "-w /usr/bin/nc -p x -k suspicious_netcat"
    "-w /var/lib/mysql/ -p wa -k meddefense_db"
    "-w /etc/apache2/ -p wa -k meddefense_web"
    "-w /etc/init.d/ -p wa -k startup_scripts"
)

# ---------------------------------------------------------------------------
# Check/install auditd
# ---------------------------------------------------------------------------

echo "[*] Checking auditd..."

if command -v auditctl >/dev/null 2>&1; then
    echo "    auditd tools: installed"
else
    if [[ "$AUDIT_ONLY" == "1" ]]; then
        echo "    auditd [WOULD INSTALL]"
    else
        echo "    Installing auditd..."

        apt-get update

        DEBIAN_FRONTEND=noninteractive \
            apt-get install -y auditd

        echo "    auditd [INSTALLED]"
    fi
fi

echo "[*] Enabling auditd service..."

if [[ "$AUDIT_ONLY" == "1" ]]; then

    if systemctl is-active --quiet auditd 2>/dev/null; then
        echo "    auditd.service: active (running)"
    else
        echo "    auditd.service: inactive [WOULD ENABLE/START]"
    fi

else

    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl start auditd

    if systemctl is-active --quiet auditd; then
        echo "    auditd.service: active (running)"
    else
        echo "Error: auditd failed to start." >&2
        exit 1
    fi

fi

# ---------------------------------------------------------------------------
# Validate paths before deploying watches
# ---------------------------------------------------------------------------

rule_path() {
    local rule="$1"
    local remainder

    remainder="${rule#-w }"

    printf '%s\n' "${remainder%% *}"
}

echo "[*] Deploying MedDefense audit rules..."

MISSING_PATHS=0

for rule in "${RULES[@]}"; do

    path="$(rule_path "$rule")"

    if [[ ! -e "$path" ]]; then
        printf '    %-58s [PATH MISSING]\n' "$rule"
        MISSING_PATHS=$((MISSING_PATHS + 1))
        continue
    fi

    if [[ "$AUDIT_ONLY" == "1" ]]; then
        printf '    %-58s [WOULD ADD]\n' "$rule"
    else
        printf '    %-58s [ADDED]\n' "$rule"
    fi

done

if [[ "$AUDIT_ONLY" == "1" ]]; then

    echo
    echo "Rules defined: ${#RULES[@]}"
    echo "Paths missing on this host: ${MISSING_PATHS}"
    echo "Mode: AUDIT ONLY - no audit rules were changed"

    exit 0
fi

# On the production MedDefense server all monitored resources should exist.
if (( MISSING_PATHS > 0 )); then
    echo "Error: ${MISSING_PATHS} monitored paths do not exist." >&2
    echo "Audit rules were not deployed." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Backup existing MedDefense rule file
# ---------------------------------------------------------------------------

if [[ -f "$RULE_FILE" && ! -f "${RULE_FILE}.bak" ]]; then
    cp -a "$RULE_FILE" "${RULE_FILE}.bak"
fi

# ---------------------------------------------------------------------------
# Write deterministic rule file
# ---------------------------------------------------------------------------

cat > "$RULE_FILE" <<'EOF'
# MedDefense Health Systems - Linux Audit Rules
#
# Identity and authentication monitoring
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Privilege escalation monitoring
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /etc/sudoers -p wa -k sudoers

# Suspicious attacker-tool execution
-w /usr/bin/wget -p x -k suspicious_download
-w /usr/bin/curl -p x -k suspicious_download
-w /usr/bin/nc -p x -k suspicious_netcat

# MedDefense application integrity
-w /var/lib/mysql/ -p wa -k meddefense_db
-w /etc/apache2/ -p wa -k meddefense_web

# Persistence monitoring
-w /etc/init.d/ -p wa -k startup_scripts
EOF

chown root:root "$RULE_FILE"
chmod 640 "$RULE_FILE"

# ---------------------------------------------------------------------------
# Load audit rules
# ---------------------------------------------------------------------------

echo "[*] Loading rules..."

if augenrules --load >/dev/null; then
    echo "    augenrules --load: OK"
else
    echo "Error: augenrules failed to load the rules." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Verify active rules
# ---------------------------------------------------------------------------

echo "[*] Verifying active rules..."

ACTIVE_RULES="$(auditctl -l)"

VERIFIED_COUNT=0

for rule in "${RULES[@]}"; do

    path="$(rule_path "$rule")"

    if grep -Fq "$path" <<< "$ACTIVE_RULES"; then
        VERIFIED_COUNT=$((VERIFIED_COUNT + 1))
    fi

done

echo "    auditctl -l: ${VERIFIED_COUNT} MedDefense rules verified"

if [[ "$VERIFIED_COUNT" -ne "${#RULES[@]}" ]]; then
    echo "Error: not all audit rules were loaded." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Generate a safe auditable event
# ---------------------------------------------------------------------------
#
# The identity rules use "-p wa", meaning WRITE and ATTRIBUTE changes.
# Simply reading /etc/shadow would NOT reliably trigger these rules.
#
# We therefore invoke chmod on /etc/passwd using its existing permissions.
# The final permissions remain unchanged, but the attribute-related system
# call generates an auditable event.

echo "[*] Test: triggering identity-file audit event..."

CURRENT_MODE="$(stat -c '%a' /etc/passwd)"

chmod "$CURRENT_MODE" /etc/passwd

sleep 1

# ---------------------------------------------------------------------------
# Search for the test event
# ---------------------------------------------------------------------------

EVENT_COUNT="$(
    ausearch \
        -ts recent \
        -k identity \
        --raw 2>/dev/null |
    grep -c '^type=SYSCALL' || true
)"

if (( EVENT_COUNT > 0 )); then
    echo "    ausearch -ts recent -k identity: ${EVENT_COUNT} event(s) found [PASS]"
else
    echo "    ausearch -ts recent -k identity: no event found [FAIL]"
    exit 1
fi

echo
echo "Rules deployed: ${#RULES[@]}"
echo "Rules verified: ${VERIFIED_COUNT}"
echo "Audit test: PASS"
echo "Audit log: ${AUDIT_LOG}"
