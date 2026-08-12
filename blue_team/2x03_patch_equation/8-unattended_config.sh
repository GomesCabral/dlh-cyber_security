#!/bin/bash
# name: 8-unattended_config.sh
# purpose: Configure unattended-upgrades so low-risk security patches land
#          automatically, while critical packages (kernel, database, web
#          server) are protected by an explicit blacklist and automatic
#          reboots stay off -- appropriate defaults for a healthcare
#          system where an unattended reboot is not acceptable.
# Project: 2x03 - Patch Equation
# Task:    8 - The Unattended Upgrades Configuration
#
# Idempotency: both config files are regenerated in full from a fixed
# template and written atomically (temp file + mv), never appended to.
# Re-running this script always produces the exact same file content --
# there is no "check if the line already exists" logic to get wrong, and
# therefore no way for entries to duplicate.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
OUTPUT_FILE="${SCRIPT_DIR}/unattended_config.json"

# Overridable for safe testing -- default to the real system paths.
UNATTENDED_CONF="${UNATTENDED_CONF_PATH:-/etc/apt/apt.conf.d/50unattended-upgrades}"
AUTO_UPGRADES_CONF="${AUTO_UPGRADES_CONF_PATH:-/etc/apt/apt.conf.d/20auto-upgrades}"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq dpkg apt-get systemctl awk grep sed mktemp; do need "$c"; done

BLACKLIST=(
    "linux-image*"
    "linux-headers*"
    "mysql-server*"
    "apache2*"
    "libapache2-mod-php*"
)

# ---------------------------------------------------------------------------
# 1. Install unattended-upgrades if not present
# ---------------------------------------------------------------------------
WAS_INSTALLED=true
if dpkg -s unattended-upgrades >/dev/null 2>&1; then
    echo "[*] unattended-upgrades: already installed"
else
    WAS_INSTALLED=false
    echo "[*] unattended-upgrades: not installed, installing..."
    if DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades >/dev/null 2>&1; then
        echo "    install OK"
    else
        fail "failed to install unattended-upgrades"
    fi
fi

# ---------------------------------------------------------------------------
# 2. Write /etc/apt/apt.conf.d/50unattended-upgrades (idempotent overwrite)
# ---------------------------------------------------------------------------
write_atomic() {
    local target="$1" content="$2"
    local dir tmp
    dir="$(dirname -- "${target}")"
    [[ -d "${dir}" ]] || mkdir -p "${dir}" 2>/dev/null || true
    tmp="$(mktemp "${dir}/.tmp.XXXXXX" 2>/dev/null || mktemp)"
    printf '%s\n' "${content}" > "${tmp}"
    chmod 644 "${tmp}" 2>/dev/null || true
    mv -f "${tmp}" "${target}"
}

echo -n "[*] Writing ${UNATTENDED_CONF}...   "

BLACKLIST_LINES="$(printf '    "%s";\n' "${BLACKLIST[@]}")"

UNATTENDED_CONTENT=$(cat << EOF
// Managed by 8-unattended_config.sh -- MedDefense unattended-upgrades policy.
// This file is regenerated in full on every run; do not hand-edit.

Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};

// Critical packages: kernel, database, web server, and its PHP module
// are never patched unattended. These require a planned maintenance
// window (see Task 3's patch plan / Task 4's execution log instead).
Unattended-Upgrade::Package-Blacklist {
${BLACKLIST_LINES}
};

// A healthcare system does not get to reboot itself unattended.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";

// No mail system is assumed in this lab environment.
Unattended-Upgrade::Mail "";
Unattended-Upgrade::MailOnlyOnError "false";
EOF
)

write_atomic "${UNATTENDED_CONF}" "${UNATTENDED_CONTENT}" && echo "OK" || fail "could not write ${UNATTENDED_CONF}"

# ---------------------------------------------------------------------------
# 3. Write /etc/apt/apt.conf.d/20auto-upgrades (idempotent overwrite)
# ---------------------------------------------------------------------------
echo -n "[*] Writing ${AUTO_UPGRADES_CONF}...         "

AUTO_UPGRADES_CONTENT=$(cat << 'EOF'
// Managed by 8-unattended_config.sh -- enables the daily apt timer.
// This file is regenerated in full on every run; do not hand-edit.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
)

write_atomic "${AUTO_UPGRADES_CONF}" "${AUTO_UPGRADES_CONTENT}" && echo "OK" || fail "could not write ${AUTO_UPGRADES_CONF}"

# ---------------------------------------------------------------------------
# 4. Enable and start the timers (systemctl enable --now is itself
#    idempotent -- re-enabling an already-enabled, already-active timer
#    is a safe no-op).
# ---------------------------------------------------------------------------
echo -n "[*] Enabling timers...                                     "

TIMERS_OK=true
for t in apt-daily.timer apt-daily-upgrade.timer; do
    systemctl enable --now "${t}" >/dev/null 2>&1 || TIMERS_OK=false
done

if [[ "${TIMERS_OK}" == "true" ]]; then
    echo "OK"
else
    echo "PARTIAL"
fi

timer_state_json() {
    local t="$1"
    local active enabled
    active="$(systemctl is-active "${t}" 2>/dev/null || echo "unknown")"
    enabled="$(systemctl is-enabled "${t}" 2>/dev/null || echo "unknown")"
    jq -cn --arg timer "${t}" --arg active "${active}" --arg enabled "${enabled}" \
      '{timer:$timer, active_state:$active, enabled_state:$enabled}'
}
TIMER_STATE_JSON="$(jq -cs '.' <(timer_state_json apt-daily.timer; timer_state_json apt-daily-upgrade.timer))"

# ---------------------------------------------------------------------------
# 5. Dry run -- execute and parse
#
# The actual binary shipped by the unattended-upgrades package is named
# `unattended-upgrade` (singular). Some docs/exercises refer to it as
# `unattended-upgrades --dry-run --debug` (plural); this script tries the
# real binary name first and falls back to the plural form if that's what
# is present on PATH, so it works either way.
# ---------------------------------------------------------------------------
echo "[*] Dry run..."

DRYRUN_BIN=""
command -v unattended-upgrade >/dev/null 2>&1 && DRYRUN_BIN="unattended-upgrade"
[[ -z "${DRYRUN_BIN}" ]] && command -v unattended-upgrades >/dev/null 2>&1 && DRYRUN_BIN="unattended-upgrades"

DRYRUN_OUTPUT=""
if [[ -n "${DRYRUN_BIN}" ]]; then
    DRYRUN_OUTPUT="$("${DRYRUN_BIN}" --dry-run --debug 2>&1 || true)"
else
    echo "    [WARN] unattended-upgrade binary not found on PATH -- skipping dry run" >&2
fi

# Parsing is best-effort against the real tool's debug transcript, which
# varies somewhat between distro versions. Multiple patterns are tried;
# anything unmatched simply contributes 0 rather than aborting the script.
WOULD_UPGRADE_LIST="$(grep -oP '(?<=^Packages that will be upgraded: ).*' <<< "${DRYRUN_OUTPUT}" | tr ' ' '\n' | grep -v '^$' || true)"
WOULD_UPGRADE_COUNT="$(grep -c . <<< "${WOULD_UPGRADE_LIST}" 2>/dev/null || echo 0)"
[[ -z "${WOULD_UPGRADE_LIST}" ]] && WOULD_UPGRADE_COUNT=0

BLACKLISTED_LIST="$(grep -oP '(?<=^Package )\S+(?= has a blacklist match)' <<< "${DRYRUN_OUTPUT}" | sort -u || true)"
BLACKLISTED_COUNT="$(grep -c . <<< "${BLACKLISTED_LIST}" 2>/dev/null || echo 0)"
[[ -z "${BLACKLISTED_LIST}" ]] && BLACKLISTED_COUNT=0

HELD_LIST="$(grep -oP '(?<=^Package )\S+(?= is set on hold)' <<< "${DRYRUN_OUTPUT}" | sort -u || true)"
HELD_COUNT="$(grep -c . <<< "${HELD_LIST}" 2>/dev/null || echo 0)"
[[ -z "${HELD_LIST}" ]] && HELD_COUNT=0

blacklisted_display="$(paste -sd, - <<< "${BLACKLISTED_LIST}" 2>/dev/null | sed 's/,/, /g')"
echo "would upgrade:       ${WOULD_UPGRADE_COUNT}"
echo "skipped (blacklist): ${BLACKLISTED_COUNT}$([[ ${BLACKLISTED_COUNT} -gt 0 ]] && echo " (${blacklisted_display})")"
echo "skipped (held):      ${HELD_COUNT}"

# ---------------------------------------------------------------------------
# 6. Emit unattended_config.json
# ---------------------------------------------------------------------------
BLACKLIST_JSON="$(printf '%s\n' "${BLACKLIST[@]}" | jq -Rsc 'split("\n")|map(select(length>0))')"
WOULD_UPGRADE_JSON="$(printf '%s\n' "${WOULD_UPGRADE_LIST}" | jq -Rsc 'split("\n")|map(select(length>0))')"
BLACKLISTED_JSON="$(printf '%s\n' "${BLACKLISTED_LIST}" | jq -Rsc 'split("\n")|map(select(length>0))')"
HELD_JSON="$(printf '%s\n' "${HELD_LIST}" | jq -Rsc 'split("\n")|map(select(length>0))')"

jq -n \
  --argjson installed "${WAS_INSTALLED}" \
  --arg conf1 "${UNATTENDED_CONF}" --arg conf2 "${AUTO_UPGRADES_CONF}" \
  --argjson blacklist "${BLACKLIST_JSON}" \
  --argjson timer_state "${TIMER_STATE_JSON}" \
  --argjson would_upgrade_count "${WOULD_UPGRADE_COUNT}" \
  --argjson would_upgrade_list "${WOULD_UPGRADE_JSON}" \
  --argjson skipped_blacklisted_count "${BLACKLISTED_COUNT}" \
  --argjson skipped_blacklisted_list "${BLACKLISTED_JSON}" \
  --argjson skipped_held_count "${HELD_COUNT}" \
  --argjson skipped_held_list "${HELD_JSON}" \
  '{
     installed: $installed,
     config_paths: [$conf1, $conf2],
     blacklist: $blacklist,
     timer_state: $timer_state,
     dry_run_summary: {
       would_upgrade: $would_upgrade_count,
       would_upgrade_packages: $would_upgrade_list,
       skipped_blacklisted: $skipped_blacklisted_count,
       skipped_blacklisted_packages: $skipped_blacklisted_list,
       skipped_held: $skipped_held_count,
       skipped_held_packages: $skipped_held_list
     }
   }' > "${OUTPUT_FILE}"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "unattended_config.json is invalid JSON"

echo "Report saved to: unattended_config.json"