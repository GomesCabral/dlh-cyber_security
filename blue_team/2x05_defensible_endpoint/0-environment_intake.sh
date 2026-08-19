#!/bin/bash
#
# 0-environment_intake.sh
#
# Captures a complete, deterministic snapshot of an unhardened Linux
# endpoint (hawthorne-app-01) BEFORE any hardening action, and writes it
# as structured JSON. Every later task in this capstone measures its
# success by the delta between this snapshot and the post-hardening state.
#
# This script is read-only: it inspects system state, it never changes it.
# Idempotency is therefore automatic -- running it twice never corrupts
# anything and never "re-applies" anything, because nothing is applied.
#
# Usage:
#   sudo ./0-environment_intake.sh [output_dir]
#
# Exit codes:
#   0 - success, snapshot captured and written
#   1 - controlled failure (a required capture could not be completed)
#   2 - environment error (missing required command / cannot write output)
#
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR}"
OUTPUT_JSON="${OUTPUT_JSON:-${OUTPUT_DIR}/environment_intake.json}"

log()  { printf '[intake] %s\n' "$*" >&2; }
warn() { printf '[intake] WARNING: %s\n' "$*" >&2; WARNINGS=$((WARNINGS + 1)); }
die()  { printf '[intake] ERROR: %s\n' "$*" >&2; exit 2; }

WARNINGS=0

# ---------------------------------------------------------------------------
# Environment preconditions -- missing hard dependencies are an environment
# error (exit 2), not a controlled failure.
# ---------------------------------------------------------------------------
for cmd in jq hostname uname find systemctl sysctl dpkg-query ss; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
done
[[ -d "$OUTPUT_DIR" ]] || die "output directory does not exist: $OUTPUT_DIR"
[[ -w "$OUTPUT_DIR" ]] || die "output directory is not writable: $OUTPUT_DIR"

CAPTURED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Capturing environment intake for $(hostname) at $CAPTURED_AT"

# ---------------------------------------------------------------------------
# Host / OS identity
# ---------------------------------------------------------------------------
HOSTNAME_VAL="$(hostname)"
KERNEL_RELEASE="$(uname -r)"
OS_NAME=""
OS_VERSION=""
OS_VERSION_ID=""
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091  # /etc/os-release is a runtime-only file, not a repo path shellcheck can follow
  OS_NAME="$(. /etc/os-release; echo "${NAME:-}")"
  # shellcheck disable=SC1091
  OS_VERSION="$(. /etc/os-release; echo "${VERSION:-}")"
  # shellcheck disable=SC1091
  OS_VERSION_ID="$(. /etc/os-release; echo "${VERSION_ID:-}")"
else
  warn "/etc/os-release not readable; OS identity fields will be empty"
fi

# ---------------------------------------------------------------------------
# Installed package count
# ---------------------------------------------------------------------------
PACKAGE_COUNT="$(dpkg-query -W 2>/dev/null | wc -l)"

# ---------------------------------------------------------------------------
# Listening sockets (ss -tulnpH -> structured rows)
# Columns: netid, state, recv-q, send-q, local_address:port, peer_address:port, process
# ---------------------------------------------------------------------------
LISTENING_SOCKETS_JSON="$(
  ss -tulnpH 2>/dev/null | awk '
    {
      netid=$1; state=$2; local_addr=$5
      proc=""
      for (i=7; i<=NF; i++) proc = proc (i>7 ? " " : "") $i
      # split local_addr into address / port on the LAST colon
      # (handles IPv6 addresses that contain colons themselves)
      n = length(local_addr)
      split_pos = 0
      for (i=n; i>=1; i--) { if (substr(local_addr,i,1) == ":") { split_pos=i; break } }
      addr = (split_pos>0) ? substr(local_addr,1,split_pos-1) : local_addr
      port = (split_pos>0) ? substr(local_addr,split_pos+1) : ""
      gsub(/"/, "\\\"", proc)
      printf "{\"proto\":\"%s\",\"address\":\"%s\",\"port\":\"%s\",\"process\":\"%s\"}\n", netid, addr, port, proc
    }
  ' | jq -s '.'
)"
[[ -n "$LISTENING_SOCKETS_JSON" && "$LISTENING_SOCKETS_JSON" != "null" ]] || LISTENING_SOCKETS_JSON="[]"

# ---------------------------------------------------------------------------
# Active systemd services
# ---------------------------------------------------------------------------
if systemctl list-units --type=service --state=running --no-legend --plain >/tmp/.intake_services 2>/dev/null \
   && [[ -s /tmp/.intake_services ]]; then
  ACTIVE_SERVICES_JSON="$(awk '{print $1}' /tmp/.intake_services | jq -R . | jq -s '.')"
else
  ACTIVE_SERVICES_JSON="[]"
  warn "could not enumerate active systemd services (is systemd PID 1?)"
fi
rm -f /tmp/.intake_services

# ---------------------------------------------------------------------------
# sshd_config as a key-value record (first occurrence wins; comments/blank
# lines skipped; Match blocks are not expanded -- documented limitation)
# ---------------------------------------------------------------------------
SSHD_CONFIG_PATH="/etc/ssh/sshd_config"
if [[ -r "$SSHD_CONFIG_PATH" ]]; then
  SSHD_CONFIG_JSON="$(
    grep -vE '^\s*(#|$)' "$SSHD_CONFIG_PATH" 2>/dev/null | awk '
      { key=$1; $1=""; sub(/^ /,""); value=$0
        if (!(key in seen)) { seen[key]=1; print key "\t" value }
      }' | jq -R -s '
        split("\n") | map(select(length > 0)) | map(split("\t")) |
        map({(.[0]): (.[1] // "")}) | add // {}
      '
  )"
else
  SSHD_CONFIG_JSON="{}"
  warn "sshd_config not readable at $SSHD_CONFIG_PATH"
fi

# ---------------------------------------------------------------------------
# Security-relevant sysctl parameters (curated set; unknown/missing keys
# are recorded as null rather than omitted, so the schema is stable)
# ---------------------------------------------------------------------------
SYSCTL_KEYS=(
  net.ipv4.ip_forward
  net.ipv4.conf.all.rp_filter
  net.ipv4.conf.all.accept_redirects
  net.ipv4.conf.all.send_redirects
  net.ipv4.tcp_syncookies
  net.ipv4.icmp_echo_ignore_broadcasts
  kernel.randomize_va_space
  kernel.dmesg_restrict
  fs.suid_dumpable
)
SYSCTL_JSON="{}"
for key in "${SYSCTL_KEYS[@]}"; do
  val="$(sysctl -n "$key" 2>/dev/null)"
  if [[ -z "$val" ]]; then
    SYSCTL_JSON="$(jq --arg k "$key" '. + {($k): null}' <<< "$SYSCTL_JSON")"
  else
    SYSCTL_JSON="$(jq --arg k "$key" --arg v "$val" '. + {($k): $v}' <<< "$SYSCTL_JSON")"
  fi
done

# ---------------------------------------------------------------------------
# SUID/SGID binary count
# ---------------------------------------------------------------------------
SUID_SGID_COUNT="$(find / -perm /6000 -type f 2>/dev/null | wc -l)"

# ---------------------------------------------------------------------------
# World-writable file count (excluding /proc and /sys)
# ---------------------------------------------------------------------------
WORLD_WRITABLE_COUNT="$(find / -perm -0002 -type f \
  -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | wc -l)"

# ---------------------------------------------------------------------------
# Firewall status (nft ruleset line count; 0 if nft is absent or empty)
# ---------------------------------------------------------------------------
if command -v nft >/dev/null 2>&1; then
  NFT_RULESET_LINES="$(nft list ruleset 2>/dev/null | wc -l)"
else
  NFT_RULESET_LINES=0
  warn "nft not installed; firewall_ruleset_lines recorded as 0"
fi

# ---------------------------------------------------------------------------
# Telemetry presence
# ---------------------------------------------------------------------------
auditd_active="false"
systemctl is-active --quiet auditd 2>/dev/null && auditd_active="true"

rsyslog_active="false"
systemctl is-active --quiet rsyslog 2>/dev/null && rsyslog_active="true"

sysmon_present="false"
sysmon_version=""
if command -v sysmon >/dev/null 2>&1 || [[ -x /opt/sysmon/sysmon ]]; then
  sysmon_present="true"
  sysmon_version="$( { sysmon -v 2>/dev/null || /opt/sysmon/sysmon -v 2>/dev/null; } | head -1)"
fi

# ---------------------------------------------------------------------------
# Assemble and write the JSON snapshot
# ---------------------------------------------------------------------------
jq -n \
  --arg schema_version "1.0" \
  --arg captured_at "$CAPTURED_AT" \
  --arg hostname "$HOSTNAME_VAL" \
  --arg kernel_release "$KERNEL_RELEASE" \
  --arg os_name "$OS_NAME" \
  --arg os_version "$OS_VERSION" \
  --arg os_version_id "$OS_VERSION_ID" \
  --argjson package_count "$PACKAGE_COUNT" \
  --argjson listening_sockets "$LISTENING_SOCKETS_JSON" \
  --argjson active_services "$ACTIVE_SERVICES_JSON" \
  --argjson sshd_config "$SSHD_CONFIG_JSON" \
  --argjson sysctl "$SYSCTL_JSON" \
  --argjson suid_sgid_count "$SUID_SGID_COUNT" \
  --argjson world_writable_count "$WORLD_WRITABLE_COUNT" \
  --argjson firewall_ruleset_lines "$NFT_RULESET_LINES" \
  --argjson auditd_active "$auditd_active" \
  --argjson rsyslog_active "$rsyslog_active" \
  --argjson sysmon_present "$sysmon_present" \
  --arg sysmon_version "$sysmon_version" \
  --argjson warning_count "$WARNINGS" \
  '{
    schema_version: $schema_version,
    captured_at: $captured_at,
    host: {
      hostname: $hostname,
      kernel_release: $kernel_release,
      os_name: $os_name,
      os_version: $os_version,
      os_version_id: $os_version_id
    },
    packages: {
      installed_count: $package_count
    },
    network: {
      listening_sockets: $listening_sockets,
      firewall_ruleset_lines: $firewall_ruleset_lines
    },
    services: {
      active_systemd_services: $active_services
    },
    ssh: {
      sshd_config: $sshd_config
    },
    sysctl: $sysctl,
    filesystem: {
      suid_sgid_count: $suid_sgid_count,
      world_writable_count: $world_writable_count
    },
    telemetry: {
      auditd_active: $auditd_active,
      rsyslog_active: $rsyslog_active,
      sysmon_present: $sysmon_present,
      sysmon_version: $sysmon_version
    },
    capture_warning_count: $warning_count
  }' > "$OUTPUT_JSON" || die "failed to write $OUTPUT_JSON"

log "Wrote $OUTPUT_JSON"
log "packages=$PACKAGE_COUNT listening_sockets=$(jq 'length' <<< "$LISTENING_SOCKETS_JSON") suid_sgid=$SUID_SGID_COUNT world_writable=$WORLD_WRITABLE_COUNT warnings=$WARNINGS"

if [[ "$WARNINGS" -gt 0 ]]; then
  log "completed with $WARNINGS warning(s) -- see above"
  exit 1
fi

exit 0