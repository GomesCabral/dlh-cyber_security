#!/bin/bash
#
# 2-target_state.sh
#
# Declares the finish line for the Hawthorne handoff as a machine-readable
# contract: capstone/target_state.json. This is the source of truth every
# downstream task validates against -- it is defined here, before the
# hardening/instrumentation/patching/segmentation work is scored, so the
# criteria cannot be invented retroactively to match whatever shipped.
#
# check_target convention for json_field_equals / json_field_gte controls:
#   "<path/to/file.json>#<jq filter>"
#   e.g. "environment_intake.json#.ssh.sshd_config.PermitRootLogin"
# The validation suite splits on the first '#', reads the file at the left
# side, and evaluates the jq filter on the right side against it.
#
# A missing or corrupted target_state.json MUST be treated as fatal by
# every downstream validation script -- there is no meaningful pass/fail
# verdict without this contract. This script itself refuses to silently
# overwrite an existing one for the same reason: the finish line does not
# move to match convenience.
#
# Usage:
#   ./2-target_state.sh [capstone_dir] [--force]
#
# Exit codes:
#   0 - success, target_state.json written
#   1 - controlled failure (target_state.json already exists, --force not given)
#   2 - environment error (cannot write output / internal control data invalid)
#
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

FORCE=0
CAPSTONE_DIR=""
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    *) [[ -z "$CAPSTONE_DIR" ]] && CAPSTONE_DIR="$arg" ;;
  esac
done
CAPSTONE_DIR="${CAPSTONE_DIR:-$SCRIPT_DIR/capstone}"
OUTPUT_JSON="$CAPSTONE_DIR/target_state.json"

die() {
  printf '[target_state] ERROR: %s\n' "$1" >&2
  case "${2:-2}" in
    1) exit 1 ;;
    *) exit 2 ;;
  esac
}

command -v jq >/dev/null 2>&1 || die "jq is required to assemble target_state.json" 2

if [[ -f "$OUTPUT_JSON" && "$FORCE" -ne 1 ]]; then
  printf '[target_state] ERROR: %s already exists; pass --force to overwrite the target-state contract\n' "$OUTPUT_JSON" >&2
  exit 1
fi

mkdir -p "$CAPSTONE_DIR" || die "failed to create $CAPSTONE_DIR" 2
[[ -w "$CAPSTONE_DIR" ]] || die "$CAPSTONE_DIR is not writable" 2

# ---------------------------------------------------------------------------
# The control list. One entry per checkable fact. IDs are stable and follow
# <PLATFORM>-<FAMILY_CODE>-<NN>. Embedded as a literal JSON array (rather
# than built control-by-control with jq calls) so the full contract is
# readable in one place; it is syntax-validated with `jq empty` below
# before anything is written.
# ---------------------------------------------------------------------------
read -r -d '' CONTROLS_JSON << 'EOF'
[
  {
    "id": "LNX-SSH-01",
    "platform": "linux",
    "family": "hardening",
    "description": "SSH must refuse direct root login.",
    "check_type": "json_field_equals",
    "check_target": "environment_intake.json#.ssh.sshd_config.PermitRootLogin",
    "expected_value": "no",
    "source_project": "2x00",
    "severity": "critical"
  },
  {
    "id": "LNX-SSH-02",
    "platform": "linux",
    "family": "hardening",
    "description": "SSH must refuse password authentication.",
    "check_type": "json_field_equals",
    "check_target": "environment_intake.json#.ssh.sshd_config.PasswordAuthentication",
    "expected_value": "no",
    "source_project": "2x00",
    "severity": "critical"
  },
  {
    "id": "LNX-SYSCTL-01",
    "platform": "linux",
    "family": "hardening",
    "description": "IP forwarding must be disabled at the kernel level.",
    "check_type": "json_field_equals",
    "check_target": "environment_intake.json#.sysctl.\"net.ipv4.ip_forward\"",
    "expected_value": "0",
    "source_project": "2x00",
    "severity": "high"
  },
  {
    "id": "LNX-SYSCTL-02",
    "platform": "linux",
    "family": "hardening",
    "description": "ASLR must be fully enabled (randomize_va_space = 2).",
    "check_type": "json_field_equals",
    "check_target": "environment_intake.json#.sysctl.\"kernel.randomize_va_space\"",
    "expected_value": "2",
    "source_project": "2x00",
    "severity": "medium"
  },
  {
    "id": "LNX-AUDITD-01",
    "platform": "linux",
    "family": "telemetry",
    "description": "auditd must be active.",
    "check_type": "json_field_equals",
    "check_target": "environment_intake.json#.telemetry.auditd_active",
    "expected_value": true,
    "source_project": "2x00",
    "severity": "high"
  },
  {
    "id": "LNX-APPARMOR-01",
    "platform": "linux",
    "family": "hardening",
    "description": "AppArmor must have at least one profile in enforce mode.",
    "check_type": "command_exit_zero",
    "check_target": "test \"$(aa-status --enforced 2>/dev/null | wc -l)\" -gt 0",
    "expected_value": 0,
    "source_project": "2x00",
    "severity": "high"
  },
  {
    "id": "LNX-LYNIS-01",
    "platform": "linux",
    "family": "hardening",
    "description": "Lynis hardening index must be at least 80.",
    "check_type": "json_field_gte",
    "check_target": "capstone/baseline/baseline_linux.json#.hardening_index",
    "expected_value": 80,
    "source_project": "2x05 (T1)",
    "severity": "high"
  },
  {
    "id": "WIN-FW-01",
    "platform": "windows",
    "family": "hardening",
    "description": "Windows Firewall must default-deny inbound on every profile.",
    "check_type": "command_exit_zero",
    "check_target": "powershell -NoProfile -Command \"exit [int]((Get-NetFirewallProfile | Where-Object { $_.DefaultInboundAction -ne 'Block' -or $_.Enabled -ne $true }).Count -gt 0)\"",
    "expected_value": 0,
    "source_project": "2x01",
    "severity": "critical"
  },
  {
    "id": "WIN-PSLOG-01",
    "platform": "windows",
    "family": "telemetry",
    "description": "PowerShell Script Block Logging must be enabled.",
    "check_type": "json_field_equals",
    "check_target": "environment_intake.json#.telemetry.script_block_logging_enabled",
    "expected_value": true,
    "source_project": "2x00",
    "severity": "high"
  },
  {
    "id": "WIN-SYSMON-01",
    "platform": "windows",
    "family": "telemetry",
    "description": "Sysmon service must be installed and running.",
    "check_type": "json_field_equals",
    "check_target": "environment_intake.json#.telemetry.sysmon_present",
    "expected_value": true,
    "source_project": "2x02",
    "severity": "high"
  },
  {
    "id": "WIN-AUD-01",
    "platform": "windows",
    "family": "telemetry",
    "description": "Audit policy must cover the Account Logon subcategory.",
    "check_type": "grep_match",
    "check_target": "capstone/baseline/windows_baseline.log",
    "expected_value": "Account Logon",
    "source_project": "2x02",
    "severity": "medium"
  },
  {
    "id": "WIN-AUD-02",
    "platform": "windows",
    "family": "telemetry",
    "description": "Audit policy must cover the Logon subcategory.",
    "check_type": "grep_match",
    "check_target": "capstone/baseline/windows_baseline.log",
    "expected_value": "^Logon$|[^/]Logon[^/]",
    "source_project": "2x02",
    "severity": "medium"
  },
  {
    "id": "WIN-AUD-03",
    "platform": "windows",
    "family": "telemetry",
    "description": "Audit policy must cover the Object Access subcategory.",
    "check_type": "grep_match",
    "check_target": "capstone/baseline/windows_baseline.log",
    "expected_value": "Object Access",
    "source_project": "2x02",
    "severity": "medium"
  },
  {
    "id": "WIN-AUD-04",
    "platform": "windows",
    "family": "telemetry",
    "description": "Audit policy must cover the Privilege Use subcategory.",
    "check_type": "grep_match",
    "check_target": "capstone/baseline/windows_baseline.log",
    "expected_value": "Privilege Use",
    "source_project": "2x02",
    "severity": "medium"
  },
  {
    "id": "WIN-CIS-01",
    "platform": "windows",
    "family": "hardening",
    "description": "CIS Level 1 control pass rate must be at least 85 percent.",
    "check_type": "json_field_gte",
    "check_target": "capstone/baseline/baseline_windows.json#.pass_rate_percent",
    "expected_value": 85,
    "source_project": "2x05 (T1)",
    "severity": "high"
  },
  {
    "id": "LNX-AUDITD-02",
    "platform": "linux",
    "family": "telemetry",
    "description": "An auditd rules file must be present.",
    "check_type": "file_exists",
    "check_target": "/etc/audit/rules.d/hardening.rules",
    "expected_value": true,
    "source_project": "2x02",
    "severity": "high"
  },
  {
    "id": "LNX-AUDITD-03",
    "platform": "linux",
    "family": "telemetry",
    "description": "auditd rules must be loaded into the running kernel ruleset.",
    "check_type": "command_exit_zero",
    "check_target": "test \"$(auditctl -l 2>/dev/null | grep -cv '^No rules')\" -gt 0",
    "expected_value": 0,
    "source_project": "2x02",
    "severity": "high"
  },
  {
    "id": "BOTH-TELEM-01",
    "platform": "both",
    "family": "telemetry",
    "description": "The structured telemetry export path must exist.",
    "check_type": "file_exists",
    "check_target": "capstone/telemetry_handoff/",
    "expected_value": true,
    "source_project": "2x02",
    "severity": "high"
  },
  {
    "id": "WIN-SYSMON-02",
    "platform": "windows",
    "family": "telemetry",
    "description": "Sysmon must have logged at least one event in the last 10 minutes.",
    "check_type": "command_exit_zero",
    "check_target": "powershell -NoProfile -Command \"exit [int]((Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0)\"",
    "expected_value": 0,
    "source_project": "2x02",
    "severity": "medium"
  },
  {
    "id": "WIN-PSLOG-02",
    "platform": "windows",
    "family": "telemetry",
    "description": "The Script Block Logging event channel must have non-zero configured size.",
    "check_type": "command_exit_zero",
    "check_target": "powershell -NoProfile -Command \"exit [int]((Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational').MaximumSizeInBytes -le 0)\"",
    "expected_value": 0,
    "source_project": "2x02",
    "severity": "medium"
  },
  {
    "id": "BOTH-PATCH-01",
    "platform": "both",
    "family": "patching",
    "description": "The vulnerability inventory artifact must be present.",
    "check_type": "file_exists",
    "check_target": "capstone/patching/vulnerability_inventory.json",
    "expected_value": true,
    "source_project": "2x03",
    "severity": "high"
  },
  {
    "id": "BOTH-PATCH-02",
    "platform": "both",
    "family": "patching",
    "description": "The patch plan artifact must be present.",
    "check_type": "file_exists",
    "check_target": "capstone/patching/patch_plan.json",
    "expected_value": true,
    "source_project": "2x03",
    "severity": "high"
  },
  {
    "id": "BOTH-PATCH-03",
    "platform": "both",
    "family": "patching",
    "description": "The patch execution log must be present with zero failed entries.",
    "check_type": "json_field_equals",
    "check_target": "capstone/patching/patch_execution_log.json#(.entries // [] | map(select(.state == \"failed\")) | length)",
    "expected_value": 0,
    "source_project": "2x03",
    "severity": "critical"
  },
  {
    "id": "LNX-UU-01",
    "platform": "linux",
    "family": "patching",
    "description": "unattended-upgrades must be configured with the mandated package blacklist.",
    "check_type": "grep_match",
    "check_target": "/etc/apt/apt.conf.d/50unattended-upgrades",
    "expected_value": "Unattended-Upgrade::Package-Blacklist",
    "source_project": "2x03",
    "severity": "medium"
  },
  {
    "id": "NET-NFT-01",
    "platform": "network",
    "family": "network",
    "description": "nftables input chain must default to drop.",
    "check_type": "grep_match",
    "check_target": "nftables.conf",
    "expected_value": "policy drop",
    "source_project": "2x04",
    "severity": "critical"
  },
  {
    "id": "NET-SEG-01",
    "platform": "network",
    "family": "network",
    "description": "The segmentation rules artifact must be present.",
    "check_type": "file_exists",
    "check_target": "segmentation_rules.json",
    "expected_value": true,
    "source_project": "2x04",
    "severity": "high"
  },
  {
    "id": "NET-SURICATA-01",
    "platform": "network",
    "family": "network",
    "description": "The custom Suricata rule file must be loaded with at least six rules.",
    "check_type": "command_exit_zero",
    "check_target": "test \"$(grep -cE '^\\s*alert\\s' meddefense.rules)\" -ge 6",
    "expected_value": 0,
    "source_project": "2x04 (T10)",
    "severity": "critical"
  },
  {
    "id": "NET-SURICATA-02",
    "platform": "network",
    "family": "network",
    "description": "The Suricata rule validation report must show every custom rule fired against its target PCAP.",
    "check_type": "json_field_equals",
    "check_target": "rule_validation.json#.failed",
    "expected_value": 0,
    "source_project": "2x04 (T10)",
    "severity": "critical"
  },
  {
    "id": "NET-DNS-01",
    "platform": "network",
    "family": "network",
    "description": "The local DNS filter must be active.",
    "check_type": "command_exit_zero",
    "check_target": "systemctl is-active --quiet dnsmasq",
    "expected_value": 0,
    "source_project": "2x04 (T13)",
    "severity": "high"
  },
  {
    "id": "HND-COMPLIANCE-01",
    "platform": "both",
    "family": "handoff",
    "description": "The compliance report artifact must be present.",
    "check_type": "file_exists",
    "check_target": "capstone/compliance.json",
    "expected_value": true,
    "source_project": "2x05 (T10)",
    "severity": "high"
  },
  {
    "id": "HND-MANIFEST-01",
    "platform": "both",
    "family": "handoff",
    "description": "The handoff manifest must be present with a SHA-256 hash recorded per file.",
    "check_type": "json_field_equals",
    "check_target": "capstone/manifest.json#(.files // [] | map(has(\"sha256\") and (.sha256 | length) == 64) | all)",
    "expected_value": true,
    "source_project": "2x05",
    "severity": "critical"
  },
  {
    "id": "HND-TELEM-PKG-01",
    "platform": "both",
    "family": "handoff",
    "description": "The telemetry export package must exist and be tarballed.",
    "check_type": "file_exists",
    "check_target": "capstone/telemetry_handoff.tar.gz",
    "expected_value": true,
    "source_project": "2x05",
    "severity": "medium"
  },
  {
    "id": "HND-RUNBOOK-01",
    "platform": "both",
    "family": "handoff",
    "description": "The operations runbook script must be present and executable.",
    "check_type": "command_exit_zero",
    "check_target": "test -x capstone/runbook.sh",
    "expected_value": 0,
    "source_project": "2x05",
    "severity": "high"
  }
]
EOF

echo "$CONTROLS_JSON" | jq empty 2>/dev/null \
  || die "internal control list failed JSON validation -- this is a script bug, not an environment issue" 2

CONTROL_COUNT="$(echo "$CONTROLS_JSON" | jq 'length')"
[[ "$CONTROL_COUNT" -ge 1 ]] || die "control list is empty after validation" 2

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
  --arg schema_version "1.0" \
  --arg generated_at "$GENERATED_AT" \
  --argjson controls "$CONTROLS_JSON" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    controls: $controls
  }' > "$OUTPUT_JSON" || die "failed to write $OUTPUT_JSON" 2

exit 0