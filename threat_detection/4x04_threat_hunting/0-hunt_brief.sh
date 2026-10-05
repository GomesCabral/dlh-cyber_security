#!/bin/bash

# HEALTHBANE Stage 4 - Threat Hunt Brief
# Task 0
#
# Reads the provided intelligence and ATT&CK mapping files and builds
# the initial scope and priorities for the Stage 4 threat hunt.

set -euo pipefail

ADVISORY="reference/hc3_advisory_004.txt"
ATTACK_MAPPING="reference/4x03_attack_mapping.json"
ADMIN_SCHEDULE="reference/admin_schedule.txt"
SERVICE_ACCOUNTS="reference/service_accounts.txt"
NETWORK_TOPOLOGY="reference/network_topology.txt"

# ------------------------------------------------------------
# Check required files
# ------------------------------------------------------------

for file in \
    "$ADVISORY" \
    "$ATTACK_MAPPING" \
    "$ADMIN_SCHEDULE" \
    "$SERVICE_ACCOUNTS" \
    "$NETWORK_TOPOLOGY"
do
    if [[ ! -f "$file" ]]; then
        echo "[ERROR] Required file not found: $file" >&2
        exit 1
    fi
done

# ------------------------------------------------------------
# Check jq
# ------------------------------------------------------------

if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required but was not found." >&2
    exit 1
fi

# ------------------------------------------------------------
# Read ATT&CK coverage summary
# ------------------------------------------------------------

TOTAL=$(jq -r '.technique_count_summary.total_in_threat_model' "$ATTACK_MAPPING")
OBSERVED=$(jq -r '.technique_count_summary.observed' "$ATTACK_MAPPING")
INFERRED=$(jq -r '.technique_count_summary.inferred' "$ATTACK_MAPPING")
NOT_COVERED=$(jq -r '.technique_count_summary.not_covered' "$ATTACK_MAPPING")
PERCENT_OBSERVED=$(jq -r '.technique_count_summary.percent_observed' "$ATTACK_MAPPING")

# ------------------------------------------------------------
# Function: get current ATT&CK state
# ------------------------------------------------------------

get_state() {
    local technique_id="$1"

    jq -r --arg id "$technique_id" '
        .techniques[]
        | select(.techniqueID == $id)
        | if .score == 3 then "OBSERVED"
          elif .score == 2 then "INFERRED"
          elif .score == 0 then "NOT COVERED"
          else "UNKNOWN"
          end
    ' "$ATTACK_MAPPING"
}

# ------------------------------------------------------------
# Stage 4 ATT&CK techniques
# ------------------------------------------------------------

PSEXEC_STATE=$(get_state "T1021.002")
WMI_STATE=$(get_state "T1047")
PSREMOTE_STATE=$(get_state "T1021.006")
LSASS_STATE=$(get_state "T1003.001")
DOMAIN_STATE=$(get_state "T1078.002")

# ------------------------------------------------------------
# Confirm that the advisory contains the expected Stage 4 TTPs
# ------------------------------------------------------------

check_advisory_ttp() {
    local pattern="$1"
    local description="$2"

    if grep -Eiq "$pattern" "$ADVISORY"; then
        printf '    [*] %s\n' "$description"
    else
        printf '    [!] %s - not found in advisory\n' "$description"
    fi
}

# ------------------------------------------------------------
# Output
# ------------------------------------------------------------

echo "================================================================"
echo "   THREAT HUNT BRIEF - HEALTHBANE Stage 4 (LOLBin Lateral Movement)"
echo "   Classification: TLP:AMBER"
echo "================================================================"
echo

echo "HC3 ADVISORY SUMMARY:"
echo "  Stage 4 TTPs:"

check_advisory_ttp \
    "PsExec" \
    "PsExec for remote command execution on servers"

check_advisory_ttp \
    "WMI|wmic" \
    "WMI for remote process creation and enumeration"

check_advisory_ttp \
    "PSRemoting|PowerShell Remoting|Enter-PSSession|Invoke-Command" \
    "PowerShell Remoting for interactive access and staging"

check_advisory_ttp \
    "LSASS|lsass" \
    "Credential dumping via LSASS memory access"

check_advisory_ttp \
    "service account" \
    "Service account abuse for lateral authentication"

check_advisory_ttp \
    "01:00.*05:00|off-hours" \
    "Off-hours operations to avoid detection"

echo

echo "ATT&CK COVERAGE GAP ANALYSIS:"
echo "  Current coverage: ${OBSERVED}/${TOTAL} techniques (${PERCENT_OBSERVED}%)"
echo "  Coverage states:"
echo "    OBSERVED:    ${OBSERVED}"
echo "    INFERRED:    ${INFERRED}"
echo "    NOT COVERED: ${NOT_COVERED}"
echo
echo "  Stage 4 techniques in gap:"
printf '    %-10s %-30s %s\n' \
    "T1021.002" "SMB/Windows Admin Shares" "$PSEXEC_STATE"

printf '    %-10s %-30s %s\n' \
    "T1047" "WMI" "$WMI_STATE"

printf '    %-10s %-30s %s\n' \
    "T1021.006" "Windows Remote Management" "$PSREMOTE_STATE"

printf '    %-10s %-30s %s\n' \
    "T1003.001" "LSASS Memory" "$LSASS_STATE"

printf '    %-10s %-30s %s\n' \
    "T1078.002" "Domain Accounts" "$DOMAIN_STATE"

echo

echo "HUNT PRIORITY RANKING:"
echo "  P1: T1021.002 PsExec"
echo "  P2: T1003.001 LSASS"
echo "  P3: T1047 WMI"
echo "  P4: T1021.006 PSRemoting"
echo "  P5: T1078.002 Domain Accounts"

echo

echo "DATA SOURCES:"
echo "  Primary:   siem_export/wazuh_alerts_14d.json"
echo "  Secondary: siem_export/wazuh_raw_sysmon_14d.json"
echo "  Baseline:  baseline/robert_kim_activity.json"
echo "  Reference: admin_schedule.txt, service_accounts.txt, network_topology.txt"

echo
echo "TIME WINDOW: 14 days (2026-05-04 through 2026-05-18)"

echo

echo "FALSE-POSITIVE CONTROLS:"
echo "  [*] Robert Kim authorized maintenance schedule"
echo "  [*] Service account authorization matrix"
echo "  [*] Network topology and authorized host roles"

echo
echo "================================================================"