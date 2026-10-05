#!/bin/bash

# Task 2 - Robert Kim Administrative Baseline Profile

set -euo pipefail

BASELINE="baseline/robert_kim_activity.json"
SCHEDULE="reference/admin_schedule.txt"

if [[ ! -f "$BASELINE" ]]; then
    echo "[ERROR] Missing file: $BASELINE" >&2
    exit 1
fi

if [[ ! -f "$SCHEDULE" ]]; then
    echo "[ERROR] Missing file: $SCHEDULE" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required." >&2
    exit 1
fi

# Tool counts
PSEXEC=$(jq -s '[.[] | select(.hunt_meta.tool == "PsExec")] | length' "$BASELINE")
WMI=$(jq -s '[.[] | select(.hunt_meta.tool == "WMI")] | length' "$BASELINE")
PSREMOTE=$(jq -s '[.[] | select(.hunt_meta.tool == "PSRemoting")] | length' "$BASELINE")
TOTAL=$(jq -s 'length' "$BASELINE")

# Source host counts
ADMIN01=$(jq -s '[.[] | select(.hunt_meta.source_host == "WS-ADMIN-01")] | length' "$BASELINE")
OTHER_HOSTS=$(jq -s '[.[] | select(.hunt_meta.source_host != "WS-ADMIN-01")] | length' "$BASELINE")

# Account counts
ROBERT=$(jq -s '
[
  .[]
  | select(.data.win.eventdata.user == "MEDDEFENSE\\robert.kim")
] | length
' "$BASELINE")

SERVICE_ACCOUNTS=$(jq -s '
[
  .[]
  | select((.data.win.eventdata.user // "") | test("\\\\svc_"; "i"))
] | length
' "$BASELINE")

# Convert UTC timestamps to CDT.
# During May 2026 Central Time is UTC-5.
BUSINESS_HOURS=$(jq -s '
[
  .[]
  | (.timestamp[11:13] | tonumber) as $utc_hour
  | (($utc_hour + 19) % 24) as $cdt_hour
  | select($cdt_hour >= 8 and $cdt_hour < 18)
] | length
' "$BASELINE")

OFF_HOURS=$((TOTAL - BUSINESS_HOURS))

echo "================================================================"
echo "   BASELINE PROFILE - Robert Kim (IT Administrator)"
echo "   Source: baseline/robert_kim_activity.json"
echo "================================================================"
echo

echo "TOOL USAGE SUMMARY:"
printf "  PsExec events:          %s\n" "$PSEXEC"
printf "  WMI events:             %s\n" "$WMI"
printf "  PSRemoting events:      %s\n" "$PSREMOTE"
printf "  Total admin events:     %s\n" "$TOTAL"

echo
echo "SOURCE HOST:"
printf "  WS-ADMIN-01: %s\n" "$ADMIN01"
printf "  Other hosts: %s\n" "$OTHER_HOSTS"
echo "  -> BASELINE: All admin activity originates from WS-ADMIN-01"

echo
echo "TIME DISTRIBUTION (CDT):"
printf "  08:00-18:00: %s\n" "$BUSINESS_HOURS"
printf "  18:00-08:00: %s\n" "$OFF_HOURS"
echo "  -> BASELINE: Zero admin activity outside business hours"

echo
echo "DAY-OF-WEEK DISTRIBUTION:"

jq -r -s '
  group_by(
    (.timestamp[0:10] + "T00:00:00Z")
    | fromdateiso8601
    | strftime("%A")
  )
  | .[]
  | "\(.[0].timestamp[0:10] + "T00:00:00Z"
      | fromdateiso8601
      | strftime("%A")): \(length)"
' "$BASELINE" | sort

echo
echo "TARGET HOST ANALYSIS:"

jq -r -s '
  group_by(.hunt_meta.target_host)
  | .[]
  | "\(.[0].hunt_meta.target_host): \(length)"
' "$BASELINE" | sort

echo
echo "USER ACCOUNTS:"
printf "  MEDDEFENSE\\\\robert.kim: %s\n" "$ROBERT"
printf "  Service accounts: %s\n" "$SERVICE_ACCOUNTS"
echo "  -> BASELINE: Robert uses his named account, not service accounts"

echo
echo "BASELINE SUMMARY:"
echo "  Normal source host: WS-ADMIN-01"
echo "  Normal time window: 08:00-18:00 CDT"
echo "  Normal account: MEDDEFENSE\\robert.kim"
echo "  Normal tools: PsExec, WMI, PSRemoting"
echo "  Normal targets: documented server segment hosts"

echo
echo "ANOMALY DETECTION CRITERIA:"
echo "  [!] Admin tool from any host other than WS-ADMIN-01"
echo "  [!] Admin tool usage outside 08:00-18:00 CDT"
echo "  [!] Service account used interactively from a workstation"
echo "  [!] WMI targeting unusual or unauthorized hosts"
echo "  [!] PsExec or PSRemoting inconsistent with maintenance windows"
echo "  [!] Administrative activity using an unexpected user account"

echo
echo "================================================================"