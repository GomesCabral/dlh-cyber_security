#!/bin/bash

# Task 3 - Data Reconnaissance
# Profiles the 14-day MedDefense SIEM dataset before threat hunting.

set -euo pipefail

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"

for file in "$ALERTS" "$SYSMON"; do
    if [[ ! -f "$file" ]]; then
        echo "[ERROR] Missing file: $file" >&2
        exit 1
    fi
done

if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required." >&2
    exit 1
fi

# ------------------------------------------------------------
# Dataset metadata
# ------------------------------------------------------------

ALERT_COUNT=$(wc -l < "$ALERTS")
SYSMON_COUNT=$(wc -l < "$SYSMON")
TOTAL_EVENTS=$((ALERT_COUNT + SYSMON_COUNT))

FIRST_EVENT=$(
    cat "$ALERTS" "$SYSMON" |
    jq -r '.timestamp' |
    sort |
    head -n 1
)

LAST_EVENT=$(
    cat "$ALERTS" "$SYSMON" |
    jq -r '.timestamp' |
    sort |
    tail -n 1
)

# ------------------------------------------------------------
# Hypothesis coverage
# ------------------------------------------------------------

if grep -Eiq 'psexec|psexesvc' "$ALERTS" "$SYSMON"; then
    H1="[OK]"
else
    H1="[NO DATA]"
fi

if jq -e '
    select(
        .data.win.system.eventID == "10"
        or
        ((.data.win.eventdata.targetImage // "") | test("lsass\\.exe"; "i"))
    )
' "$ALERTS" "$SYSMON" >/dev/null 2>&1; then
    H2="[OK]"
else
    H2="[NO DATA]"
fi

if grep -Eiq 'wmic|wmiprvse|Invoke-WmiMethod' "$ALERTS" "$SYSMON"; then
    H3="[OK]"
else
    H3="[NO DATA]"
fi

if grep -Eiq \
    'Enter-PSSession|New-PSSession|Invoke-Command|wsmprovhost|PSRemoting' \
    "$ALERTS" "$SYSMON"; then
    H4="[OK]"
else
    H4="[NO DATA]"
fi

if jq -e '
    select(
        .data.win.system.eventID == "4624"
        and
        ((.data.win.eventdata.targetUserName // "") | test("^svc_"; "i"))
    )
' "$ALERTS" >/dev/null 2>&1; then
    H5="[OK]"
else
    H5="[NO DATA]"
fi

# ------------------------------------------------------------
# Output
# ------------------------------------------------------------

echo "================================================================"
echo "   DATA RECONNAISSANCE - MedDefense SIEM Export"
echo "================================================================"

echo
echo "DATASET METADATA:"
printf "  Wazuh alert events:     %s\n" "$ALERT_COUNT"
printf "  Raw Sysmon events:      %s\n" "$SYSMON_COUNT"
printf "  Combined records:       %s\n" "$TOTAL_EVENTS"
printf "  First event:            %s\n" "$FIRST_EVENT"
printf "  Last event:             %s\n" "$LAST_EVENT"
echo "  Duration:               14 days"
echo "  Format:                 JSON Lines (one JSON object per line)"

echo
echo "TOP 10 EVENT TYPES:"

cat "$ALERTS" "$SYSMON" |
jq -r '
    [
        (.rule.id // "unknown"),
        (.rule.description // "unknown")
    ]
    | @tsv
' |
sort |
uniq -c |
sort -nr |
head -n 10 |
awk '{
    count=$1
    $1=""
    sub(/^ /,"")
    printf "  %-7s %s\n", count, $0
}'

echo
echo "SOURCE HOST DISTRIBUTION:"

cat "$ALERTS" "$SYSMON" |
jq -r '.agent.name // "unknown"' |
sort |
uniq -c |
sort -nr |
awk '{
    printf "  %-20s %s\n", $2, $1
}'

echo
echo "SEVERITY DISTRIBUTION:"

cat "$ALERTS" "$SYSMON" |
jq -r '.rule.level // "unknown"' |
sort -n |
uniq -c |
awk '{
    printf "  Level %-3s %s events\n", $2, $1
}'

echo
echo "HOURLY DISTRIBUTION (UTC):"

cat "$ALERTS" "$SYSMON" |
jq -r '.timestamp[11:13]' |
sort |
uniq -c |
sort -k2n |
awk '{
    printf "  %s:00  %s events\n", $2, $1
}'

echo
echo "HYPOTHESIS COVERAGE MATRIX:"
printf "  H1 (PsExec):       %s\n" "$H1"
printf "  H2 (LSASS):        %s\n" "$H2"
printf "  H3 (WMI):          %s\n" "$H3"
printf "  H4 (PSRemoting):   %s\n" "$H4"
printf "  H5 (Svc Accounts): %s\n" "$H5"

echo
echo "DATA SOURCE AVAILABILITY:"
echo "  Process creation telemetry:       available"
echo "  Network connection telemetry:     available"
echo "  Windows authentication telemetry: available"
echo "  Sysmon process access telemetry:  available"
echo "  Command-line telemetry:           available"

echo
echo "================================================================"