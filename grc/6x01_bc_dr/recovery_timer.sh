#!/bin/bash
set -u
STATE_DIR=/tmp/rtest_state
LOG_FILE="${RECOVERY_TEST_LOG:-$(pwd)/recovery_test_log.txt}"
RTO_SECONDS=1800
usage() { printf 'Usage: %s "Step name" START|PASS|FAIL\n       %s SUMMARY\n' "$0" "$0" >&2; exit 2; }
[[ $# -eq 1 && $1 == SUMMARY ]] || [[ $# -eq 2 ]] || usage
mkdir -p "$STATE_DIR" || exit 1
now=$(date +%s)
clock=$(date '+%H:%M:%S')
format_duration() { local n=$1; printf '%dm %02ds' "$((n/60))" "$((n%60))"; }
if [[ $1 == SUMMARY ]]; then
    [[ -f "$STATE_DIR/test_start" ]] || { echo 'No test started.' >&2; exit 1; }
    start=$(cat "$STATE_DIR/test_start")
    elapsed=$((now-start))
    result=PASS
    (( elapsed > RTO_SECONDS )) && result=FAIL
    if [[ -f "$STATE_DIR/failed" ]]; then outcome=FAIL; else outcome=$result; fi
    printf 'SUMMARY | Start: %s | End: %s | Total: %s | RTO: 30m 00s | RTO result: %s | Test steps: %s\n' "$(cat "$STATE_DIR/test_clock")" "$clock" "$(format_duration "$elapsed")" "$result" "$outcome"
    exit 0
fi
step=$1
status=$2
[[ -n $step && $step != *$'\n'* && $step != *'|'* ]] || usage
case "$status" in START|PASS|FAIL) ;; *) usage ;; esac
if [[ $status == START ]]; then
    if [[ ! -f "$STATE_DIR/test_start" ]]; then
        printf '%s\n' "$now" > "$STATE_DIR/test_start"
        printf '%s\n' "$clock" > "$STATE_DIR/test_clock"
        : > "$LOG_FILE"
        printf '0\n' > "$STATE_DIR/count"
        rm -f "$STATE_DIR/failed"
    fi
    [[ ! -f "$STATE_DIR/current" ]] || { echo 'Finish the active step before starting another.' >&2; exit 1; }
    count=$(cat "$STATE_DIR/count")
    count=$((count+1))
    printf '%s\n' "$count" > "$STATE_DIR/count"
    printf '%s\t%s\t%s\t%s\n' "$count" "$step" "$now" "$clock" > "$STATE_DIR/current"
    exit 0
fi
[[ -f "$STATE_DIR/current" ]] || { echo 'No active step.' >&2; exit 1; }
IFS=$'\t' read -r count active_step started start_clock < "$STATE_DIR/current"
[[ $step == "$active_step" ]] || { echo "Active step is: $active_step" >&2; exit 1; }
elapsed=$((now-started))
printf '[STEP %02d] %-30s | Start: %s | End: %s | Duration: %s | %s\n' "$count" "$step" "$start_clock" "$clock" "$(format_duration "$elapsed")" "$status" | tee -a "$LOG_FILE"
[[ $status == FAIL ]] && touch "$STATE_DIR/failed"
rm -f "$STATE_DIR/current"
