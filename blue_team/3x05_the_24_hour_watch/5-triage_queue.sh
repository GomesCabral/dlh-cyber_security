#!/bin/bash

set -Eeuo pipefail

fail() {
    printf '[triage] ERROR: %s\n' "$*" >&2
    exit 1
}

queue="$SHIFT_WORKSPACE/alerts/alert_queue.json"
briefing="$SHIFT_WORKSPACE/alerts/shift_briefing.json"
baseline="$SHIFT_WORKSPACE/enriched/baseline.json"
assets="$ASSETS_DIR/assets.json"
output="$SHIFT_WORKSPACE/alerts/triage_log.jsonl"

[[ -s "$queue" ]] || fail "alert_queue.json missing"
[[ -s "$briefing" ]] || fail "shift_briefing.json missing"

alert_count="$(jq 'length' "$queue")"
ioc_count="$(jq '.ioc_count' "$briefing")"
change_count="$(jq '.active_change_tickets | length' "$briefing")"

printf '[triage] alert_queue: %s alerts\n' "$alert_count"
printf '[triage] briefing loaded (%s IOCs, %s change tickets)\n' \
    "$ioc_count" "$change_count"
printf '[triage] invoking %s\n' "$TRIAGE_BIN"
printf '[triage] classifying %s alerts\n' "$alert_count"

"$TRIAGE_BIN" \
    "$queue" \
    "$briefing" \
    "$baseline" \
    "$assets" \
    "$output" ||
    fail "triage runner failed"

[[ -s "$output" ]] || fail "triage_log.jsonl missing"

log_count="$(wc -l < "$output")"
unclassified=$((alert_count - log_count))

tp="$(jq -s '[.[] | select(.classification == "TP")] | length' "$output")"
fp="$(jq -s '[.[] | select(.classification == "FP")] | length' "$output")"
noise="$(jq -s '[.[] | select(.classification == "NOISE")] | length' "$output")"
invalid="$(jq -s '[.[] | select(
    .classification != "TP"
    and .classification != "FP"
    and .classification != "NOISE"
)] | length' "$output")"

(( invalid == 0 )) || fail "$invalid records have invalid classification"
(( unclassified == 0 )) || fail "$unclassified alerts remain unclassified"

printf '[triage] TP=%s FP=%s NOISE=%s unclassified=%s\n' \
    "$tp" "$fp" "$noise" "$unclassified"
printf '[triage] triage_log.jsonl written\n'
