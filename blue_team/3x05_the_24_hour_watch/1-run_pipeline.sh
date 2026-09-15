#!/bin/bash

set -Eeuo pipefail

fail() {
    printf '[pipeline] ERROR: %s\n' "$*" >&2
    exit 1
}

for variable in SHIFT_WORKSPACE PIPELINE_BIN CAPSTONE_PACK
do
    [[ -n "${!variable:-}" ]] ||
        fail "$variable is not defined"
done

intake_file="$SHIFT_WORKSPACE/runtime/shift_start.json"
log_file="$SHIFT_WORKSPACE/runtime/pipeline_run.log"
run_file="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
output_dir="$SHIFT_WORKSPACE/enriched"

[[ -s "$intake_file" ]] ||
    fail "shift_start.json is absent or empty"

jq empty "$intake_file" 2>/dev/null ||
    fail "shift_start.json is invalid"

printf '[pipeline] intake check: OK\n'
printf '[pipeline] invoking %s\n' "$PIPELINE_BIN"
printf '[pipeline] input: %s\n' "$CAPSTONE_PACK"
printf '[pipeline] output: %s/\n' "$output_dir"

mkdir -p "$output_dir" "$SHIFT_WORKSPACE/runtime"

started_epoch="$(date -u +%s)"
started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

set +e
"$PIPELINE_BIN" "$CAPSTONE_PACK" "$output_dir" 2>&1 |
    tee "$log_file"
pipeline_status="${PIPESTATUS[0]}"
set -e

ended_epoch="$(date -u +%s)"
ended_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
duration=$((ended_epoch - started_epoch))

(( pipeline_status == 0 )) ||
    fail "pipeline exited with status $pipeline_status; see $log_file"

if [[ -s "$output_dir/enriched_events.jsonl" ]]; then
    enriched_file="$output_dir/enriched_events.jsonl"
elif [[ -s "$output_dir/enriched_events.json" ]]; then
    enriched_file="$output_dir/enriched_events.json"
else
    fail "missing enriched_events.jsonl or enriched_events.json"
fi

if [[ -s "$output_dir/timeline.jsonl" ]]; then
    timeline_file="$output_dir/timeline.jsonl"
elif [[ -s "$output_dir/timeline_index.json" ]]; then
    timeline_file="$output_dir/timeline_index.json"
else
    fail "missing timeline.jsonl or timeline_index.json"
fi

[[ -s "$output_dir/source_stats.json" ]] ||
    fail "missing source_stats.json"

jq empty "$output_dir/source_stats.json" 2>/dev/null ||
    fail "source_stats.json is invalid"

nonzero_sources="$(
    jq '[.source_counts[] | select(. > 0)] | length' \
        "$output_dir/source_stats.json"
)"

(( nonzero_sources >= 4 )) ||
    fail "fewer than four source types contain events"

while IFS=$'\t' read -r source count
do
    printf '[pipeline] source %s=%s\n' "$source" "$count"
done < <(
    jq -r '.source_counts | to_entries[] | [.key, .value] | @tsv' \
        "$output_dir/source_stats.json"
)

pipeline_version="$("$PIPELINE_BIN" --version 2>/dev/null || printf 'unknown')"
pipeline_version="${pipeline_version//$'\n'/ }"

events_in="$(jq -r '.events_in // 0' "$output_dir/source_stats.json")"
events_out="$(jq -r '.events_out // 0' "$output_dir/source_stats.json")"
events_dropped="$(jq -r '.events_dropped // 0' "$output_dir/source_stats.json")"

jq -n \
    --arg pipeline_version "$pipeline_version" \
    --arg started_at "$started_at" \
    --arg ended_at "$ended_at" \
    --arg input_pack "$(readlink -f "$CAPSTONE_PACK")" \
    --argjson duration "$duration" \
    --argjson events_in "$events_in" \
    --argjson events_out "$events_out" \
    --argjson events_dropped "$events_dropped" \
    --argjson source_counts "$(
        jq '.source_counts' "$output_dir/source_stats.json"
    )" \
    --argjson dirty_data "$(
        jq '.dirty_data_detected // []' "$output_dir/source_stats.json"
    )" \
    '{
        pipeline_version: $pipeline_version,
        started_at: $started_at,
        ended_at: $ended_at,
        duration_seconds: $duration,
        input_pack: $input_pack,
        events_in: $events_in,
        events_out: $events_out,
        events_dropped: $events_dropped,
        source_counts: $source_counts,
        dirty_data_detected: $dirty_data,
        exit_status: 0
    }' > "$run_file"

printf '[pipeline] duration %ss\n' "$duration"
printf '[pipeline] events_in=%s events_out=%s dropped=%s\n' \
    "$events_in" "$events_out" "$events_dropped"
printf '[pipeline] pipeline_run.json written\n'
