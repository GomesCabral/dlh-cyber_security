#!/bin/bash

set -Eeuo pipefail

fail() {
    printf '[baseline] ERROR: %s\n' "$*" >&2
    exit 1
}

pipeline_run="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
baseline_file="$SHIFT_WORKSPACE/enriched/baseline.json"
runtime_file="$SHIFT_WORKSPACE/runtime/baseline_run.json"

[[ -s "$pipeline_run" ]] ||
    fail "pipeline_run.json missing"

[[ "$(jq -r '.exit_status // -1' "$pipeline_run")" == "0" ]] ||
    fail "pipeline did not complete successfully"

printf '[baseline] pipeline check: OK\n'

if [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" ]]; then
    input_file="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
elif [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.json" ]]; then
    input_file="$SHIFT_WORKSPACE/enriched/enriched_events.json"
else
    fail "enriched events file missing"
fi

printf '[baseline] invoking %s\n' "$BASELINE_BIN"
printf '[baseline] input: %s\n' "$input_file"
printf '[baseline] output: %s\n' "$baseline_file"

started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

"$BASELINE_BIN" "$input_file" "$baseline_file" ||
    fail "baseline process failed"

ended_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

[[ -s "$baseline_file" ]] ||
    fail "baseline.json missing or empty"

hosts_total="$(jq '.hosts | length' "$baseline_file")"

(( hosts_total > 0 )) ||
    fail "hosts_total is zero"

hosts_with_deviations="$(
    jq '[.hosts[] | select(.deviation_count > 0)] | length' \
        "$baseline_file"
)"

markers="$(
    jq '.deviation_markers | length' "$baseline_file"
)"

hot_hosts_json="$(
    jq '
        .hosts
        | sort_by(.deviation_score)
        | reverse
        | .[0:5]
        | map(.host)
    ' "$baseline_file"
)"

printf '[baseline] hosts processed: %s\n' "$hosts_total"
printf '[baseline] hosts with deviations: %s\n' \
    "$hosts_with_deviations"

jq -r '
    .hosts
    | sort_by(.deviation_score)
    | reverse
    | .[0:5]
    | .[]
    | "[baseline] hot host: \(.host) score=\(.deviation_score) markers=\(.deviation_count)"
' "$baseline_file"

printf '[baseline] markers: %s total\n' "$markers"

baseline_version="$(
    "$BASELINE_BIN" --version 2>/dev/null || printf 'unknown'
)"

jq \
    --arg baseline_version "$baseline_version" \
    --argjson hosts_total "$hosts_total" \
    --argjson hosts_with_deviations "$hosts_with_deviations" \
    --arg started_at "$started_at" \
    --arg ended_at "$ended_at" \
    '{
        baseline_version: $baseline_version,
        hosts_total: $hosts_total,
        hosts_with_deviations: $hosts_with_deviations,
        deviation_markers: .deviation_markers,
        hot_hosts: (
            .hosts
            | sort_by(.deviation_score)
            | reverse
            | .[0:5]
            | map(.host)
        ),
        started_at: $started_at,
        ended_at: $ended_at,
        exit_status: 0
    }' "$baseline_file" > "$runtime_file"

printf '[baseline] baseline_run.json written\n'

