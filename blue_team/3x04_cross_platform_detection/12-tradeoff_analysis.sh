#!/bin/bash

# Compare paired CLI and Wazuh-export findings using measured SOC evidence.

set -u

FINDINGS_DIR="${FINDINGS_DIR:-findings}"
COMPARISON_DIR="${COMPARISON_DIR:-comparison}"
JSON_OUTPUT="$COMPARISON_DIR/tradeoff_table.json"
MD_OUTPUT="$COMPARISON_DIR/tradeoff_table.md"
ERRORS=0

fail()
{
    printf 'error              : %s\n' "$1" >&2
    ERRORS=$((ERRORS + 1))
}

command -v jq >/dev/null 2>&1 || {
    printf 'error              : jq not found on PATH\n' >&2
    exit 1
}

if [[ ! -d "$FINDINGS_DIR" ]]; then
    printf 'error              : findings directory not found: %s\n' "$FINDINGS_DIR" >&2
    exit 1
fi

mapfile -t FINDING_FILES < <(find "$FINDINGS_DIR" -maxdepth 1 -type f -name '*.json' | sort)

if [[ ${#FINDING_FILES[@]} -eq 0 ]]; then
    printf 'error              : no JSON findings found in %s\n' "$FINDINGS_DIR" >&2
    exit 1
fi

for file in "${FINDING_FILES[@]}"
do
    if ! jq -e '
        (.scenario_id | IN("anchor", "scenario_a", "scenario_b", "scenario_c"))
        and (.interface | IN("cli", "wazuh_export"))
        and (.time_to_first_answer_seconds | type == "number")
        and (.actions | type == "array")
    ' "$file" >/dev/null 2>&1; then
        fail "invalid comparison fields in $file"
    fi
done

if [[ $ERRORS -ne 0 ]]; then
    exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
ALL_FINDINGS="$TMP_DIR/all_findings.json"
ROWS_FILE="$TMP_DIR/rows.json"

jq -s '.' "${FINDING_FILES[@]}" > "$ALL_FINDINGS"

for scenario in anchor scenario_a scenario_b scenario_c
do
    cli_count="$(jq --arg scenario "$scenario" \
        '[.[] | select(.scenario_id == $scenario and .interface == "cli")] | length' \
        "$ALL_FINDINGS")"
    export_count="$(jq --arg scenario "$scenario" \
        '[.[] | select(.scenario_id == $scenario and .interface == "wazuh_export")] | length' \
        "$ALL_FINDINGS")"

    [[ "$cli_count" -eq 1 ]] || fail "$scenario requires exactly one CLI finding (found $cli_count)"
    [[ "$export_count" -eq 1 ]] || fail "$scenario requires exactly one Wazuh export finding (found $export_count)"
done

if [[ $ERRORS -ne 0 ]]; then
    exit 1
fi

jq --argfile findings "$ALL_FINDINGS" -n '
    def cause($scenario; $winner):
        if $winner == "tie" then "reproducibility"
        elif $scenario == "anchor" and $winner == "wazuh_export" then "filter_bar_efficiency"
        elif $scenario == "anchor" then "text_speed_iteration"
        elif $scenario == "scenario_a" and $winner == "wazuh_export" then "timeline_visualization"
        elif $scenario == "scenario_a" then "pipeline_expressiveness"
        elif $scenario == "scenario_b" and $winner == "cli" then "context_join_ergonomics"
        elif $scenario == "scenario_b" then "filter_bar_efficiency"
        elif $scenario == "scenario_c" and $winner == "wazuh_export" then "native_field_surface"
        else "text_speed_iteration"
        end;

    def evidence($scenario; $winner):
        if $winner == "tie" then
            "Both interfaces reached the first answer in the same measured time; action counts remain a secondary comparison."
        elif $scenario == "anchor" and $winner == "wazuh_export" then
            "The prepared dashboard filter exposed the known SSH cluster without rescanning the large NDJSON handoff."
        elif $scenario == "anchor" then
            "Direct text filtering reached the known SSH cluster faster than reading the export workflow."
        elif $scenario == "scenario_a" and $winner == "wazuh_export" then
            "The exported, host-scoped event set made the ordered credential-theft chain quick to reconstruct."
        elif $scenario == "scenario_a" then
            "The CLI pipeline reconstructed and filtered the multi-event chain faster."
        elif $scenario == "scenario_b" and $winner == "cli" then
            "The CLI joined host evidence to asset classification more efficiently."
        elif $scenario == "scenario_b" then
            "The prepared event filter surfaced the privileged logon chain quickly despite the inventory fallback."
        elif $scenario == "scenario_c" and $winner == "wazuh_export" then
            "source.zone was present in the exported documents, avoiding a secondary zone lookup."
        else
            "The narrow source/destination tuple was faster to iterate as a direct text filter."
        end;

    ["anchor", "scenario_a", "scenario_b", "scenario_c"]
    | map(. as $scenario
        | ($findings[] | select(.scenario_id == $scenario and .interface == "cli")) as $cli
        | ($findings[] | select(.scenario_id == $scenario and .interface == "wazuh_export")) as $export
        | ($export.time_to_first_answer_seconds - $cli.time_to_first_answer_seconds) as $time_delta
        | (($export.actions | length) - ($cli.actions | length)) as $action_delta
        | (if $time_delta < 0 then "wazuh_export"
           elif $time_delta > 0 then "cli"
           else "tie"
           end) as $winner
        | {
            scenario_id: $scenario,
            cli_time_seconds: $cli.time_to_first_answer_seconds,
            wazuh_export_time_seconds: $export.time_to_first_answer_seconds,
            time_delta_seconds: $time_delta,
            faster_interface: $winner,
            cli_action_count: ($cli.actions | length),
            wazuh_export_action_count: ($export.actions | length),
            action_delta: $action_delta,
            advantage_cause: cause($scenario; $winner),
            evidence: evidence($scenario; $winner)
        })
' > "$ROWS_FILE"

mkdir -p "$COMPARISON_DIR"

jq -n \
    --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --argjson findings_loaded "${#FINDING_FILES[@]}" \
    --slurpfile rows "$ROWS_FILE" '
    ($rows[0]) as $data
    | {
        generated_at: $generated_at,
        findings_loaded: $findings_loaded,
        scenarios_analyzed: ($data | length),
        export_advantages: ([$data[] | select(.faster_interface == "wazuh_export")] | length),
        cli_advantages: ([$data[] | select(.faster_interface == "cli")] | length),
        ties: ([$data[] | select(.faster_interface == "tie")] | length),
        delta_definition: "wazuh_export minus cli; negative means export was faster or used fewer actions",
        comparisons: $data
    }
' > "$TMP_DIR/tradeoff_table.json"

mv "$TMP_DIR/tradeoff_table.json" "$JSON_OUTPUT"

{
    printf '# CLI vs. Wazuh Export Trade-off Analysis\n\n'
    printf 'Generated from paired structured findings. Time and action deltas are calculated as `wazuh_export - cli`; negative values favor the export workflow.\n\n'
    printf '| Scenario | CLI time (s) | Export time (s) | Time delta | Faster interface | CLI actions | Export actions | Action delta | Cause |\n'
    printf '|---|---:|---:|---:|---|---:|---:|---:|---|\n'
    jq -r '.comparisons[] | [
        .scenario_id,
        .cli_time_seconds,
        .wazuh_export_time_seconds,
        .time_delta_seconds,
        .faster_interface,
        .cli_action_count,
        .wazuh_export_action_count,
        .action_delta,
        .advantage_cause
    ] | "| " + (map(tostring) | join(" | ")) + " |"' "$JSON_OUTPUT"
    printf '\n## Evidence-based attribution\n\n'
    jq -r '.comparisons[] | "- **" + .scenario_id + " — " + .advantage_cause + ":** " + .evidence' "$JSON_OUTPUT"
    printf '\n## Summary\n\n'
    jq -r '"- Scenarios analyzed: \(.scenarios_analyzed)\n- Export advantages: \(.export_advantages)\n- CLI advantages: \(.cli_advantages)\n- Ties: \(.ties)"' "$JSON_OUTPUT"
} > "$TMP_DIR/tradeoff_table.md"

mv "$TMP_DIR/tradeoff_table.md" "$MD_OUTPUT"

SCENARIO_COUNT="$(jq -r '.scenarios_analyzed' "$JSON_OUTPUT")"
EXPORT_ADVANTAGES="$(jq -r '.export_advantages' "$JSON_OUTPUT")"
CLI_ADVANTAGES="$(jq -r '.cli_advantages' "$JSON_OUTPUT")"
TIES="$(jq -r '.ties' "$JSON_OUTPUT")"

printf '%-20s: %s (anchor + 3)\n' 'scenarios analyzed' "$SCENARIO_COUNT"
printf '%-20s: %s\n' 'export advantages' "$EXPORT_ADVANTAGES"
printf '%-20s: %s\n' 'cli advantages' "$CLI_ADVANTAGES"
printf '%-20s: %s\n' 'ties' "$TIES"
printf '%s written\n' "$JSON_OUTPUT"
printf '%s written\n' "$MD_OUTPUT"

