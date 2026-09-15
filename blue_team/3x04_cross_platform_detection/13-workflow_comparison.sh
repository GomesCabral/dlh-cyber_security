#!/bin/bash

# Aggregate cross-platform SOC workflow metrics from structured findings.

set -u

FINDINGS_DIR="${FINDINGS_DIR:-findings}"
COMPARISON_DIR="${COMPARISON_DIR:-comparison}"
OUTPUT_FILE="$COMPARISON_DIR/workflow_comparison.json"
ERRORS=0

fail()
{
    printf 'error                  : %s\n' "$1" >&2
    ERRORS=$((ERRORS + 1))
}

command -v jq >/dev/null 2>&1 || {
    printf 'error                  : jq not found on PATH\n' >&2
    exit 1
}

if [[ ! -d "$FINDINGS_DIR" ]]; then
    printf 'error                  : findings directory not found: %s\n' \
        "$FINDINGS_DIR" >&2
    exit 1
fi

mapfile -t FINDING_FILES < <(
    find "$FINDINGS_DIR" -maxdepth 1 -type f -name '*.json' | sort
)

if [[ ${#FINDING_FILES[@]} -eq 0 ]]; then
    printf 'error                  : no JSON findings found in %s\n' \
        "$FINDINGS_DIR" >&2
    exit 1
fi

for file in "${FINDING_FILES[@]}"
do
    if ! jq -e '
        (.scenario_id | IN("anchor", "scenario_a", "scenario_b", "scenario_c"))
        and (.interface | IN("cli", "wazuh_export"))
        and (.time_to_first_answer_seconds | type == "number")
        and (.time_to_first_answer_seconds >= 0)
        and (.actions | type == "array")
        and (.fields_touched | type == "array")
        and (.event_refs | type == "array")
        and (.confidence | IN("low", "medium", "high"))
    ' "$file" >/dev/null 2>&1; then
        fail "invalid workflow fields in $file"
    fi
done

if [[ $ERRORS -ne 0 ]]; then
    exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
ALL_FINDINGS="$TMP_DIR/all_findings.json"
TMP_OUTPUT="$TMP_DIR/workflow_comparison.json"

jq -s '.' "${FINDING_FILES[@]}" > "$ALL_FINDINGS"

CLI_COUNT="$(jq '[.[] | select(.interface == "cli")] | length' \
    "$ALL_FINDINGS")"
EXPORT_COUNT="$(jq '[.[] | select(.interface == "wazuh_export")] | length' \
    "$ALL_FINDINGS")"

[[ "$CLI_COUNT" -eq 4 ]] || \
    fail "expected 4 CLI findings, found $CLI_COUNT"
[[ "$EXPORT_COUNT" -eq 4 ]] || \
    fail "expected 4 Wazuh export findings, found $EXPORT_COUNT"

for scenario in anchor scenario_a scenario_b scenario_c
do
    cli_pair_count="$(jq --arg scenario "$scenario" '
        [.[] | select(
            .scenario_id == $scenario and .interface == "cli"
        )] | length
    ' "$ALL_FINDINGS")"
    export_pair_count="$(jq --arg scenario "$scenario" '
        [.[] | select(
            .scenario_id == $scenario and .interface == "wazuh_export"
        )] | length
    ' "$ALL_FINDINGS")"

    [[ "$cli_pair_count" -eq 1 ]] || \
        fail "$scenario requires one CLI finding (found $cli_pair_count)"
    [[ "$export_pair_count" -eq 1 ]] || \
        fail "$scenario requires one Wazuh export finding (found $export_pair_count)"
done

if [[ $ERRORS -ne 0 ]]; then
    exit 1
fi

jq -n \
    --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --slurpfile loaded_findings "$ALL_FINDINGS" '
    ($loaded_findings[0]) as $findings
    |
    def rounded:
        ((. * 100) | round) / 100;

    def median:
        sort as $values
        | ($values | length) as $count
        | if $count == 0 then null
          elif ($count % 2) == 1 then $values[($count / 2 | floor)]
          else (($values[($count / 2) - 1] + $values[$count / 2]) / 2)
          end;

    def metric_summary($values):
        {
            total: ($values | add),
            average: (($values | add) / ($values | length) | rounded),
            median: ($values | median)
        };

    def interface_summary($name):
        [$findings[] | select(.interface == $name)] as $selected
        | {
            finding_count: ($selected | length),
            time_to_first_answer_seconds: metric_summary(
                [$selected[] | .time_to_first_answer_seconds]
            ),
            action_count: metric_summary(
                [$selected[] | (.actions | length)]
            ),
            fields_touched_count: metric_summary(
                [$selected[] | (.fields_touched | length)]
            ),
            event_refs_count: metric_summary(
                [$selected[] | (.event_refs | length)]
            )
        };

    def confidence_for($name):
        [$findings[] | select(.interface == $name)] as $selected
        | {
            low: ([$selected[] | select(.confidence == "low")] | length),
            medium: ([$selected[] | select(.confidence == "medium")] | length),
            high: ([$selected[] | select(.confidence == "high")] | length)
        };

    def faster($delta):
        if $delta < 0 then "wazuh_export"
        elif $delta > 0 then "cli"
        else "tie"
        end;

    def scenario_comparison($scenario):
        ($findings[] | select(
            .scenario_id == $scenario and .interface == "cli"
        )) as $cli
        | ($findings[] | select(
            .scenario_id == $scenario and .interface == "wazuh_export"
        )) as $export
        | ($export.time_to_first_answer_seconds
            - $cli.time_to_first_answer_seconds) as $time_delta
        | (($export.actions | length)
            - ($cli.actions | length)) as $action_delta
        | (($export.fields_touched | length)
            - ($cli.fields_touched | length)) as $fields_delta
        | (($export.event_refs | length)
            - ($cli.event_refs | length)) as $refs_delta
        | {
            scenario_id: $scenario,
            cli: {
                time_to_first_answer_seconds:
                    $cli.time_to_first_answer_seconds,
                action_count: ($cli.actions | length),
                fields_touched_count: ($cli.fields_touched | length),
                event_refs_count: ($cli.event_refs | length)
            },
            wazuh_export: {
                time_to_first_answer_seconds:
                    $export.time_to_first_answer_seconds,
                action_count: ($export.actions | length),
                fields_touched_count: ($export.fields_touched | length),
                event_refs_count: ($export.event_refs | length)
            },
            deltas: {
                time_to_first_answer_seconds: $time_delta,
                action_count: $action_delta,
                fields_touched_count: $fields_delta,
                event_refs_count: $refs_delta
            },
            faster_interface: faster($time_delta)
        };

    {
        per_interface: {
            cli: interface_summary("cli"),
            wazuh_export: interface_summary("wazuh_export")
        },
        per_scenario: ([
            "anchor",
            "scenario_a",
            "scenario_b",
            "scenario_c"
        ] | map(scenario_comparison(.))),
        confidence_distribution: {
            cli: confidence_for("cli"),
            wazuh_export: confidence_for("wazuh_export")
        },
        generated_at: $generated_at
    }
' > "$TMP_OUTPUT"

if ! jq -e '
    (.per_interface.cli.finding_count == 4)
    and (.per_interface.wazuh_export.finding_count == 4)
    and (.per_scenario | length == 4)
' "$TMP_OUTPUT" >/dev/null; then
    printf 'error                  : generated comparison failed validation\n' >&2
    exit 1
fi

mkdir -p "$COMPARISON_DIR"
mv "$TMP_OUTPUT" "$OUTPUT_FILE"

CLI_TOTAL="$(jq -r \
    '.per_interface.cli.time_to_first_answer_seconds.total' "$OUTPUT_FILE")"
CLI_AVG="$(jq -r \
    '.per_interface.cli.time_to_first_answer_seconds.average' "$OUTPUT_FILE")"
CLI_MEDIAN="$(jq -r \
    '.per_interface.cli.time_to_first_answer_seconds.median' "$OUTPUT_FILE")"
CLI_ACTIONS="$(jq -r '.per_interface.cli.action_count.total' "$OUTPUT_FILE")"

EXPORT_TOTAL="$(jq -r \
    '.per_interface.wazuh_export.time_to_first_answer_seconds.total' \
    "$OUTPUT_FILE")"
EXPORT_AVG="$(jq -r \
    '.per_interface.wazuh_export.time_to_first_answer_seconds.average' \
    "$OUTPUT_FILE")"
EXPORT_MEDIAN="$(jq -r \
    '.per_interface.wazuh_export.time_to_first_answer_seconds.median' \
    "$OUTPUT_FILE")"
EXPORT_ACTIONS="$(jq -r \
    '.per_interface.wazuh_export.action_count.total' "$OUTPUT_FILE")"

printf 'findings loaded       : %s (%s cli + %s wazuh_export)\n' \
    "${#FINDING_FILES[@]}" "$CLI_COUNT" "$EXPORT_COUNT"
printf 'per interface totals:\n'
printf '  %-15s: %ss total, avg %ss, median %ss, %s actions\n' \
    'cli' "$CLI_TOTAL" "$CLI_AVG" "$CLI_MEDIAN" "$CLI_ACTIONS"
printf '  %-15s: %ss total, avg %ss, median %ss, %s actions\n' \
    'wazuh_export' "$EXPORT_TOTAL" "$EXPORT_AVG" "$EXPORT_MEDIAN" \
    "$EXPORT_ACTIONS"

printf 'per interface confidence:\n'
for interface in cli wazuh_export
do
    high="$(jq -r --arg interface "$interface" \
        '.confidence_distribution[$interface].high' "$OUTPUT_FILE")"
    medium="$(jq -r --arg interface "$interface" \
        '.confidence_distribution[$interface].medium' "$OUTPUT_FILE")"
    low="$(jq -r --arg interface "$interface" \
        '.confidence_distribution[$interface].low' "$OUTPUT_FILE")"
    printf '  %-15s: high=%s medium=%s low=%s\n' \
        "$interface" "$high" "$medium" "$low"
done

printf 'per scenario deltas (wazuh_export - cli):\n'
jq -r '
    .per_scenario[]
    | .deltas.time_to_first_answer_seconds as $delta
    | if $delta < 0 then
        "  \(.scenario_id)\t: \($delta)s (wazuh_export faster)"
      elif $delta > 0 then
        "  \(.scenario_id)\t: +\($delta)s (cli faster)"
      else
        "  \(.scenario_id)\t: 0s (tie)"
      end
' "$OUTPUT_FILE" | expand -t 18

printf '%s written\n' "$OUTPUT_FILE"

