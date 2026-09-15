#!/bin/bash

# Assemble the auditable MedDefense cross-platform tool evaluation package.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${TOOL_EVALUATION_DIR:-$SCRIPT_DIR/tool_evaluation}"
ERRORS=0

fail()
{
    printf 'error              : %s\n' "$1" >&2
    ERRORS=$((ERRORS + 1))
}

for tool in jq sha256sum stat find sort
do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool not found on PATH"
done

if [[ $ERRORS -ne 0 ]]; then
    exit 1
fi

FINDINGS=(
    findings/anchor_cli.json
    findings/anchor_export.json
    findings/scenario_a_cli.json
    findings/scenario_a_export.json
    findings/scenario_b_cli.json
    findings/scenario_b_export.json
    findings/scenario_c_cli.json
    findings/scenario_c_export.json
)

RULES=(
    rules/wazuh/001_ssh_brute_force.xml
    rules/wazuh/003_interpreter_abuse.xml
    rules/wazuh/010_credential_theft_chain.xml
    rules/wazuh/translation_report.json
)

QUESTIONS=(
    comparison/questions/q1.yml
    comparison/questions/q2.yml
    comparison/questions/q3.yml
    comparison/questions/q4.yml
)

COMPARISON=(
    comparison/query_comparison.json
    comparison/tradeoff_table.json
    comparison/tradeoff_table.md
    comparison/workflow_comparison.json
)

DOCUMENTS=(
    playbook/tool_agnostic_playbook.md
    brief/vendor_brief.md
    workspace/workspace_init.json
)

RUNTIME=(
    0-tool_check.sh
    1-wazuh_container.sh
    2-cli_anchor.sh
    3-export_anchor.sh
    4-cli_scenario_a.sh
    5-cli_scenario_b.sh
    6-cli_scenario_c.sh
    7-export_scenario_a.sh
    8-export_scenario_b.sh
    9-export_scenario_c.sh
)

for task_number in 10 11
do
    mapfile -t task_matches < <(
        find "$SCRIPT_DIR" -maxdepth 1 -type f \
            -name "${task_number}-*.sh" -printf '%f\n' | sort
    )
    if [[ ${#task_matches[@]} -ne 1 ]]; then
        fail "expected one ${task_number}-*.sh runtime script; found ${#task_matches[@]}"
    else
        RUNTIME+=("${task_matches[0]}")
    fi
done

RUNTIME+=(
    12-tradeoff_analysis.sh
    13-workflow_comparison.sh
)

ALL_REQUIRED=(
    "${FINDINGS[@]}"
    "${RULES[@]}"
    "${QUESTIONS[@]}"
    "${COMPARISON[@]}"
    "${DOCUMENTS[@]}"
    "${RUNTIME[@]}"
)

for relative_path in "${ALL_REQUIRED[@]}"
do
    if [[ ! -s "$SCRIPT_DIR/$relative_path" ]]; then
        fail "missing or empty required file: $relative_path"
    fi
done

if [[ ${#RUNTIME[@]} -ne 14 ]]; then
    fail "expected 14 runtime scripts, found ${#RUNTIME[@]}"
fi

if [[ ${#ALL_REQUIRED[@]} -ne 37 ]]; then
    fail "internal layout error: expected 37 source files, found ${#ALL_REQUIRED[@]}"
fi

if [[ $ERRORS -ne 0 ]]; then
    printf 'package assembly   : aborted (%s error(s))\n' "$ERRORS" >&2
    exit 1
fi

STAGING_PARENT="$(mktemp -d "$SCRIPT_DIR/.tool_evaluation.XXXXXX")"
STAGING_DIR="$STAGING_PARENT/tool_evaluation"
PREVIOUS_DIR="$STAGING_PARENT/previous_tool_evaluation"

cleanup()
{
    rm -rf "$STAGING_PARENT"
}
trap cleanup EXIT

mkdir -p \
    "$STAGING_DIR/findings" \
    "$STAGING_DIR/rules/wazuh" \
    "$STAGING_DIR/comparison/questions" \
    "$STAGING_DIR/playbook" \
    "$STAGING_DIR/brief" \
    "$STAGING_DIR/workspace" \
    "$STAGING_DIR/runtime"

copy_group()
{
    local destination="$1"
    shift
    local relative_path

    for relative_path in "$@"
    do
        cp -p "$SCRIPT_DIR/$relative_path" "$destination/"
    done
}

printf 'copying findings   ... %s files\n' "${#FINDINGS[@]}"
copy_group "$STAGING_DIR/findings" "${FINDINGS[@]}"

printf 'copying rules      ... %s files\n' "${#RULES[@]}"
copy_group "$STAGING_DIR/rules/wazuh" "${RULES[@]}"

printf 'copying comparison ... %s files\n' \
    "$((${#QUESTIONS[@]} + ${#COMPARISON[@]}))"
copy_group "$STAGING_DIR/comparison/questions" "${QUESTIONS[@]}"
copy_group "$STAGING_DIR/comparison" "${COMPARISON[@]}"

printf 'copying playbook   ... 1 file\n'
cp -p "$SCRIPT_DIR/playbook/tool_agnostic_playbook.md" \
    "$STAGING_DIR/playbook/"

printf 'copying brief      ... 1 file\n'
cp -p "$SCRIPT_DIR/brief/vendor_brief.md" "$STAGING_DIR/brief/"

printf 'copying workspace  ... 1 file\n'
cp -p "$SCRIPT_DIR/workspace/workspace_init.json" \
    "$STAGING_DIR/workspace/"

printf 'copying runtime    ... %s files\n' "${#RUNTIME[@]}"
copy_group "$STAGING_DIR/runtime" "${RUNTIME[@]}"

MANIFEST_ROWS="$STAGING_PARENT/manifest_rows.ndjson"
: > "$MANIFEST_ROWS"

while IFS= read -r -d '' packaged_file
do
    relative_path="${packaged_file#"$STAGING_DIR/"}"
    size="$(stat -c '%s' "$packaged_file")"
    sha256="$(sha256sum "$packaged_file" | awk '{print $1}')"

    jq -cn \
        --arg path "$relative_path" \
        --argjson size "$size" \
        --arg sha256 "$sha256" \
        '{path: $path, size: $size, sha256: $sha256}' \
        >> "$MANIFEST_ROWS"
done < <(
    find "$STAGING_DIR" -type f ! -name 'MANIFEST.json' -print0 | sort -z
)

jq -s \
    --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" '
    {
        generated_at: $generated_at,
        hash_algorithm: "sha256",
        entry_count: length,
        files: .
    }
' "$MANIFEST_ROWS" > "$STAGING_DIR/MANIFEST.json"

MANIFEST_COUNT="$(jq -r '.entry_count' "$STAGING_DIR/MANIFEST.json")"
if [[ "$MANIFEST_COUNT" -ne 37 ]]; then
    printf 'error              : manifest has %s entries; expected 37\n' \
        "$MANIFEST_COUNT" >&2
    exit 1
fi

while IFS=$'\t' read -r relative_path expected_size expected_hash
do
    packaged_file="$STAGING_DIR/$relative_path"
    [[ -s "$packaged_file" ]] || {
        printf 'error              : manifest file missing: %s\n' \
            "$relative_path" >&2
        exit 1
    }

    actual_size="$(stat -c '%s' "$packaged_file")"
    actual_hash="$(sha256sum "$packaged_file" | awk '{print $1}')"

    if [[ "$actual_size" != "$expected_size" \
        || "$actual_hash" != "$expected_hash" ]]; then
        printf 'error              : integrity mismatch: %s\n' \
            "$relative_path" >&2
        exit 1
    fi
done < <(
    jq -r '.files[] | [.path, .size, .sha256] | @tsv' \
        "$STAGING_DIR/MANIFEST.json"
)

if [[ -e "$OUTPUT_DIR" && ! -d "$OUTPUT_DIR" ]]; then
    printf 'error              : output exists and is not a directory: %s\n' \
        "$OUTPUT_DIR" >&2
    exit 1
fi

if [[ -d "$OUTPUT_DIR" ]]; then
    mv "$OUTPUT_DIR" "$PREVIOUS_DIR"
fi

if ! mv "$STAGING_DIR" "$OUTPUT_DIR"; then
    if [[ -d "$PREVIOUS_DIR" ]]; then
        mv "$PREVIOUS_DIR" "$OUTPUT_DIR"
    fi
    printf 'error              : failed to install completed package\n' >&2
    exit 1
fi

printf 'MANIFEST.json      : %s entries\n' "$MANIFEST_COUNT"
printf 'sanity check       : ok\n'
printf 'tool_evaluation/ ready\n'

