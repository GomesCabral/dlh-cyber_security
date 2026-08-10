#!/bin/bash

# name: 13-consolidated_export.sh
# purpose: Consolidate Windows and Linux telemetry exports, normalize timestamps to UTC ISO 8601, verify required fields, and package attacker ground truth.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 13 - Consolidated Telemetry Export
#
# Inputs:
# - windows_events_export.json
# - linux_events_export.json
# - windows_attack_log.json
# - linux_attack_log.json
#
# Output:
# telemetry_handoff/
#   windows_events.json
#   linux_events.json
#   attack_ground_truth.json
#
# Safety:
# - READ-ONLY with respect to source telemetry.
# - Writes only to telemetry_handoff/.

set -euo pipefail

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1
    pwd -P
)"

WINDOWS_EVENTS="${SCRIPT_DIR}/windows_events_export.json"
LINUX_EVENTS="${SCRIPT_DIR}/linux_events_export.json"
WINDOWS_GROUND_TRUTH="${SCRIPT_DIR}/windows_attack_log.json"
LINUX_GROUND_TRUTH="${SCRIPT_DIR}/linux_attack_log.json"

HANDOFF_DIR="${SCRIPT_DIR}/telemetry_handoff"
WINDOWS_OUTPUT="${HANDOFF_DIR}/windows_events.json"
LINUX_OUTPUT="${HANDOFF_DIR}/linux_events.json"
GROUND_TRUTH_OUTPUT="${HANDOFF_DIR}/attack_ground_truth.json"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

WINDOWS_TMP="${TMP_DIR}/windows_events.json"
LINUX_TMP="${TMP_DIR}/linux_events.json"
GROUND_TRUTH_TMP="${TMP_DIR}/attack_ground_truth.json"

require_command() {
    local command_name="$1"
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        printf '[FAIL] Required command not found: %s\n' "${command_name}"
        exit 1
    fi
}

require_command jq
require_command date
require_command awk
require_command du

for input_file in     "${WINDOWS_EVENTS}"     "${LINUX_EVENTS}"     "${WINDOWS_GROUND_TRUTH}"     "${LINUX_GROUND_TRUTH}"
do
    if [[ ! -f "${input_file}" ]]; then
        printf '[FAIL] Required input file not found: %s\n' "${input_file}"
        exit 1
    fi

    if ! jq empty "${input_file}" >/dev/null 2>&1; then
        printf '[FAIL] Invalid JSON: %s\n' "${input_file}"
        exit 1
    fi
done

event_count() {
    jq '
        if type == "array" then
            length
        elif (.events? | type) == "array" then
            .events | length
        else
            0
        end
    ' "$1"
}

action_count() {
    jq '
        if (.actions? | type) == "array" then
            .actions | length
        else
            0
        end
    ' "$1"
}

human_size() {
    du -h "$1" | awk '{print $1}'
}

normalize_export() {
    local input_file="$1"
    local platform="$2"
    local output_file="$3"

    jq --arg platform "${platform}" '
        def events_array:
            if type == "array" then .
            elif (.events? | type) == "array" then .events
            else []
            end;

        def meta:
            if type == "object" and (.metadata? | type) == "object"
            then .metadata
            else {}
            end;

        def normts:
            if . == null or . == "" then null
            elif test("Z$") then .
            elif test("[+-][0-9]{2}:[0-9]{2}$") then
                (try (fromdateiso8601 | todateiso8601) catch .)
            elif test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?$") then
                . + "Z"
            else
                (try (fromdateiso8601 | todateiso8601) catch .)
            end;

        . as $root
        | {
            metadata:
                (($root | meta) + {
                    platform: $platform,
                    normalized_to_utc: true,
                    normalized_at_utc: (now | todateiso8601)
                }),
            events:
                (
                    $root
                    | events_array
                    | map(
                        .timestamp = (
                            (.timestamp // .Timestamp // .time // .TimeCreated // null)
                            | if . == null then null else normts end
                        )
                        | .hostname = (
                            .hostname // .host // .computer // .Computer // .computer_name // ""
                        )
                        | .source_type = (
                            .source_type // .source // .provider // .log_name // ""
                        )
                        | .event_category = (
                            .event_category // .category // .event_type // .type // ""
                        )
                    )
                )
        }
    ' "${input_file}" > "${output_file}"
}

verify_required_fields() {
    jq -e '
        [
            .events[]
            | select(
                (.timestamp // "") == ""
                or (.hostname // "") == ""
                or (.source_type // "") == ""
                or (.event_category // "") == ""
            )
        ]
        | length == 0
    ' "$1" >/dev/null
}

missing_field_count() {
    jq '
        [
            .events[]
            | select(
                (.timestamp // "") == ""
                or (.hostname // "") == ""
                or (.source_type // "") == ""
                or (.event_category // "") == ""
            )
        ]
        | length
    ' "$1"
}

WINDOWS_COUNT="$(event_count "${WINDOWS_EVENTS}")"
LINUX_COUNT="$(event_count "${LINUX_EVENTS}")"

printf '[*] Loading Windows events (%s)...\n' "${WINDOWS_COUNT}"
printf '[*] Loading Linux events (%s)...\n' "${LINUX_COUNT}"

if [[ "${WINDOWS_COUNT}" -eq 0 || "${LINUX_COUNT}" -eq 0 ]]; then
    printf '[FAIL] One or both telemetry exports contain no events.\n'
    exit 1
fi

printf '[*] Normalizing timestamps to UTC...\n'

normalize_export "${WINDOWS_EVENTS}" "Windows" "${WINDOWS_TMP}"
normalize_export "${LINUX_EVENTS}" "Linux" "${LINUX_TMP}"

WINDOWS_NORMALIZED_COUNT="$(jq '.events | length' "${WINDOWS_TMP}")"
LINUX_NORMALIZED_COUNT="$(jq '.events | length' "${LINUX_TMP}")"

printf '    Windows: %s events normalized\n' "${WINDOWS_NORMALIZED_COUNT}"
printf '    Linux: %s events normalized\n' "${LINUX_NORMALIZED_COUNT}"

printf '[*] Verifying field consistency...\n'

WINDOWS_MISSING="$(missing_field_count "${WINDOWS_TMP}")"
LINUX_MISSING="$(missing_field_count "${LINUX_TMP}")"

if verify_required_fields "${WINDOWS_TMP}" && verify_required_fields "${LINUX_TMP}"; then
    printf '    Required fields present in all events    [OK]\n'
else
    printf '    Required fields present in all events    [FAIL]\n'
    printf '    Windows events missing required fields: %s\n' "${WINDOWS_MISSING}"
    printf '    Linux events missing required fields:   %s\n' "${LINUX_MISSING}"
    exit 1
fi

printf '[*] Combining ground truth...\n'

WINDOWS_ACTIONS="$(action_count "${WINDOWS_GROUND_TRUTH}")"
LINUX_ACTIONS="$(action_count "${LINUX_GROUND_TRUTH}")"
TOTAL_ACTIONS=$((WINDOWS_ACTIONS + LINUX_ACTIONS))

printf '    Windows actions: %s | Linux actions: %s | Total: %s\n'     "${WINDOWS_ACTIONS}" "${LINUX_ACTIONS}" "${TOTAL_ACTIONS}"

jq -n     --slurpfile windows "${WINDOWS_GROUND_TRUTH}"     --slurpfile linux "${LINUX_GROUND_TRUTH}"     '
    def norm_action:
        if (.timestamp // "") == "" then .
        elif (.timestamp | test("Z$")) then .
        elif (.timestamp | test("[+-][0-9]{2}:[0-9]{2}$")) then
            .timestamp = (try (.timestamp | fromdateiso8601 | todateiso8601) catch .timestamp)
        else
            .timestamp = (.timestamp + "Z")
        end;

    {
        metadata: {
            package: "2x02 Eyes on Endpoint - Consolidated Attacker Ground Truth",
            generated_at_utc: (now | todateiso8601),
            platforms: ["Windows", "Linux"],
            windows_actions: ($windows[0].actions | length),
            linux_actions: ($linux[0].actions | length),
            total_actions: (($windows[0].actions | length) + ($linux[0].actions | length))
        },
        windows: {
            metadata: ($windows[0].metadata // {}),
            actions: [
                $windows[0].actions[]
                | norm_action
                | .platform = "Windows"
            ]
        },
        linux: {
            metadata: ($linux[0].metadata // {}),
            actions: [
                $linux[0].actions[]
                | norm_action
                | .platform = "Linux"
            ]
        },
        actions:
            (
                (
                    [
                        $windows[0].actions[]
                        | norm_action
                        | .platform = "Windows"
                    ]
                    +
                    [
                        $linux[0].actions[]
                        | norm_action
                        | .platform = "Linux"
                    ]
                )
                | sort_by(.timestamp)
            )
    }
    ' > "${GROUND_TRUTH_TMP}"

if ! jq empty "${GROUND_TRUTH_TMP}" >/dev/null 2>&1; then
    printf '[FAIL] Combined ground truth JSON is invalid.\n'
    exit 1
fi

printf '[*] Building handoff directory...\n'

rm -rf "${HANDOFF_DIR}"
mkdir -p "${HANDOFF_DIR}"

cp "${WINDOWS_TMP}" "${WINDOWS_OUTPUT}"
cp "${LINUX_TMP}" "${LINUX_OUTPUT}"
cp "${GROUND_TRUTH_TMP}" "${GROUND_TRUTH_OUTPUT}"

for output_file in     "${WINDOWS_OUTPUT}"     "${LINUX_OUTPUT}"     "${GROUND_TRUTH_OUTPUT}"
do
    if ! jq empty "${output_file}" >/dev/null 2>&1; then
        printf '[FAIL] Invalid output JSON: %s\n' "${output_file}"
        exit 1
    fi
done

WINDOWS_FINAL_COUNT="$(jq '.events | length' "${WINDOWS_OUTPUT}")"
LINUX_FINAL_COUNT="$(jq '.events | length' "${LINUX_OUTPUT}")"
GROUND_TRUTH_FINAL_COUNT="$(jq '.actions | length' "${GROUND_TRUTH_OUTPUT}")"

WINDOWS_SIZE="$(human_size "${WINDOWS_OUTPUT}")"
LINUX_SIZE="$(human_size "${LINUX_OUTPUT}")"
GROUND_TRUTH_SIZE="$(human_size "${GROUND_TRUTH_OUTPUT}")"

TOTAL_EVENTS=$((WINDOWS_FINAL_COUNT + LINUX_FINAL_COUNT))

printf 'telemetry_handoff/\n'
printf '  windows_events.json      (%s events, %s)\n' "${WINDOWS_FINAL_COUNT}" "${WINDOWS_SIZE}"
printf '  linux_events.json        (%s events, %s)\n' "${LINUX_FINAL_COUNT}" "${LINUX_SIZE}"
printf '  attack_ground_truth.json (%s actions, %s)\n' "${GROUND_TRUTH_FINAL_COUNT}" "${GROUND_TRUTH_SIZE}"
printf 'Total: %s events across 2 platforms\n' "${TOTAL_EVENTS}"

exit 0