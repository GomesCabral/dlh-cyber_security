#!/bin/bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"
readonly SUMMARY_FILE="${BASELINE_SUMMARY:-${SCRIPT_DIR}/baseline_summary.json}"
readonly LABELED_FILE="${LABELED_EVENTS:-${SCRIPT_DIR}/labeled_events.json}"
readonly AUTH_SCRIPT="${AUTH_ANOMALY_SCRIPT:-${SCRIPT_DIR}/10-anomalies_auth.sh}"
readonly PROCESS_SCRIPT="${PROCESS_ANOMALY_SCRIPT:-${SCRIPT_DIR}/11-anomalies_process.sh}"
readonly NETWORK_SCRIPT="${NETWORK_ANOMALY_SCRIPT:-${SCRIPT_DIR}/12-anomalies_network.sh}"
readonly AUTH_OUTPUT="${SCRIPT_DIR}/anomalies_auth.json"
readonly PROCESS_OUTPUT="${SCRIPT_DIR}/anomalies_process.json"
readonly NETWORK_OUTPUT="${SCRIPT_DIR}/anomalies_network.json"
readonly OUTPUT_FILE="${SCRIPT_DIR}/baseline_validation.json"
readonly SELF_THRESHOLD="${SELF_CHECK_THRESHOLD:-5}"
readonly MIN_RATIO="${MIN_SIGNAL_TO_NOISE_RATIO:-3.0}"

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 2
}

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
[[ -d "$HANDOFF_DIR" ]] || die "handoff directory is not accessible: $HANDOFF_DIR"
[[ -r "$SUMMARY_FILE" ]] || die "baseline summary is not readable: $SUMMARY_FILE"
[[ -r "$LABELED_FILE" ]] || die "labeled dataset is not readable: $LABELED_FILE"
[[ -r "$AUTH_SCRIPT" ]] || die "authentication anomaly script is not readable: $AUTH_SCRIPT"
[[ -r "$PROCESS_SCRIPT" ]] || die "process anomaly script is not readable: $PROCESS_SCRIPT"
[[ "$SELF_THRESHOLD" =~ ^[0-9]+$ ]] || die "SELF_CHECK_THRESHOLD must be a non-negative integer"
[[ "$MIN_RATIO" =~ ^[0-9]+([.][0-9]+)?$ ]] ||
    die "MIN_SIGNAL_TO_NOISE_RATIO must be a non-negative number"

self_summary_tmp=$(mktemp "${SCRIPT_DIR}/.self_summary.XXXXXX")
validation_tmp=$(mktemp "${SCRIPT_DIR}/.baseline_validation.XXXXXX")
auth_events_tmp=$(mktemp "${SCRIPT_DIR}/.validation_auth_events.XXXXXX")
process_events_tmp=$(mktemp "${SCRIPT_DIR}/.validation_process_events.XXXXXX")
cleanup() {
    rm -f -- \
        "$self_summary_tmp" "$validation_tmp" \
        "$auth_events_tmp" "$process_events_tmp"
}
trap cleanup EXIT

# Create small detector-specific streams. The source dataset can exceed 400 MB;
# retaining complete records would make the self-check vulnerable to the OOM
# killer. event_ref preserves the original NDJSON line reference.
python3 -W error - \
    "$LABELED_FILE" "$auth_events_tmp" "$process_events_tmp" <<'PY'
import json
import pathlib
import sys


AUTH_LABELS = {
    "login_success", "login_failure", "logout", "account_lockout",
    "privilege_escalation",
}
PROCESS_LABELS = {"process_start", "child_process_spawn"}
COMMON_FIELDS = (
    "timestamp", "hostname", "host", "user", "src_ip", "source_ip",
    "canonical_label", "source_type", "event_id", "event_ref", "event_uuid",
    "id", "asset_criticality", "asset",
)
PROCESS_FIELDS = ("process_name", "parent_process_name")
DETAIL_FIELDS = (
    "Image", "NewProcessName", "ProcessName", "process_name", "exe", "comm",
    "ParentImage", "ParentProcessName", "parent_process_name", "parent_comm",
)


def compact(event: dict, line_number: int, process: bool = False) -> dict:
    result = {key: event[key] for key in COMMON_FIELDS if key in event}
    if process:
        result.update({key: event[key] for key in PROCESS_FIELDS if key in event})
        details = event.get("details")
        if isinstance(details, dict):
            selected = {key: details[key] for key in DETAIL_FIELDS if key in details}
            if selected:
                result["details"] = selected
    if not any(result.get(key) not in (None, "") for key in
               ("event_ref", "event_uuid", "id")):
        source = event.get("source_type", "unknown")
        event_id = event.get("event_id", "na")
        result["event_ref"] = f"{source}:{event_id}:line:{line_number}"
    return result


source_path, auth_path, process_path = map(pathlib.Path, sys.argv[1:4])
with (
    source_path.open("r", encoding="utf-8") as source,
    auth_path.open("w", encoding="utf-8", newline="\n") as auth_output,
    process_path.open("w", encoding="utf-8", newline="\n") as process_output,
):
    for line_number, line in enumerate(source, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"invalid labeled-events NDJSON on line {line_number}: {error}"
            ) from error
        if not isinstance(event, dict):
            raise ValueError(f"labeled-events line {line_number} is not an object")
        label = event.get("canonical_label")
        if label in AUTH_LABELS:
            json.dump(compact(event, line_number), auth_output, separators=(",", ":"))
            auth_output.write("\n")
        if label in PROCESS_LABELS:
            json.dump(
                compact(event, line_number, process=True),
                process_output,
                separators=(",", ":"),
            )
            process_output.write("\n")
PY

jq '
    .baseline_window as $baseline
    | .evaluation_window = {
        "start": $baseline.start,
        "end": $baseline.end,
        "end_exclusive": true,
        "duration_hours": ($baseline.duration_days * 24)
      }
' "$SUMMARY_FILE" >"$self_summary_tmp"

run_detector() {
    local script=$1
    local summary=$2
    local events=$3
    local generated_output=$4
    local captured_output=$5

    BASELINE_SUMMARY="$summary" LABELED_EVENTS="$events" bash "$script" >/dev/null
    [[ -r "$generated_output" ]] || die "detector did not produce: $generated_output"
    jq -e 'type == "array"' "$generated_output" >/dev/null ||
        die "detector output is not a JSON array: $generated_output"
    cp -f -- "$generated_output" "$captured_output"
}

run_detector "$AUTH_SCRIPT" "$self_summary_tmp" "$auth_events_tmp" "$AUTH_OUTPUT" \
    "${SCRIPT_DIR}/self_check_auth.json"
run_detector "$PROCESS_SCRIPT" "$self_summary_tmp" "$process_events_tmp" "$PROCESS_OUTPUT" \
    "${SCRIPT_DIR}/self_check_process.json"

network_status="executed"
if [[ -r "$NETWORK_SCRIPT" ]]; then
    run_detector "$NETWORK_SCRIPT" "$self_summary_tmp" "$LABELED_FILE" "$NETWORK_OUTPUT" \
        "${SCRIPT_DIR}/self_check_network.json"
else
    network_status="placeholder_task_12_not_provided"
    printf '[]\n' >"${SCRIPT_DIR}/self_check_network.json"
fi

run_detector "$AUTH_SCRIPT" "$SUMMARY_FILE" "$auth_events_tmp" "$AUTH_OUTPUT" \
    "${SCRIPT_DIR}/live_check_auth.json"
run_detector "$PROCESS_SCRIPT" "$SUMMARY_FILE" "$process_events_tmp" "$PROCESS_OUTPUT" \
    "${SCRIPT_DIR}/live_check_process.json"

if [[ -r "$NETWORK_SCRIPT" ]]; then
    run_detector "$NETWORK_SCRIPT" "$SUMMARY_FILE" "$LABELED_FILE" "$NETWORK_OUTPUT" \
        "${SCRIPT_DIR}/live_check_network.json"
else
    printf '[]\n' >"${SCRIPT_DIR}/live_check_network.json"
    printf '[]\n' >"$NETWORK_OUTPUT"
fi

python3 -W error - \
    "${SCRIPT_DIR}/self_check_auth.json" \
    "${SCRIPT_DIR}/self_check_process.json" \
    "${SCRIPT_DIR}/self_check_network.json" \
    "${SCRIPT_DIR}/live_check_auth.json" \
    "${SCRIPT_DIR}/live_check_process.json" \
    "${SCRIPT_DIR}/live_check_network.json" \
    "$validation_tmp" "$SELF_THRESHOLD" "$MIN_RATIO" "$network_status" <<'PY'
import collections
import json
import pathlib
import sys


def concise_error(error_type, error, traceback):
    del error_type, traceback
    print(f"Error: {error}", file=sys.stderr)


sys.excepthook = concise_error


def load_array(path: pathlib.Path) -> list[dict]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            items = json.load(stream)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise ValueError(f"{path} must contain an array of objects")
    return items


def breakdown(items: list[dict]) -> dict[str, int]:
    counts = collections.Counter()
    for item in items:
        anomaly_type = item.get("anomaly_type")
        if anomaly_type in (None, ""):
            raise ValueError("every anomaly must contain anomaly_type")
        counts[str(anomaly_type)] += 1
    return {name: counts[name] for name in sorted(counts)}


paths = [pathlib.Path(value) for value in sys.argv[1:7]]
output_path = pathlib.Path(sys.argv[7])
self_threshold = int(sys.argv[8])
minimum_ratio = float(sys.argv[9])
network_status = sys.argv[10]

self_documents = {
    "auth": load_array(paths[0]),
    "process": load_array(paths[1]),
    "network": load_array(paths[2]),
}
live_documents = {
    "auth": load_array(paths[3]),
    "process": load_array(paths[4]),
    "network": load_array(paths[5]),
}
self_items = [item for document in self_documents.values() for item in document]
live_items = [item for document in live_documents.values() for item in document]
self_total = len(self_items)
live_total = len(live_items)
ratio = live_total / max(self_total, 1)
verdict = (
    "pass"
    if self_total < self_threshold and ratio >= minimum_ratio
    else "fail"
)

result = {
    "self_check_total": self_total,
    "live_check_total": live_total,
    "signal_to_noise_ratio": round(ratio, 6),
    "self_check_breakdown": breakdown(self_items),
    "live_check_breakdown": breakdown(live_items),
    "per_source": {
        "self_check": {
            source: len(document) for source, document in self_documents.items()
        },
        "live_check": {
            source: len(document) for source, document in live_documents.items()
        },
    },
    "thresholds": {
        "acceptable_self_check_exclusive_max": self_threshold,
        "minimum_signal_to_noise_ratio": minimum_ratio,
    },
    "detector_status": {
        "auth": "executed",
        "process": "executed",
        "network": network_status,
    },
    "verdict": verdict,
}

with output_path.open("w", encoding="utf-8", newline="\n") as output:
    json.dump(result, output, indent=2)
    output.write("\n")

print(f"self-check anomalies (baseline window): {self_total}")
print(f"live-check anomalies (evaluation win ): {live_total}")
print(f"signal-to-noise ratio                : {ratio:.2f}")
print(f"verdict                              : {verdict}")
PY

mv -f -- "$validation_tmp" "$OUTPUT_FILE"
chmod 0644 \
    "$OUTPUT_FILE" \
    "${SCRIPT_DIR}"/self_check_*.json \
    "${SCRIPT_DIR}"/live_check_*.json
printf 'baseline_validation.json written\n'

if jq -e '.verdict == "pass"' "$OUTPUT_FILE" >/dev/null; then
    exit 0
fi
exit 1

