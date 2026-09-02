#!/bin/bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"
readonly AUTH_FILE="${AUTH_BASELINE:-${SCRIPT_DIR}/baseline_auth.json}"
readonly PROCESS_FILE="${PROCESS_BASELINE:-${SCRIPT_DIR}/baseline_process.json}"
readonly NETWORK_FILE="${NETWORK_BASELINE:-${SCRIPT_DIR}/baseline_network.json}"
readonly FILE_BASELINE_FILE="${FILE_BASELINE:-${SCRIPT_DIR}/baseline_file.json}"
readonly TEMPORAL_FILE="${TEMPORAL_PROFILE:-${SCRIPT_DIR}/temporal_profile.json}"
readonly OUTPUT_FILE="${SCRIPT_DIR}/baseline_summary.json"

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || die "python3 is required"
[[ -d "$HANDOFF_DIR" ]] || die "handoff directory is not accessible: $HANDOFF_DIR"

for input_file in \
    "$AUTH_FILE" \
    "$PROCESS_FILE" \
    "$NETWORK_FILE" \
    "$FILE_BASELINE_FILE" \
    "$TEMPORAL_FILE"; do
    [[ -r "$input_file" ]] || die "required baseline is not readable: $input_file"
done

output_tmp=$(mktemp "${SCRIPT_DIR}/.baseline_summary.XXXXXX")
cleanup() {
    rm -f -- "$output_tmp"
}
trap cleanup EXIT

python3 -W error - \
    "$AUTH_FILE" \
    "$PROCESS_FILE" \
    "$NETWORK_FILE" \
    "$FILE_BASELINE_FILE" \
    "$TEMPORAL_FILE" \
    "$output_tmp" <<'PY'
import datetime as dt
import json
import math
import pathlib
import sys


SECTION_NAMES = ("auth", "process", "network", "file", "temporal")


def concise_error(error_type, error, traceback):
    del error_type, traceback
    print(f"Error: {error}", file=sys.stderr)


sys.excepthook = concise_error


def load_document(path: pathlib.Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as stream:
            document = json.load(stream)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"baseline is not a JSON object: {path}")
    return document


def parse_timestamp(value: object, field_name: str) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing {field_name}")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"invalid ISO-8601 {field_name}: {value}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def iso_z(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def get_window(document: dict, section_name: str) -> tuple[str, str]:
    window = document.get("window", document.get("baseline_window"))
    if not isinstance(window, dict):
        raise ValueError(f"{section_name} has no window object")
    start = window.get("start")
    end = window.get("end")
    parse_timestamp(start, f"{section_name}.window.start")
    parse_timestamp(end, f"{section_name}.window.end")
    return start, end


def collect_hosts(document: dict) -> set[str]:
    hosts = set()
    per_host = document.get("per_host")
    if isinstance(per_host, dict):
        hosts.update(str(host) for host in per_host if str(host))
    host_inventory = document.get("host_inventory")
    if isinstance(host_inventory, list):
        hosts.update(str(host) for host in host_inventory if host not in (None, ""))
    listed_hosts = document.get("hosts")
    if isinstance(listed_hosts, list):
        for entry in listed_hosts:
            if isinstance(entry, str) and entry:
                hosts.add(entry)
            elif isinstance(entry, dict):
                value = entry.get("hostname", entry.get("host"))
                if value not in (None, ""):
                    hosts.add(str(value))
    return hosts


paths = [pathlib.Path(value) for value in sys.argv[1:6]]
output_path = pathlib.Path(sys.argv[6])
documents = {
    section: load_document(path)
    for section, path in zip(SECTION_NAMES, paths, strict=True)
}

reference_start, reference_end = get_window(documents["auth"], "auth")
reference_start_time = parse_timestamp(reference_start, "baseline_window.start")
reference_end_time = parse_timestamp(reference_end, "baseline_window.end")
if reference_end_time <= reference_start_time:
    raise ValueError("baseline window end must be after start")

for section in SECTION_NAMES[1:]:
    section_start, section_end = get_window(documents[section], section)
    if (
        parse_timestamp(section_start, f"{section}.window.start") != reference_start_time
        or parse_timestamp(section_end, f"{section}.window.end") != reference_end_time
    ):
        raise ValueError(
            f"{section} window {section_start} -> {section_end} does not match "
            f"auth window {reference_start} -> {reference_end}"
        )

duration_days_value = (reference_end_time - reference_start_time).total_seconds() / 86400
duration_days = (
    int(duration_days_value)
    if duration_days_value.is_integer()
    else round(duration_days_value, 6)
)
evaluation_start = reference_end_time
evaluation_end = evaluation_start + dt.timedelta(hours=24)

hosts = set()
for document in documents.values():
    hosts.update(collect_hosts(document))

normal_failure_burst = documents["auth"].get("max_failures_1h_window", 0)
if not isinstance(normal_failure_burst, (int, float)) or isinstance(
    normal_failure_burst, bool
):
    raise ValueError("auth.max_failures_1h_window must be numeric")

failure_rate_multiplier = 3
unknown_port_penalty = 4
unknown_process_penalty = unknown_port_penalty + 1
failure_burst_threshold = max(1, math.ceil(normal_failure_burst * failure_rate_multiplier))
privilege_surge_threshold = 1

thresholds = {
    "failure_rate_multiplier": {
        "value": failure_rate_multiplier,
        "comment": "Three times the clean-window authentication rate marks a material deviation.",
    },
    "max_failures_1h_baseline": {
        "value": normal_failure_burst,
        "comment": "Directly observed maximum failures from one source IP in any rolling baseline hour.",
    },
    "failure_burst_threshold": {
        "value": failure_burst_threshold,
        "comment": "Baseline one-hour maximum multiplied by failure_rate_multiplier and rounded up.",
    },
    "unknown_port_penalty": {
        "value": unknown_port_penalty,
        "comment": "Risk weight for a destination port absent from the per-host network baseline.",
    },
    "unknown_process_penalty": {
        "value": unknown_process_penalty,
        "comment": "One point above unknown_port_penalty because first-seen executable behavior has higher investigation value.",
    },
    "privilege_escalation_surge_threshold": {
        "value": privilege_surge_threshold,
        "comment": "On a host with zero baseline privilege events, more than one evaluation event constitutes a surge.",
    },
}

result = {
    "version": "1.0",
    "generated_at": iso_z(evaluation_end),
    "baseline_window": {
        "start": iso_z(reference_start_time),
        "end": iso_z(reference_end_time),
        "end_exclusive": True,
        "duration_days": duration_days,
    },
    "evaluation_window": {
        "start": iso_z(evaluation_start),
        "end": iso_z(evaluation_end),
        "end_exclusive": True,
        "duration_hours": 24,
    },
    "host_inventory": sorted(hosts),
    "auth": documents["auth"],
    "process": documents["process"],
    "network": documents["network"],
    "file": documents["file"],
    "temporal": documents["temporal"],
    "thresholds": thresholds,
}

with output_path.open("w", encoding="utf-8", newline="\n") as output:
    json.dump(result, output, indent=2, sort_keys=False)
    output.write("\n")

print("version           : 1.0")
print(
    f"baseline window   : {iso_z(reference_start_time)} -> "
    f"{iso_z(reference_end_time)}  ({duration_days} days)"
)
print(
    f"evaluation window : {iso_z(evaluation_start)} -> "
    f"{iso_z(evaluation_end)}  (24h)"
)
print(f"hosts             : {len(hosts)}")
print("sections included : auth, process, network, file, temporal, thresholds")
PY

mv -f -- "$output_tmp" "$OUTPUT_FILE"
chmod 0644 "$OUTPUT_FILE"
printf 'baseline_summary.json written\n'

