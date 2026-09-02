#!/bin/bash

set -Eeuo pipefail

# Severity rubric for consistent Tier 1 prioritization.
readonly UNKNOWN_PROCESS_SEVERITY="low"
readonly UNKNOWN_PARENT_CHILD_SEVERITY="medium"
readonly RARE_PROCESS_SPIKE_SEVERITY="high"
readonly HIGH_RISK_PROCESS_SEVERITY="medium"

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"
readonly SUMMARY_FILE="${BASELINE_SUMMARY:-${SCRIPT_DIR}/baseline_summary.json}"
readonly LABELED_EVENTS="${LABELED_EVENTS:-${SCRIPT_DIR}/labeled_events.json}"
readonly OUTPUT_FILE="${SCRIPT_DIR}/anomalies_process.json"

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || die "python3 is required"
[[ -d "$HANDOFF_DIR" ]] || die "handoff directory is not accessible: $HANDOFF_DIR"
[[ -r "$SUMMARY_FILE" ]] || die "baseline summary is not readable: $SUMMARY_FILE"
[[ -r "$LABELED_EVENTS" ]] || die "labeled dataset is not readable: $LABELED_EVENTS"

output_tmp=$(mktemp "${SCRIPT_DIR}/.anomalies_process.XXXXXX")
cleanup() {
    rm -f -- "$output_tmp"
}
trap cleanup EXIT

python3 -W error - \
    "$SUMMARY_FILE" "$LABELED_EVENTS" "$output_tmp" \
    "$UNKNOWN_PROCESS_SEVERITY" "$UNKNOWN_PARENT_CHILD_SEVERITY" \
    "$RARE_PROCESS_SPIKE_SEVERITY" "$HIGH_RISK_PROCESS_SEVERITY" <<'PY'
import collections
import datetime as dt
import json
import pathlib
import sys


PROCESS_LABELS = {"process_start", "child_process_spawn"}
HIGH_RISK_PROCESSES = {
    "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "nc", "nmap",
    "wget", "curl", "python3", "bash",
}


def concise_error(error_type, error, traceback):
    del error_type, traceback
    print(f"Error: {error}", file=sys.stderr)


sys.excepthook = concise_error


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
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def first_value(event: dict, top_fields: tuple[str, ...], detail_fields: tuple[str, ...]):
    for field in top_fields:
        value = event.get(field)
        if value not in (None, "", "-"):
            return str(value)
    details = event.get("details")
    if isinstance(details, dict):
        for field in detail_fields:
            value = details.get(field)
            if value not in (None, "", "-"):
                return str(value)
    return None


def executable_name(value: str | None):
    if value is None:
        return None
    normalized = value.strip().strip('"').replace("\\", "/")
    return normalized.rsplit("/", maxsplit=1)[-1] if normalized else None


def process_name(event: dict):
    return executable_name(first_value(
        event, ("process_name",),
        ("Image", "NewProcessName", "ProcessName", "process_name", "exe", "comm"),
    ))


def parent_name(event: dict):
    return executable_name(first_value(
        event, ("parent_process_name",),
        ("ParentImage", "ParentProcessName", "parent_process_name", "parent_comm"),
    ))


def event_ref(event: dict, line_number: int) -> str:
    for field in ("event_ref", "event_uuid", "id"):
        value = event.get(field)
        if value not in (None, ""):
            return str(value)
    return f"{event.get('source_type', 'unknown')}:{event.get('event_id', 'na')}:line:{line_number}"


def text(value: object) -> str:
    return "unknown" if value in (None, "", "-") else str(value)


def known_names(entries: object, host: str) -> set[str]:
    if isinstance(entries, dict):
        return {str(name).lower() for name in entries}
    if not isinstance(entries, list):
        raise ValueError(f"process.per_host.{host} must be a list or object")
    names = set()
    for entry in entries:
        if isinstance(entry, str):
            names.add(entry.lower())
        elif isinstance(entry, dict):
            name = entry.get("process_name", entry.get("name"))
            if name not in (None, ""):
                names.add(str(name).lower())
    return names


summary_path = pathlib.Path(sys.argv[1])
events_path = pathlib.Path(sys.argv[2])
output_path = pathlib.Path(sys.argv[3])
severity = {
    "unknown_process_for_host": sys.argv[4],
    "unknown_parent_child": sys.argv[5],
    "rare_process_spike": sys.argv[6],
    "high_risk_process": sys.argv[7],
}

try:
    with summary_path.open("r", encoding="utf-8") as stream:
        summary = json.load(stream)
except json.JSONDecodeError as error:
    raise ValueError(f"invalid baseline summary JSON: {error}") from error

evaluation = summary.get("evaluation_window")
baseline = summary.get("process")
if not isinstance(evaluation, dict) or not isinstance(baseline, dict):
    raise ValueError("baseline summary requires evaluation_window and process objects")
start = parse_timestamp(evaluation.get("start"), "evaluation_window.start")
end = parse_timestamp(evaluation.get("end"), "evaluation_window.end")
if end <= start:
    raise ValueError("evaluation window end must be after start")

per_host = baseline.get("per_host")
rare = baseline.get("rare_processes")
pairs = baseline.get("parent_child_pairs")
if not isinstance(per_host, dict) or not isinstance(rare, list) or not isinstance(pairs, dict):
    raise ValueError("process baseline requires per_host, rare_processes, and parent_child_pairs")

known_by_host = {host: known_names(entries, host) for host, entries in per_host.items()}
known_pairs = collections.defaultdict(set)
for host, entries in pairs.items():
    if not isinstance(entries, list):
        raise ValueError(f"process.parent_child_pairs.{host} must be a list")
    for pair in entries:
        if not isinstance(pair, dict):
            continue
        parent, child = pair.get("parent"), pair.get("child")
        if parent not in (None, "") and child not in (None, ""):
            parent_key = str(parent).lower()
            if not parent_key.startswith("pid:"):
                known_pairs[str(host)].add((parent_key, str(child).lower()))

globally_rare = {
    str(item["process_name"]).lower()
    for item in rare
    if isinstance(item, dict)
    and item.get("process_name") not in (None, "")
    and isinstance(item.get("total_executions", item.get("execution_count")), int)
    and item.get("total_executions", item.get("execution_count")) < 5
}

by_process = collections.defaultdict(list)
by_pair = collections.defaultdict(list)
with events_path.open("r", encoding="utf-8") as stream:
    for line_number, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid NDJSON on line {line_number}: {error}") from error
        timestamp = parse_timestamp(event.get("timestamp"), f"line {line_number}.timestamp")
        if not (start <= timestamp < end) or event.get("canonical_label") not in PROCESS_LABELS:
            continue
        child = process_name(event)
        if child is None:
            continue
        parent = parent_name(event)
        host = text(event.get("hostname"))
        event.update({"_time": timestamp, "_ref": event_ref(event, line_number),
                      "_child": child, "_parent": parent})
        by_process[(host, child.lower())].append(event)
        if parent is not None:
            by_pair[(host, parent.lower(), child.lower())].append(event)

anomalies = []
for (host, child_key), events in sorted(by_process.items()):
    ordered = sorted(events, key=lambda item: item["_time"])
    first = ordered[0]
    is_known = child_key in known_by_host.get(host, set())
    common = {
        "host": host, "process_name": first["_child"],
        "event_refs": [item["_ref"] for item in ordered],
    }
    if not is_known:
        anomalies.append({
            "timestamp": iso_z(first["_time"]), **common,
            "user": text(first.get("user")),
            "parent_process_name": first["_parent"] or "unknown",
            "anomaly_type": "unknown_process_for_host",
            "severity": severity["unknown_process_for_host"],
        })
    if child_key in globally_rare and len(ordered) > 10:
        crossing = ordered[10]
        anomalies.append({
            "timestamp": iso_z(crossing["_time"]), **common,
            "user": text(crossing.get("user")),
            "parent_process_name": crossing["_parent"] or "unknown",
            "anomaly_type": "rare_process_spike",
            "severity": severity["rare_process_spike"],
        })
    if child_key in HIGH_RISK_PROCESSES and not is_known:
        anomalies.append({
            "timestamp": iso_z(first["_time"]), **common,
            "user": text(first.get("user")),
            "parent_process_name": first["_parent"] or "unknown",
            "anomaly_type": "high_risk_process",
            "severity": severity["high_risk_process"],
        })

for (host, parent_key, child_key), events in sorted(by_pair.items()):
    if (parent_key, child_key) in known_pairs.get(host, set()):
        continue
    ordered = sorted(events, key=lambda item: item["_time"])
    first = ordered[0]
    anomalies.append({
        "timestamp": iso_z(first["_time"]), "host": host,
        "user": text(first.get("user")), "process_name": first["_child"],
        "parent_process_name": first["_parent"],
        "anomaly_type": "unknown_parent_child",
        "severity": severity["unknown_parent_child"],
        "event_refs": [item["_ref"] for item in ordered],
    })

anomalies.sort(key=lambda item: (
    item["timestamp"], item["anomaly_type"], item["host"],
    item["process_name"].lower(), item["parent_process_name"].lower(),
))
with output_path.open("w", encoding="utf-8", newline="\n") as output:
    json.dump(anomalies, output, indent=2)
    output.write("\n")

counts = collections.Counter(item["anomaly_type"] for item in anomalies)
print(f"evaluation window : {iso_z(start)} -> {iso_z(end)}")
print(f"unknown_process_for_host : {counts['unknown_process_for_host']}")
print(f"unknown_parent_child     : {counts['unknown_parent_child']}")
print(f"rare_process_spike       : {counts['rare_process_spike']}")
print(f"high_risk_process        : {counts['high_risk_process']}")
print(f"total anomalies          : {len(anomalies)}")
PY

mv -f -- "$output_tmp" "$OUTPUT_FILE"
chmod 0644 "$OUTPUT_FILE"
printf 'anomalies_process.json written\n'


