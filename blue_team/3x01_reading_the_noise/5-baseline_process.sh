#!/bin/bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"
readonly LABELED_EVENTS="${LABELED_EVENTS:-${SCRIPT_DIR}/labeled_events.json}"
readonly OUTPUT_FILE="${SCRIPT_DIR}/baseline_process.json"
readonly BASELINE_DAYS="${BASELINE_DAYS:-7}"

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || die "python3 is required"
[[ -d "$HANDOFF_DIR" ]] || die "handoff directory is not accessible: $HANDOFF_DIR"
[[ -r "$LABELED_EVENTS" ]] || die "labeled dataset is not readable: $LABELED_EVENTS"
[[ "$BASELINE_DAYS" =~ ^[1-9][0-9]*$ ]] || die "BASELINE_DAYS must be a positive integer"

output_tmp=$(mktemp "${SCRIPT_DIR}/.baseline_process.XXXXXX")
cleanup() {
    rm -f -- "$output_tmp"
}
trap cleanup EXIT

python3 -W error - "$LABELED_EVENTS" "$output_tmp" "$BASELINE_DAYS" <<'PY'
import collections
import datetime as dt
import json
import pathlib
import sys


PROCESS_LABELS = {"process_start", "child_process_spawn"}


def concise_error(error_type, error, traceback):
    del error_type, traceback
    print(f"Error: {error}", file=sys.stderr)


sys.excepthook = concise_error


def parse_timestamp(value: object) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("missing or non-string timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def iso_z(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def iter_events(path: pathlib.Path):
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid NDJSON on line {line_number}: {error}") from error
            if not isinstance(event, dict):
                raise ValueError(f"line {line_number} is not a JSON object")
            yield line_number, event


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
    if not normalized:
        return None
    return normalized.rsplit("/", maxsplit=1)[-1]


def process_name(event: dict):
    value = first_value(
        event,
        ("process_name",),
        ("Image", "NewProcessName", "ProcessName", "process_name", "exe", "comm"),
    )
    return executable_name(value)


def parent_name(event: dict):
    value = first_value(
        event,
        ("parent_process_name",),
        ("ParentImage", "ParentProcessName", "parent_process_name", "parent_comm"),
    )
    name = executable_name(value)
    if name is not None:
        return name
    parent_id = first_value(
        event,
        ("parent_process_id",),
        ("ParentProcessId", "ParentProcessID", "ppid"),
    )
    return f"pid:{parent_id}" if parent_id is not None else None


input_path = pathlib.Path(sys.argv[1])
output_path = pathlib.Path(sys.argv[2])
baseline_days = int(sys.argv[3])

minimum_time = None
maximum_time = None
for line_number, event in iter_events(input_path):
    try:
        event_time = parse_timestamp(event.get("timestamp"))
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid timestamp on line {line_number}: {error}") from error
    minimum_time = event_time if minimum_time is None else min(minimum_time, event_time)
    maximum_time = event_time if maximum_time is None else max(maximum_time, event_time)

if minimum_time is None or maximum_time is None:
    raise ValueError("labeled dataset contains no events")

window_start = minimum_time
window_end = window_start + dt.timedelta(days=baseline_days)
if window_end > maximum_time:
    raise ValueError(
        "BASELINE_DAYS exceeds the available dataset span: "
        f"requested end {iso_z(window_end)}, dataset maximum {iso_z(maximum_time)}"
    )

processes_by_host = collections.defaultdict(dict)
global_counts = collections.Counter()
process_hosts = collections.defaultdict(set)
parent_child_by_host = collections.defaultdict(set)

for line_number, event in iter_events(input_path):
    try:
        event_time = parse_timestamp(event.get("timestamp"))
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid timestamp on line {line_number}: {error}") from error
    if not (window_start <= event_time < window_end):
        continue
    if event.get("canonical_label") not in PROCESS_LABELS:
        continue

    child = process_name(event)
    if child is None:
        continue
    hostname = event.get("hostname")
    host = str(hostname) if hostname not in (None, "", "-") else "unknown"
    seen_at = iso_z(event_time)

    stats = processes_by_host[host].setdefault(
        child,
        {"execution_count": 0, "first_seen": seen_at, "last_seen": seen_at, "users": set()},
    )
    stats["execution_count"] += 1
    stats["first_seen"] = min(stats["first_seen"], seen_at)
    stats["last_seen"] = max(stats["last_seen"], seen_at)

    user = first_value(
        event,
        ("user",),
        ("User", "SubjectUserName", "user", "uid", "auid"),
    )
    if user is not None and user not in ("unknown", "4294967295"):
        stats["users"].add(user)

    global_counts[child] += 1
    process_hosts[child].add(host)

    parent = parent_name(event)
    if parent is not None:
        parent_child_by_host[host].add((parent, child))

per_host = {}
for host in sorted(processes_by_host):
    expected = []
    for name in sorted(processes_by_host[host]):
        stats = processes_by_host[host][name]
        expected.append(
            {
                "process_name": name,
                "execution_count": stats["execution_count"],
                "first_seen": stats["first_seen"],
                "last_seen": stats["last_seen"],
                "users": sorted(stats["users"]),
            }
        )
    per_host[host] = expected

global_top = [
    {"process_name": name, "execution_count": count}
    for name, count in sorted(global_counts.items(), key=lambda item: (-item[1], item[0]))[:50]
]

rare_processes = [
    {
        "process_name": name,
        "total_executions": global_counts[name],
        "host_count": len(process_hosts[name]),
        "hosts": sorted(process_hosts[name]),
    }
    for name in sorted(global_counts, key=lambda item: (global_counts[item], item))
    if len(process_hosts[name]) == 1 or global_counts[name] < 5
]

parent_child_pairs = {}
for host in sorted(parent_child_by_host):
    parent_child_pairs[host] = [
        {"parent": parent, "child": child}
        for parent, child in sorted(parent_child_by_host[host])
    ]

pair_count = sum(len(pairs) for pairs in parent_child_pairs.values())
result = {
    "window": {
        "start": iso_z(window_start),
        "end": iso_z(window_end),
        "end_exclusive": True,
        "baseline_days": baseline_days,
    },
    "per_host": per_host,
    "global_top": global_top,
    "rare_processes": rare_processes,
    "parent_child_pairs": parent_child_pairs,
}

with output_path.open("w", encoding="utf-8", newline="\n") as output:
    json.dump(result, output, indent=2, sort_keys=False)
    output.write("\n")

top_name = global_top[0]["process_name"] if global_top else "none"
top_count = global_top[0]["execution_count"] if global_top else 0
print(f"baseline window : {iso_z(window_start)} -> {iso_z(window_end)}")
print(f"processes indexed by host: {len(per_host)} hosts")
print(f"global top process    : {top_name} ({top_count} executions)")
print(f"rare processes        : {len(rare_processes)}")
print(f"parent->child pairs   : {pair_count}")
PY

mv -f -- "$output_tmp" "$OUTPUT_FILE"
chmod 0644 "$OUTPUT_FILE"
printf 'baseline_process.json written\n'


