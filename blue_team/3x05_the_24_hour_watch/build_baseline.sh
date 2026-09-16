#!/bin/bash

set -Eeuo pipefail

if [[ "${1:-}" == "--version" ]]; then
    echo "3x01-capstone-1.0"
    exit 0
fi

INPUT_FILE="${1:-}"
OUTPUT_FILE="${2:-}"

[[ -s "$INPUT_FILE" ]] || {
    echo "[baseline] ERROR: input missing or empty" >&2
    exit 1
}

[[ -n "$OUTPUT_FILE" ]] || {
    echo "[baseline] ERROR: output path required" >&2
    exit 1
}

python3 - "$INPUT_FILE" "$OUTPUT_FILE" <<'PYTHON'
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

source = Path(sys.argv[1])
output = Path(sys.argv[2])

scores = {
    "unseen_src_ip": 2.0,
    "off_hours_login": 2.0,
    "unusual_parent_process": 3.0,
    "unknown_destination": 2.0,
    "new_service": 4.0,
    "encoding_anomaly": 4.0,
}

def first(event, *fields):
    for field in fields:
        value = event.get(field)
        if value not in (None, "", "-", "null"):
            return value
    return None

def parse_time(value):
    if not value:
        return None

    value = str(value)
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        return None

    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)

    return result.astimezone(timezone.utc)

def events():
    with source.open("r", encoding="utf-8-sig") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                yield event

all_dates = set()

for event in events():
    timestamp = parse_time(first(
        event, "timestamp", "@timestamp", "event_time"
    ))
    if timestamp:
        all_dates.add(timestamp.date())

if not all_dates:
    raise SystemExit("no valid event timestamps found")

analysis_date = max(all_dates)
baseline_dates = {date for date in all_dates if date < analysis_date}

known_src = defaultdict(set)
known_dst = defaultdict(set)
known_pairs = defaultdict(set)
known_services = defaultdict(set)
hosts = set()

for event in events():
    timestamp = parse_time(first(
        event, "timestamp", "@timestamp", "event_time"
    ))
    host = first(
        event, "hostname", "host", "computer_name", "Computer"
    )

    if not timestamp or not host:
        continue

    host = str(host).lower()
    hosts.add(host)

    if timestamp.date() not in baseline_dates:
        continue

    src_ip = first(event, "src_ip", "source_ip", "SourceIp")
    dst_ip = first(event, "dst_ip", "dest_ip", "destination_ip")
    process = first(event, "process_name", "Image", "exe")
    parent = first(
        event, "parent_process_name", "ParentImage", "parent_process"
    )
    service = first(
        event, "service_name", "ServiceName", "service"
    )

    if src_ip:
        known_src[host].add(str(src_ip))
    if dst_ip:
        known_dst[host].add(str(dst_ip))
    if process and parent:
        known_pairs[host].add(
            (str(parent).lower(), str(process).lower())
        )
    if service:
        known_services[host].add(str(service).lower())

markers = []
seen = set()

def add(host, marker, field, value, reference):
    key = (host, marker, field, str(value))
    if key in seen:
        return

    seen.add(key)
    markers.append({
        "host": host,
        "marker": marker,
        "field": field,
        "observed_value": str(value),
        "baseline_reference": reference,
        "deviation_score": scores[marker],
    })

for event in events():
    timestamp = parse_time(first(
        event, "timestamp", "@timestamp", "event_time"
    ))
    host = first(
        event, "hostname", "host", "computer_name", "Computer"
    )

    if not timestamp or not host:
        continue

    if timestamp.date() != analysis_date:
        continue

    host = str(host).lower()
    event_id = str(first(event, "event_id", "EventID") or "")
    category = str(first(
        event, "canonical_label", "event_action",
        "event_category", "action"
    ) or "").lower()

    src_ip = first(event, "src_ip", "source_ip", "SourceIp")
    dst_ip = first(event, "dst_ip", "dest_ip", "destination_ip")
    process = first(event, "process_name", "Image", "exe")
    parent = first(
        event, "parent_process_name", "ParentImage", "parent_process"
    )
    service = first(
        event, "service_name", "ServiceName", "service"
    )
    command = str(first(
        event, "command_line", "CommandLine",
        "command", "raw_message"
    ) or "")

    is_login = (
        event_id in {"4624", "4625"}
        or "login" in category
        or "authentication" in category
    )

    if is_login and src_ip and str(src_ip) not in known_src[host]:
        add(
            host,
            "unseen_src_ip",
            "src_ip",
            src_ip,
            "source IP seen during baseline window",
        )

    if (
        (event_id == "4624" or category == "login_success")
        and (timestamp.hour >= 18 or timestamp.hour < 6)
    ):
        add(
            host,
            "off_hours_login",
            "timestamp",
            timestamp.isoformat().replace("+00:00", "Z"),
            "expected hours 06:00-17:59 UTC",
        )

    if process and parent:
        pair = (str(parent).lower(), str(process).lower())
        if pair not in known_pairs[host]:
            add(
                host,
                "unusual_parent_process",
                "parent_process -> process",
                f"{parent} -> {process}",
                "parent-child pair seen during baseline window",
            )

    if dst_ip and str(dst_ip) not in known_dst[host]:
        add(
            host,
            "unknown_destination",
            "dst_ip",
            dst_ip,
            "destination seen during baseline window",
        )

    is_service = (
        event_id == "7045"
        or "service_install" in category
        or "service created" in command.lower()
    )

    if is_service and service:
        if str(service).lower() not in known_services[host]:
            add(
                host,
                "new_service",
                "service_name",
                service,
                "service seen during baseline window",
            )

    if re.search(
        r"(?i)(-enc(?:odedcommand)?\b|frombase64string|base64\s+-d)",
        command,
    ):
        add(
            host,
            "encoding_anomaly",
            "command_line",
            command[:500],
            "no encoded command expected",
        )

host_scores = defaultdict(float)
host_counts = defaultdict(int)

for marker in markers:
    host_scores[marker["host"]] += marker["deviation_score"]
    host_counts[marker["host"]] += 1

host_results = [
    {
        "host": host,
        "deviation_score": round(host_scores[host], 2),
        "deviation_count": host_counts[host],
    }
    for host in sorted(hosts)
]

result = {
    "baseline_version": "3x01-capstone-1.0",
    "analysis_date": analysis_date.isoformat(),
    "hosts": host_results,
    "deviation_markers": markers,
}

output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(
    json.dumps(result, indent=2) + "\n",
    encoding="utf-8",
)
PYTHON

printf '[baseline] completed: %s\n' "$OUTPUT_FILE"
