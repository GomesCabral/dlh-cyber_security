#!/bin/bash

set -Eeuo pipefail

if [[ "${1:-}" == "--version" ]]; then
    echo "3x03-capstone-1.0"
    exit 0
fi

queue="${1:-}"
briefing="${2:-}"
baseline="${3:-}"
assets="${4:-}"
output="${5:-}"

for file in "$queue" "$briefing" "$baseline" "$assets"
do
    [[ -s "$file" ]] || {
        echo "[triage] ERROR: missing input: $file" >&2
        exit 1
    }
done

[[ -n "$output" ]] || {
    echo "[triage] ERROR: output path required" >&2
    exit 1
}

python3 - \
    "$queue" \
    "$briefing" \
    "$baseline" \
    "$assets" \
    "$output" <<'PYTHON'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

queue_path = Path(sys.argv[1])
briefing_path = Path(sys.argv[2])
baseline_path = Path(sys.argv[3])
assets_path = Path(sys.argv[4])
output_path = Path(sys.argv[5])

def load(path):
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)

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

def scalar_values(value):
    result = []

    if isinstance(value, dict):
        for child in value.values():
            result.extend(scalar_values(child))
    elif isinstance(value, list):
        for child in value:
            result.extend(scalar_values(child))
    elif value is not None:
        result.append(str(value).casefold())

    return result

alerts = load(queue_path)
briefing = load(briefing_path)
baseline = load(baseline_path)
load(assets_path)  # Validate assets input.

ioc_values = {
    str(value).casefold(): str(value)
    for value in briefing.get("ioc_values", [])
}

deviation_hosts = {
    str(marker.get("host", "")).casefold()
    for marker in baseline.get("deviation_markers", [])
    if marker.get("host")
}

priority_hosts = {
    str(host).casefold()
    for host in briefing.get("baseline_hot_hosts", [])
}

changes = briefing.get("active_change_tickets", [])
classified_at = datetime.now(timezone.utc).isoformat(
    timespec="seconds"
).replace("+00:00", "Z")

records = []

for alert in alerts:
    host = str(
        alert.get("hostname")
        or alert.get("host")
        or "unknown"
    ).casefold()

    timestamp = parse_time(alert.get("timestamp"))
    values = set(scalar_values(alert))

    matches_ioc = sorted({
        original
        for normalized, original in ioc_values.items()
        if normalized in values
    })

    baseline_deviation = host in deviation_hosts
    change_ticket = None

    for change in changes:
        change_hosts = {
            str(item).casefold()
            for item in change.get("hosts", [])
        }

        if host not in change_hosts:
            continue

        start = parse_time(change.get("window_start"))
        end = parse_time(change.get("window_end"))

        if timestamp and start and end and start <= timestamp <= end:
            change_ticket = change.get("ticket_id")
            break

    severity = str(alert.get("severity", "low")).lower()
    if severity not in {"critical", "high", "medium", "low"}:
        severity = "low"

    if matches_ioc:
        classification = "TP"
        note = "Alert matches HC-RED7 IOC feed; requires investigation and escalation."
    elif change_ticket:
        classification = "FP"
        note = (
            f"Host and timestamp match approved change "
            f"{change_ticket}; treated as authorized activity."
        )
    elif severity in {"critical", "high"}:
        classification = "TP"
        note = "High-severity alert without an approved change window."
    elif baseline_deviation and host in priority_hosts:
        classification = "TP"
        note = "Medium alert affects a top baseline-deviation host without an approved change."
    else:
        classification = "NOISE"
        note = "No IOC, high severity, priority-host deviation, or approved-change match."

    records.append({
        "alert_id": str(alert.get("alert_id", "")),
        "rule_id": str(alert.get("rule_id", "")),
        "host": host,
        "user": alert.get("user"),
        "classification": classification,
        "severity": severity,
        "matches_ioc": matches_ioc,
        "baseline_deviation": baseline_deviation,
        "change_ticket_match": change_ticket,
        "analyst_note": note[:200],
        "classified_at": classified_at,
    })

output_path.parent.mkdir(parents=True, exist_ok=True)

with output_path.open("w", encoding="utf-8") as stream:
    for record in records:
        stream.write(
            json.dumps(record, separators=(",", ":")) + "\n"
        )
PYTHON
