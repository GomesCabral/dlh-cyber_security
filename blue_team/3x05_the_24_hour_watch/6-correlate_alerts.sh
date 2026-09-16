#!/bin/bash

set -Eeuo pipefail

fail() {
    printf '[group] ERROR: %s\n' "$*" >&2
    exit 1
}

triage="$SHIFT_WORKSPACE/alerts/triage_log.jsonl"
queue="$SHIFT_WORKSPACE/alerts/alert_queue.json"
shift_start="$SHIFT_WORKSPACE/runtime/shift_start.json"
output="$SHIFT_WORKSPACE/alerts/incidents.json"

[[ -s "$triage" ]] || fail "triage_log.jsonl missing"
[[ -s "$queue" ]] || fail "alert_queue.json missing"
[[ -s "$shift_start" ]] || fail "shift_start.json missing"

python3 - \
    "$triage" \
    "$queue" \
    "$shift_start" \
    "$output" <<'PYTHON'
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

triage_path = Path(sys.argv[1])
queue_path = Path(sys.argv[2])
shift_path = Path(sys.argv[3])
output_path = Path(sys.argv[4])

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

def iso(value):
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")

with triage_path.open("r", encoding="utf-8") as stream:
    triage_records = [
        json.loads(line)
        for line in stream
        if line.strip()
    ]

with queue_path.open("r", encoding="utf-8") as stream:
    alerts = json.load(stream)

with shift_path.open("r", encoding="utf-8") as stream:
    shift = json.load(stream)

alert_index = {
    str(alert.get("alert_id")): alert
    for alert in alerts
}

tp_records = []

for record in triage_records:
    if record.get("classification") != "TP":
        continue

    alert_id = str(record.get("alert_id"))
    alert = alert_index.get(alert_id)

    if not alert:
        raise SystemExit(f"alert not found in queue: {alert_id}")

    timestamp = parse_time(alert.get("timestamp"))

    if not timestamp:
        raise SystemExit(f"invalid timestamp for alert: {alert_id}")

    tp_records.append({
        **record,
        "timestamp": timestamp,
        "rule_title": alert.get("rule_title", ""),
    })

print(f"[group] TP alerts: {len(tp_records)}")
print("[group] grouping by temporal proximity, shared user, IOC match")

count = len(tp_records)
parent = list(range(count))

def find(index):
    while parent[index] != index:
        parent[index] = parent[parent[index]]
        index = parent[index]
    return index

def union(left, right):
    left_root = find(left)
    right_root = find(right)

    if left_root != right_root:
        parent[right_root] = left_root

# Rule 1: same host within 15 minutes.
by_host = defaultdict(list)

for index, record in enumerate(tp_records):
    by_host[record["host"].casefold()].append(index)

for indexes in by_host.values():
    indexes.sort(key=lambda item: tp_records[item]["timestamp"])

    for left, right in zip(indexes, indexes[1:]):
        difference = (
            tp_records[right]["timestamp"]
            - tp_records[left]["timestamp"]
        ).total_seconds()

        if difference <= 900:
            union(left, right)

# Rule 2: shared non-null user.
by_user = defaultdict(list)

for index, record in enumerate(tp_records):
    user = record.get("user")

    if user not in (None, ""):
        by_user[str(user).casefold()].append(index)

for indexes in by_user.values():
    first = indexes[0]
    for other in indexes[1:]:
        union(first, other)

# Rule 3: shared IOC.
by_ioc = defaultdict(list)

for index, record in enumerate(tp_records):
    for value in record.get("matches_ioc", []):
        by_ioc[str(value).casefold()].append(index)

for indexes in by_ioc.values():
    first = indexes[0]
    for other in indexes[1:]:
        union(first, other)

groups = defaultdict(list)

for index in range(count):
    groups[find(index)].append(index)

ordered_groups = sorted(
    groups.values(),
    key=lambda indexes: min(
        tp_records[index]["timestamp"] for index in indexes
    ),
)

def incident_suffix(number):
    result = ""
    number += 1

    while number:
        number, remainder = divmod(number - 1, 26)
        result = chr(65 + remainder) + result

    return result

def grouping_rule(records):
    ioc_counts = defaultdict(int)
    user_counts = defaultdict(int)

    for record in records:
        for ioc in record.get("matches_ioc", []):
            ioc_counts[str(ioc).casefold()] += 1

        user = record.get("user")
        if user not in (None, ""):
            user_counts[str(user).casefold()] += 1

    if any(value > 1 for value in ioc_counts.values()):
        return "ioc_match"

    if any(value > 1 for value in user_counts.values()):
        return "shared_user"

    if len(records) > 1:
        return "temporal"

    return "residual"

def category(records):
    titles = " ".join(
        str(record.get("rule_title", "")).lower()
        for record in records
    )

    if "authentication" in titles or "logon" in titles:
        return "credential_abuse"
    if "service" in titles:
        return "persistence"
    if "command" in titles or "interpreter" in titles:
        return "lateral_movement"
    return "unknown"

today = datetime.now(timezone.utc).strftime("%Y%m%d")
incidents = []

for number, indexes in enumerate(ordered_groups):
    records = [tp_records[index] for index in indexes]
    rule = grouping_rule(records)

    hosts = sorted({
        record["host"].casefold()
        for record in records
        if record.get("host")
    })

    users = sorted({
        str(record["user"])
        for record in records
        if record.get("user") not in (None, "")
    })

    iocs = sorted({
        str(ioc)
        for record in records
        for ioc in record.get("matches_ioc", [])
    })

    timestamps = [record["timestamp"] for record in records]

    confidence = (
        "high" if iocs
        else "medium" if len(records) > 1
        else "low"
    )

    incidents.append({
        "incident_id": (
            f"INC-{today}-{incident_suffix(number)}"
        ),
        "host_list": hosts,
        "user_list": users,
        "ioc_list": iocs,
        "alert_ids": [
            record["alert_id"] for record in records
        ],
        "first_seen": iso(min(timestamps)),
        "last_seen": iso(max(timestamps)),
        "grouping_rule": rule,
        "tentative_category": category(records),
        "confidence": confidence,
    })

result = {
    "shift_id": shift.get("shift_id", "unknown"),
    "generated_at": iso(datetime.now(timezone.utc)),
    "incidents": incidents,
    "incident_count": len(incidents),
    "unmatched_tp_count": 0,
}

output_path.write_text(
    json.dumps(result, indent=2) + "\n",
    encoding="utf-8",
)

for incident in incidents:
    host = (
        incident["host_list"][0]
        if incident["host_list"]
        else "unknown"
    )

    print(
        f'[group] {incident["incident_id"]}: '
        f'{len(incident["alert_ids"])} alerts  '
        f'host={host}  rule={incident["grouping_rule"]}'
    )

print(f"[group] incident_count={len(incidents)}")

if len(incidents) < 3:
    raise SystemExit("fewer than 3 incidents produced")
PYTHON

printf '[group] incidents.json written\n'
