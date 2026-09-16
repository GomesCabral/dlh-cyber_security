#!/bin/bash

set -Eeuo pipefail

fail() {
    printf '[brief] ERROR: %s\n' "$*" >&2
    exit 1
}

advisory="$ASSETS_DIR/hc_red7_advisory.md"
ioc_file="$ASSETS_DIR/ioc_feed.json"
changes="$ASSETS_DIR/change_tickets.json"
notes="$ASSETS_DIR/prior_shift_notes.md"
baseline="$SHIFT_WORKSPACE/runtime/baseline_run.json"
shift_start="$SHIFT_WORKSPACE/runtime/shift_start.json"
output="$SHIFT_WORKSPACE/alerts/shift_briefing.json"

required=(
    "$advisory"
    "$ioc_file"
    "$changes"
    "$notes"
    "$baseline"
    "$shift_start"
)

printf '[brief] checking input files... '

for file in "${required[@]}"
do
    [[ -s "$file" ]] || fail "missing or empty input: $file"
done

printf 'OK\n'

python3 - \
    "$advisory" \
    "$ioc_file" \
    "$changes" \
    "$notes" \
    "$baseline" \
    "$shift_start" \
    "$output" <<'PYTHON'
import json
import re
import sys
from pathlib import Path

(
    advisory_path,
    ioc_path,
    changes_path,
    notes_path,
    baseline_path,
    shift_path,
    output_path,
) = map(Path, sys.argv[1:])

def load_json(path):
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)

def list_records(document, names):
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for name in names:
            value = document.get(name)
            if isinstance(value, list):
                return value
    return []

def first(record, *names, default=None):
    for name in names:
        value = record.get(name)
        if value not in (None, ""):
            return value
    return default

def markdown_items_under_heading(text, heading):
    lines = text.splitlines()
    collecting = False
    items = []

    for line in lines:
        stripped = line.strip()

        if re.match(r"^#{1,6}\s+", stripped):
            title = re.sub(r"^#{1,6}\s+", "", stripped).strip()

            if collecting and title.casefold() != heading.casefold():
                break

            collecting = title.casefold().startswith(heading.casefold())
            continue

        if collecting:
            match = re.match(
                r"^\s*(?:[-*]|\d+[.)])\s+(?:\[[ xX]\]\s*)?(.+)",
                line,
            )
            if match:
                items.append(match.group(1).strip())

    return items

advisory = advisory_path.read_text(encoding="utf-8-sig")
notes_text = notes_path.read_text(encoding="utf-8-sig")
ioc_document = load_json(ioc_path)
changes_document = load_json(changes_path)
baseline = load_json(baseline_path)
shift = load_json(shift_path)

cluster_match = re.search(r"\bHC-RED7\b", advisory)

if not cluster_match:
    raise SystemExit("HC-RED7 not found in advisory")

cluster_id = cluster_match.group(0)
expected_cluster = shift.get("advisory_cluster_id")

if cluster_id != expected_cluster:
    raise SystemExit(
        f"cluster mismatch: advisory={cluster_id}, shift={expected_cluster}"
    )

tactics = sorted(set(
    match.upper()
    for match in re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", advisory, re.I)
))

ioc_records = list_records(
    ioc_document,
    ("iocs", "indicators", "ioc_feed"),
)

ioc_types = {
    "ip": 0,
    "domain": 0,
    "hash": 0,
    "account": 0,
    "service_name": 0,
    "port": 0,
}
ioc_values = []

type_aliases = {
    "ipv4": "ip",
    "ipv6": "ip",
    "ip_address": "ip",
    "hostname": "domain",
    "fqdn": "domain",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
    "username": "account",
    "user": "account",
    "service": "service_name",
    "service-name": "service_name",
    "destination_port": "port",
}

for record in ioc_records:
    if not isinstance(record, dict):
        continue

    ioc_type = str(first(
        record, "type", "ioc_type", "indicator_type", default=""
    )).lower().strip()

    ioc_type = type_aliases.get(ioc_type, ioc_type)

    value = first(
        record,
        "value",
        "indicator",
        "ioc_value",
        "observable",
    )

    if value is None:
        continue

    ioc_values.append(str(value))

    if ioc_type in ioc_types:
        ioc_types[ioc_type] += 1

change_records = list_records(
    changes_document,
    ("change_tickets", "tickets", "changes"),
)

active_changes = []

for record in change_records:
    if not isinstance(record, dict):
        continue

    status = str(first(
        record, "status", "approval_status", default="approved"
    )).lower()

    if status not in {"approved", "active", "authorized", "authorised"}:
        continue

    window = record.get("window", {})
    if not isinstance(window, dict):
        window = {}

    hosts = first(
        record,
        "hosts",
        "host_list",
        "affected_hosts",
        "targets",
        default=[],
    )

    if isinstance(hosts, str):
        hosts = [hosts]
    elif not isinstance(hosts, list):
        hosts = []

    active_changes.append({
        "ticket_id": str(first(
            record, "ticket_id", "id", "change_id", default="unknown"
        )),
        "window_start": str(
            first(
                record,
                "window_start",
                "start",
                "start_time",
                default=first(window, "start", "window_start", default=""),
            )
        ),
        "window_end": str(
            first(
                record,
                "window_end",
                "end",
                "end_time",
                default=first(window, "end", "window_end", default=""),
            )
        ),
        "hosts": [str(host) for host in hosts],
        "owner": str(first(
            record, "owner", "requester", "change_owner", default=""
        )),
        "approved_activity": str(first(
            record,
            "approved_activity",
            "activity",
            "description",
            "summary",
            default="",
        )),
    })

open_items = markdown_items_under_heading(notes_text, "Open Items")

note_items = markdown_items_under_heading(advisory, "Notes")
note_count = len(note_items)

result = {
    "cluster_id": cluster_id,
    "cluster_tactics": tactics,
    "ioc_count": len(ioc_records),
    "ioc_by_type": ioc_types,
    "ioc_values": sorted(set(ioc_values)),
    "active_change_tickets": active_changes,
    "prior_shift_open_items": open_items,
    "baseline_hot_hosts": baseline.get("hot_hosts", []),
    "hosts_with_deviations": baseline.get(
        "hosts_with_deviations", 0
    ),
}

output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(
    json.dumps(result, indent=2) + "\n",
    encoding="utf-8",
)

print(json.dumps({
    "cluster_id": cluster_id,
    "tactics": tactics,
    "ioc_by_type": ioc_types,
    "ioc_total": len(ioc_records),
    "change_count": len(active_changes),
    "open_items": len(open_items),
    "hot_hosts": len(result["baseline_hot_hosts"]),
    "note_count": note_count,
}))
PYTHON

summary="$(
    python3 - "$output" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    document = json.load(stream)

print(document["cluster_id"])
print(" ".join(document["cluster_tactics"]))
print(" ".join(
    f"{key}={value}"
    for key, value in document["ioc_by_type"].items()
))
print(document["ioc_count"])
print(len(document["active_change_tickets"]))
print(len(document["prior_shift_open_items"]))
print(len(document["baseline_hot_hosts"]))
PYTHON
)"

mapfile -t values <<<"$summary"

printf '[brief] cluster %s loaded\n' "${values[0]}"
printf '[brief] tactics: %s\n' "${values[1]}"
printf '[brief] IOCs: %s total=%s\n' "${values[2]}" "${values[3]}"
printf '[brief] active change tickets: %s\n' "${values[4]}"
printf '[brief] prior shift open items: %s\n' "${values[5]}"
printf '[brief] baseline hot hosts: %s\n' "${values[6]}"
printf '[brief] cluster ID cross-check: OK\n'
printf '[brief] shift_briefing.json written\n'
