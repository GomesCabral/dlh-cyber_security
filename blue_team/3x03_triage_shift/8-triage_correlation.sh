#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INPUT_FILE="${ENRICHED_QUEUE_FILE:-$SCRIPT_DIR/enriched_queue.json}"
TICKETS_DIR="${TICKETS_DIR:-$SCRIPT_DIR/tickets}"
OUTPUT_FILE="$TICKETS_DIR/batch6_incidents.json"

[[ -r "$INPUT_FILE" ]] || {
    printf 'ERROR: required input is not readable: %s\n' "$INPUT_FILE" >&2
    exit 1
}
mkdir -p "$TICKETS_DIR"

python3 -W error /dev/fd/3 \
    "$INPUT_FILE" "$TICKETS_DIR" "$OUTPUT_FILE" 3<<'PY'
import collections
import datetime as dt
import json
import os
import pathlib
import re
import sys

input_path, tickets_dir, output_path = sys.argv[1:]


def load_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=dt.timezone.utc)
    return result.astimezone(dt.timezone.utc)


def iso_time(value):
    return value.astimezone(dt.timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def event_summary(alert):
    value = alert.get("event_summary")
    return value if isinstance(value, dict) else {}


def hostname(alert):
    return str(event_summary(alert).get("hostname") or "unknown")


def timestamp(alert):
    return parse_time(event_summary(alert).get("timestamp"))


def priority(alert):
    value = alert.get("priority_score", 0)
    return float(value) if isinstance(value, (int, float)) else 0.0


def criticality(alert):
    asset = alert.get("asset")
    if not isinstance(asset, dict):
        asset = alert.get("asset_context")
    asset = asset if isinstance(asset, dict) else {}
    return str(
        asset.get("criticality") or asset.get("asset_criticality") or "unknown"
    ).casefold()


def previous_tickets(folder):
    by_alert = collections.defaultdict(list)
    paths = sorted(pathlib.Path(folder).glob("batch[1-5]_*.json"))
    for path in paths:
        try:
            document = load_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(document, list):
            continue
        for ticket in document:
            if isinstance(ticket, dict) and ticket.get("alert_id"):
                by_alert[str(ticket["alert_id"])].append(ticket)
    return by_alert, paths


def temporal_groups(queue):
    by_host = collections.defaultdict(list)
    for alert in queue:
        if not isinstance(alert, dict) or not alert.get("alert_id"):
            continue
        event_time = timestamp(alert)
        if event_time is not None:
            by_host[hostname(alert)].append((event_time, alert))

    incidents = []
    for host, records in sorted(by_host.items()):
        records.sort(key=lambda item: (item[0], str(item[1]["alert_id"])))
        current = []
        previous_time = None
        for event_time, alert in records:
            if previous_time is None or (event_time - previous_time).total_seconds() <= 600:
                current.append((event_time, alert))
            else:
                if len(current) >= 2:
                    incidents.append((host, current))
                current = [(event_time, alert)]
            previous_time = event_time
        if len(current) >= 2:
            incidents.append((host, current))
    return incidents


def unique_strings(values):
    return sorted({str(value) for value in values if value not in (None, "")})


def evidence_refs(alerts):
    references = []
    for alert in alerts:
        candidates = [alert.get("event_ref")]
        event = alert.get("event_record")
        if isinstance(event, dict):
            candidates.append(event.get("event_ref"))
        for document in (alert, event):
            if not isinstance(document, dict):
                continue
            for key in ("event_refs", "linked_event_refs", "correlation_primitives"):
                value = document.get(key, [])
                candidates.extend(value if isinstance(value, list) else [value])
        for value in candidates:
            if isinstance(value, str) and value and value not in references:
                references.append(value)
    return references


def combined_iocs(alerts):
    answer = []
    seen = set()
    for alert in alerts:
        for hit in alert.get("ioc_hits", []):
            if not isinstance(hit, dict):
                continue
            encoded = json.dumps(hit, sort_keys=True, ensure_ascii=False)
            if encoded not in seen:
                answer.append(hit)
                seen.add(encoded)
    return answer


def safe_host(value):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return cleaned or "unknown"


def atomic_json(path, document):
    target = pathlib.Path(path)
    temporary = target.with_name(f".{target.name}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    os.replace(temporary, target)


queue = load_json(input_path)
if not isinstance(queue, list):
    raise SystemExit("ERROR: enriched_queue.json must contain a JSON array")

prior_by_alert, individual_paths = previous_tickets(tickets_dir)
groups = temporal_groups(queue)
incident_tickets = []
grouped_ids = set()
rows = []

for host, records in groups:
    times = [item[0] for item in records]
    alerts = [item[1] for item in records]
    alert_ids = [str(alert["alert_id"]) for alert in alerts]
    grouped_ids.update(alert_ids)
    start = iso_time(min(times))
    end = iso_time(max(times))
    confidence = "high_confidence" if len(alerts) >= 3 else "medium_confidence"
    max_priority = max(priority(alert) for alert in alerts)
    levels = {criticality(alert) for alert in alerts}
    prior_true_positive = any(
        ticket.get("classification") == "true_positive"
        for alert_id in alert_ids
        for ticket in prior_by_alert.get(alert_id, [])
    )

    if prior_true_positive or max_priority >= 5:
        classification = "true_positive"
    else:
        classification = "escalated"

    must_escalate = (
        confidence == "high_confidence"
        and bool(levels.intersection({"critical", "high"}))
    )
    action = "escalate_tier2" if must_escalate else "monitor"
    techniques = unique_strings(
        technique
        for alert in alerts
        for technique in alert.get("attack_techniques", [])
    )
    justification = (
        f"Correlated {len(alerts)} alerts on hostname={host!r} within "
        f"incident_window={start!r}..{end!r}; confidence={confidence!r}, "
        f"highest priority_score={max_priority:g}, asset criticalities="
        f"{sorted(levels)!r}, previous_true_positive={prior_true_positive}."
    )
    ticket = {
        "ticket_id": f"incident_{safe_host(host)}_{start}",
        "classification": classification,
        "justification": justification,
        "evidence_refs": evidence_refs(alerts),
        "ioc_hits": combined_iocs(alerts),
        "attack_techniques": techniques,
        "recommended_action": action,
        "analyst_time_seconds": 300,
        "created_at": start,
        "contributing_alerts": alert_ids,
        "incident_window": {"start": start, "end": end},
        "confidence": confidence,
        "highest_priority_score": max_priority,
        "hostname": host,
    }
    incident_tickets.append(ticket)
    rows.append((ticket["ticket_id"], len(alerts), confidence, action))

incident_tickets.sort(key=lambda item: (item["incident_window"]["start"], item["hostname"]))
atomic_json(output_path, incident_tickets)

for path in individual_paths:
    document = load_json(path)
    changed = False
    for ticket in document:
        if not isinstance(ticket, dict):
            continue
        if str(ticket.get("alert_id")) in grouped_ids and ticket.get("grouped") is not True:
            ticket["grouped"] = True
            changed = True
    if changed:
        atomic_json(path, document)

print("batch 6 correlated incidents")
for ticket_id, count, confidence, action in rows:
    shown = "escalate" if action == "escalate_tier2" else action
    print(f"  {ticket_id:<52} alerts={count:<2d} {confidence:<18} {shown}")
print(f"incidents assembled      : {len(incident_tickets)}")
print(f"alerts regrouped         : {len(grouped_ids)}")
print(output_path)
PY
