#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
QUEUE="${ENRICHED_QUEUE_FILE:-$SCRIPT_DIR/enriched_queue.json}"
EVENTS="$HANDOFF_DIR/data/enriched_events.json"
ASSETS="$HANDOFF_DIR/context/asset_inventory.json"
TICKETS="${TICKETS_DIR:-$SCRIPT_DIR/tickets}"
OUTPUT="${INCIDENTS_FILE:-$SCRIPT_DIR/incidents.json}"

for file in "$QUEUE" "$EVENTS" "$ASSETS"; do
    [[ -r "$file" ]] || {
        printf 'ERROR: required input is not readable: %s\n' "$file" >&2
        exit 1
    }
done
[[ -d "$TICKETS" ]] || {
    printf 'ERROR: tickets directory does not exist: %s\n' "$TICKETS" >&2
    exit 1
}

python3 -W error /dev/fd/3 \
    "$QUEUE" "$EVENTS" "$ASSETS" "$TICKETS" "$OUTPUT" 3<<'PY'
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import sys

queue_path, event_path, asset_path, tickets_path, output_path = sys.argv[1:]


def load(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def text(value):
    return str(value).strip().casefold() if value not in (None, "") else ""


def time_value(value):
    if not isinstance(value, str):
        return None
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=dt.timezone.utc)
    return result.astimezone(dt.timezone.utc)


def walk(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            child = path + (str(key),)
            yield child, value
            yield from walk(value, child)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, path + (str(index),))


def read_tickets(folder):
    answer = []
    for path in sorted(pathlib.Path(folder).glob("batch[1-7]_*.json")):
        document = load(path)
        if not isinstance(document, list):
            raise SystemExit(f"ERROR: ticket file is not an array: {path}")
        answer.extend((path.name, item) for item in document if isinstance(item, dict))
    return answer


def reference_line(reference):
    value = str(reference)
    match = re.search(r":line:(\d+)$", value)
    if not match and ("/" in value or "\\" in value):
        match = re.search(r":(\d+)$", value)
    return int(match.group(1)) if match else None


def resolve(path, references):
    by_line = {}
    unresolved = set(references)
    for reference in references:
        number = reference_line(reference)
        if number is not None:
            by_line.setdefault(number, []).append(reference)
    found = {}
    with open(path, "r", encoding="utf-8") as stream:
        first = stream.read(1)
        stream.seek(0)
        if first == "[":
            records = enumerate(load(path), start=1)
        else:
            def ndjson():
                for number, line in enumerate(stream, start=1):
                    if not line.strip():
                        continue
                    try:
                        yield number, json.loads(line)
                    except json.JSONDecodeError as error:
                        raise ValueError(f"invalid event line {number}: {error}") from error
            records = ndjson()
        for number, event in records:
            if not isinstance(event, dict):
                continue
            for reference in by_line.get(number, []):
                found[reference] = event
                unresolved.discard(reference)
            explicit = event.get("event_ref") or event.get("event_uuid")
            if explicit and str(explicit) in unresolved:
                found[str(explicit)] = event
                unresolved.discard(str(explicit))
            if not unresolved:
                break
    return found


def asset_records(document):
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if isinstance(document, dict):
        for key in ("assets", "inventory", "records", "hosts"):
            value = document.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def assets_by_host(document):
    answer = {}
    for record in asset_records(document):
        for field in ("hostname", "host", "name", "asset_id"):
            if text(record.get(field)):
                answer[text(record[field])] = record
    return answer


def event_description(event):
    label = event.get("canonical_label") or event.get("event_action") or event.get("event_category")
    details = [str(label or "security event")]
    for field in ("process_name", "src_ip", "dst_ip", "user"):
        if event.get(field) not in (None, ""):
            details.append(f"{field}={event[field]}")
    return "; ".join(details) + "."


def extract_iocs(events):
    result = set()
    groups = {
        "ip": {"src_ip", "dst_ip", "source_ip", "destination_ip"},
        "domain": {"domain", "dst_host", "destination_host", "query_name"},
        "user_account": {"user", "username", "account", "account_name"},
        "process_name": {"process_name", "parent_process", "parent_process_name", "image"},
    }
    for event in events:
        for path, value in walk(event):
            if not path or not isinstance(value, str) or not value:
                continue
            field = path[-1].casefold()
            for kind, fields in groups.items():
                if field not in fields:
                    continue
                normalized = re.split(r"[/\\]", value)[-1] if kind == "process_name" else value
                if kind == "ip":
                    try:
                        normalized = str(ipaddress.ip_address(value))
                    except ValueError:
                        continue
                result.add((kind, normalized))
    return [{"type": kind, "value": value} for kind, value in sorted(result)]


def containment(title, events, ticket):
    categories = " ".join(
        text(category)
        for hit in ticket.get("ioc_hits", []) if isinstance(hit, dict)
        for category in hit.get("categories", [])
    )
    combined = f"{text(title)} {categories}"
    malicious_destination = any(
        text(hit.get("reputation")) == "malicious"
        for hit in ticket.get("ioc_hits", []) if isinstance(hit, dict)
    ) and any(event.get("dst_ip") or event.get("dst_host") for event in events)
    if "ssh" in combined or "brute" in combined:
        return "block_source_ip"
    if "egress" in combined or "exfil" in combined or malicious_destination:
        return "block_ip_at_egress"
    if any(word in combined for word in ("credential", "login", "logon", "patient data")):
        return "disable_account"
    return "isolate_host"


queue = load(queue_path)
tickets = read_tickets(tickets_path)
if not isinstance(queue, list):
    raise SystemExit("ERROR: enriched_queue.json must contain an array")
alerts = {
    str(alert["alert_id"]): alert for alert in queue
    if isinstance(alert, dict) and alert.get("alert_id")
}
selected = [
    (source, ticket) for source, ticket in tickets
    if ticket.get("classification") == "true_positive"
    and ticket.get("recommended_action") in {"escalate_tier2", "monitor"}
]
references = {
    str(reference) for _, ticket in selected
    for reference in ticket.get("evidence_refs", [])
    if isinstance(reference, str)
}
resolved = {}
for alert in queue:
    if isinstance(alert, dict) and isinstance(alert.get("event_record"), dict):
        if alert.get("event_ref"):
            resolved[str(alert["event_ref"])] = alert["event_record"]
for _, ticket in tickets:
    for event in ticket.get("last_20_auth_events", []):
        if isinstance(event, dict) and event.get("event_ref"):
            resolved[str(event["event_ref"])] = event
missing = references - set(resolved)
if missing:
    resolved.update(resolve(event_path, missing))

asset_index = assets_by_host(load(asset_path))
incidents = []
keys = []
for source, ticket in sorted(selected, key=lambda item: str(item[1].get("ticket_id"))):
    ids = []
    if ticket.get("alert_id"):
        ids.append(str(ticket["alert_id"]))
    ids.extend(str(value) for value in ticket.get("contributing_alerts", []))
    related_alerts = [alerts[value] for value in dict.fromkeys(ids) if value in alerts]
    refs = [str(value) for value in ticket.get("evidence_refs", []) if isinstance(value, str)]
    event_list = []
    seen = set()
    for reference in refs:
        if reference not in resolved:
            continue
        encoded = json.dumps(resolved[reference], sort_keys=True, ensure_ascii=False)
        if encoded not in seen:
            event_list.append(resolved[reference])
            seen.add(encoded)

    titles = [str(alert["rule_title"]) for alert in related_alerts if alert.get("rule_title")]
    title = titles[0] if titles else str(ticket.get("rule_title") or "security_alert")
    hosts = {
        str(event.get("hostname") or event.get("host")) for event in event_list
        if event.get("hostname") or event.get("host")
    }
    for alert in related_alerts:
        summary = alert.get("event_summary")
        if isinstance(summary, dict) and summary.get("hostname"):
            hosts.add(str(summary["hostname"]))
    if ticket.get("hostname"):
        hosts.add(str(ticket["hostname"]))
    main_host = sorted(hosts)[0] if hosts else "unknown"

    timeline = [{
        "timestamp": event.get("timestamp"),
        "hostname": event.get("hostname") or event.get("host"),
        "event_category": event.get("event_category"),
        "description": event_description(event),
    } for event in event_list]
    timeline.sort(key=lambda item: (item["timestamp"] or "", item["hostname"] or ""))
    affected = []
    for host in sorted(hosts):
        record = asset_index.get(text(host), {})
        affected.append({
            "hostname": host,
            "criticality": record.get("criticality") or record.get("asset_criticality") or "unknown",
            "data_classification": record.get("data_classification") or record.get("data_sensitivity") or "unknown",
            "network_zone": record.get("network_zone") or record.get("zone") or "unknown",
        })
    iocs = extract_iocs(event_list)
    techniques = sorted({
        str(value) for value in ticket.get("attack_techniques", [])
        if value not in (None, "")
    }.union(
        str(value) for alert in related_alerts
        for value in alert.get("attack_techniques", [])
    ))
    date_value = timeline[0]["timestamp"] if timeline else ticket.get("created_at")
    parsed = time_value(date_value)
    date_part = parsed.strftime("%Y%m%d") if parsed else "19700101"
    digest = hashlib.sha256(str(ticket.get("ticket_id")).encode("utf-8")).hexdigest()[:8].upper()
    incident = {
        "incident_id": f"INC-{date_part}-{digest}",
        "source_ticket_id": ticket.get("ticket_id"),
        "source_ticket_file": source,
        "summary": f"{title} detected on {main_host}.",
        "timeline": timeline,
        "affected_assets": affected,
        "iocs": iocs,
        "attack_techniques": techniques,
        "recommended_containment": containment(title, event_list, ticket),
        "related_incidents": [],
    }
    incidents.append(incident)
    keys.append({
        "hosts": {text(host) for host in hosts},
        "iocs": {(item["type"], text(item["value"])) for item in iocs},
    })

for index, incident in enumerate(incidents):
    incident["related_incidents"] = sorted(
        other["incident_id"] for other_index, other in enumerate(incidents)
        if other_index != index and (
            keys[index]["hosts"] & keys[other_index]["hosts"]
            or keys[index]["iocs"] & keys[other_index]["iocs"]
        )
    )

incidents.sort(key=lambda item: item["incident_id"])
target = pathlib.Path(output_path)
temporary = target.with_name(f".{target.name}.tmp")
with temporary.open("w", encoding="utf-8") as stream:
    json.dump(incidents, stream, indent=2, ensure_ascii=False)
    stream.write("\n")
os.replace(temporary, target)

print("incidents assembled")
for incident in incidents:
    host = incident["affected_assets"][0]["hostname"] if incident["affected_assets"] else "unknown"
    print(
        f"  {incident['incident_id']:<22} {host[:18]:<18} "
        f"{incident['summary'][:32]:<32} {incident['recommended_containment']}"
    )
print(f"total incidents         : {len(incidents)}")
print(f"{target.name} written")
PY
