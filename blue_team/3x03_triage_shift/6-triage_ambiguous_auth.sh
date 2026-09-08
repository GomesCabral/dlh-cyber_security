#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
INPUT_FILE="${ENRICHED_QUEUE_FILE:-$SCRIPT_DIR/enriched_queue.json}"
BASELINE_FILE="$BASELINE_PKG/baselines/baseline_summary.json"
EVENT_FILE="$HANDOFF_DIR/data/enriched_events.json"
TICKETS_DIR="${TICKETS_DIR:-$SCRIPT_DIR/tickets}"
OUTPUT_FILE="$TICKETS_DIR/batch4_auth.json"

for dependency in "$INPUT_FILE" "$BASELINE_FILE" "$EVENT_FILE"; do
    [[ -r "$dependency" ]] || {
        printf 'ERROR: required input is not readable: %s\n' "$dependency" >&2
        exit 1
    }
done
mkdir -p "$TICKETS_DIR"

python3 -W error /dev/fd/3 \
    "$INPUT_FILE" "$BASELINE_FILE" "$EVENT_FILE" \
    "$TICKETS_DIR" "$OUTPUT_FILE" 3<<'PY'
import collections
import datetime as dt
import ipaddress
import json
import os
import pathlib
import re
import sys
import uuid

input_path, baseline_path, event_path, tickets_dir, output_path = sys.argv[1:]


def load_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def text(value):
    return str(value).strip().casefold() if value not in (None, "") else ""


def walk(node, path=()):
    if isinstance(node, dict):
        yield path, node
        for key, value in node.items():
            yield from walk(value, path + (str(key),))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, path + (str(index),))


def scalars(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from scalars(value, path + (str(key),))
    elif isinstance(node, list):
        for value in node:
            yield from scalars(value, path)
    else:
        yield path, node


def event_value(alert, *names):
    event = alert.get("event_record") if isinstance(alert.get("event_record"), dict) else {}
    summary = alert.get("event_summary") if isinstance(alert.get("event_summary"), dict) else {}
    for name in names:
        if event.get(name) not in (None, ""):
            return event[name]
        if summary.get(name) not in (None, ""):
            return summary[name]
    return None


def is_auth_alert(alert):
    combined = " ".join((
        text(alert.get("rule_category")),
        text(alert.get("rule_title")),
        text(event_value(alert, "event_category", "canonical_label")),
    ))
    return any(word in combined for word in ("auth", "login", "logon", "credential"))


def handled_ids(folder):
    answer = set()
    for path in sorted(pathlib.Path(folder).glob("batch[1-3]_*.json")):
        try:
            document = load_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(document, list):
            answer.update(
                str(ticket["alert_id"])
                for ticket in document
                if isinstance(ticket, dict) and ticket.get("alert_id")
            )
    return answer


def user_scopes(document, username):
    wanted = text(username)
    answer = []
    seen = set()
    for path, node in walk(document):
        keyed = any(text(part) == wanted for part in path)
        named = any(
            text(node.get(field)) == wanted
            for field in ("user", "username", "account", "account_name")
        )
        if keyed or named:
            encoded = json.dumps(node, sort_keys=True, ensure_ascii=False)
            if encoded not in seen:
                answer.append(node)
                seen.add(encoded)
    return answer


def historical_pattern(document, username):
    source_ips = set()
    hosts = set()
    login_times = set()
    maxima = []
    for scope in user_scopes(document, username):
        for path, value in scalars(scope):
            key = ".".join(path).casefold()
            if value in (None, ""):
                continue
            if "max_failures_1h_window" in key and isinstance(value, (int, float)):
                maxima.append(float(value))
            if "host" in key and isinstance(value, str):
                hosts.add(value)
            if ("source" in key or "src" in key) and "ip" in key and isinstance(value, str):
                try:
                    source_ips.add(str(ipaddress.ip_address(value)))
                except ValueError:
                    pass
            if ("login" in key or "logon" in key) and ("time" in key or "hour" in key):
                login_times.add(str(value))
    return {
        "user": username,
        "login_times": sorted(login_times),
        "source_ips": sorted(source_ips),
        "hosts": sorted(hosts),
        "max_failures_1h_window": max(maxima) if maxima else None,
    }


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


def is_auth_event(event):
    combined = " ".join((
        text(event.get("event_category")),
        text(event.get("canonical_label")),
        text(event.get("event_action")),
    ))
    return (
        any(word in combined for word in ("auth", "login", "logon"))
        or event.get("event_id") in (4624, 4625, 4672)
    )


def recent_events(path, users):
    recent = {user: collections.deque(maxlen=20) for user in users}
    with open(path, "r", encoding="utf-8") as stream:
        first = stream.read(1)
        stream.seek(0)
        if first == "[":
            records = enumerate(load_json(path), start=1)
        else:
            def ndjson():
                for number, line in enumerate(stream, start=1):
                    if not line.strip():
                        continue
                    try:
                        yield number, json.loads(line)
                    except json.JSONDecodeError as error:
                        raise ValueError(
                            f"invalid enriched NDJSON line {number}: {error}"
                        ) from error
            records = ndjson()
        for number, event in records:
            if not isinstance(event, dict) or not is_auth_event(event):
                continue
            user = text(event.get("user") or event.get("username"))
            if user in recent:
                item = dict(event)
                item["event_ref"] = str(
                    event.get("event_ref")
                    or event.get("event_uuid")
                    or f"{path}:{number}"
                )
                recent[user].append(item)
    return {user: list(records) for user, records in recent.items()}


def failed(event):
    return (
        text(event.get("outcome")) in {"failure", "failed"}
        or "failure" in text(event.get("canonical_label"))
        or event.get("event_id") == 4625
    )


def failure_burst(alert, history):
    explicit = event_value(alert, "failure_count", "failed_count", "match_count", "event_count")
    if isinstance(explicit, (int, float)):
        return int(explicit)
    end = parse_time(event_value(alert, "timestamp"))
    if end is None:
        return sum(1 for event in history if failed(event))
    start = end - dt.timedelta(hours=1)
    return sum(
        1 for event in history
        if failed(event)
        and (event_time := parse_time(event.get("timestamp"))) is not None
        and start <= event_time <= end
    )


def asset_level(alert):
    asset = alert.get("asset") if isinstance(alert.get("asset"), dict) else {}
    return text(asset.get("criticality") or asset.get("asset_criticality")) or "unknown"


def decide(alert, pattern, history):
    source = str(event_value(alert, "src_ip", "source_ip") or "unknown")
    host = str(event_value(alert, "hostname", "host") or "unknown")
    known_ips = set(pattern["source_ips"])
    known_hosts = {text(item) for item in pattern["hosts"]}
    unknown_ip = bool(known_ips) and source not in known_ips
    never_host = bool(known_hosts) and text(host) not in known_hosts
    level = asset_level(alert)
    burst = failure_burst(alert, history)
    maximum = pattern["max_failures_1h_window"]
    ioc_count = len(alert.get("ioc_hits") or [])
    checked = (
        f"src_ip={source!r}, baseline.source_ips={sorted(known_ips)!r}, "
        f"hostname={host!r}, baseline.hosts={pattern['hosts']!r}, "
        f"asset.criticality={level!r}, failure_burst={burst}, "
        f"baseline.max_failures_1h_window={maximum!r}, ioc_hit_count={ioc_count}"
    )
    if unknown_ip and level in {"critical", "high"} and never_host:
        return "true_positive", "escalate_tier2", None, (
            f"Unknown source and new host on a high-value asset: {checked}."
        )
    if unknown_ip and level in {"medium", "low"} and ioc_count == 0:
        return "false_positive", "tune_rule", "unknown_ip_low_asset", (
            f"Unknown source on a lower-value asset with no IOC hit: {checked}."
        )
    if (
        source in known_ips and isinstance(maximum, (int, float))
        and maximum <= burst <= maximum * 2
    ):
        return "false_positive", "tune_rule", "baseline_edge_burst", (
            f"Known source produced a burst at the baseline edge: {checked}."
        )
    return "true_positive", "monitor", None, (
        f"Ambiguous authentication remains unresolved after checking {checked}; "
        "monitor for additional evidence."
    )


def created_at(alert):
    parsed = parse_time(alert.get("generated_at") or event_value(alert, "timestamp"))
    return (
        parsed.isoformat(timespec="seconds").replace("+00:00", "Z")
        if parsed else "1970-01-01T00:00:00Z"
    )


queue = load_json(input_path)
baseline = load_json(baseline_path)
if not isinstance(queue, list):
    raise SystemExit("ERROR: enriched_queue.json must contain a JSON array")

handled = handled_ids(tickets_dir)
alerts = [
    alert for alert in queue
    if isinstance(alert, dict)
    and is_auth_alert(alert)
    and str(alert.get("alert_id")) not in handled
]
users = {text(event_value(alert, "user", "username")) for alert in alerts} - {""}
history = recent_events(event_path, users)
patterns = {user: historical_pattern(baseline, user) for user in users}

tickets = []
rows = []
for alert in alerts:
    user = text(event_value(alert, "user", "username"))
    pattern = patterns.get(user, historical_pattern({}, user))
    recent = history.get(user, [])
    classification, action, reason, justification = decide(alert, pattern, recent)
    alert_id = str(alert.get("alert_id"))
    evidence = [str(alert.get("event_ref"))]
    evidence.extend(
        event["event_ref"] for event in recent
        if event.get("event_ref") and event["event_ref"] not in evidence
    )
    ticket = {
        "ticket_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"ticket:{alert_id}")),
        "alert_id": alert_id,
        "classification": classification,
        "justification": justification,
        "evidence_refs": evidence,
        "ioc_hits": alert.get("ioc_hits", []),
        "attack_techniques": alert.get("attack_techniques", []),
        "recommended_action": action,
        "analyst_time_seconds": int(alert.get("analyst_time_seconds") or 300),
        "created_at": created_at(alert),
        "historical_login_pattern": pattern,
        "last_20_auth_events": recent,
    }
    if reason:
        ticket["fp_reason"] = reason
    tickets.append(ticket)
    rows.append((alert_id, str(alert.get("rule_title") or "unknown"), classification, action))

tickets.sort(key=lambda item: (item["created_at"], item["alert_id"]))
output = pathlib.Path(output_path)
temporary = output.with_name(f".{output.name}.tmp")
with temporary.open("w", encoding="utf-8") as stream:
    json.dump(tickets, stream, indent=2, ensure_ascii=False)
    stream.write("\n")
os.replace(temporary, output)

print("batch 4 ambiguous authentication")
for alert_id, title, classification, action in rows:
    shown_action = "escalate" if action == "escalate_tier2" else action
    print(f"  {alert_id[:14]:<14}  {title[:34]:<34}  {classification:<16} {shown_action}")
print(f"batch size               : {len(tickets)}")
print(f"tickets written          : {len(tickets)}")
print(output_path)
PY
