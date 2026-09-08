#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INPUT_FILE="${ENRICHED_QUEUE_FILE:-$SCRIPT_DIR/enriched_queue.json}"
TICKETS_DIR="${TICKETS_DIR:-$SCRIPT_DIR/tickets}"
OUTPUT_FILE="$TICKETS_DIR/batch1_clearcut_tp.json"

[[ -r "$INPUT_FILE" ]] || {
    printf 'ERROR: required input is not readable: %s\n' "$INPUT_FILE" >&2
    exit 1
}

mkdir -p "$TICKETS_DIR"

python3 -W error /dev/fd/3 "$INPUT_FILE" "$OUTPUT_FILE" 3<<'PY'
import datetime as dt
import json
import os
import pathlib
import re
import sys
import uuid


input_path, output_path = sys.argv[1:]


def load_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def walk(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = path + (str(key),)
            yield child_path, value
            yield from walk(value, child_path)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, path + (str(index),))


def normalized_text(value):
    return str(value).strip().casefold() if value not in (None, "") else ""


def scalar_strings(node):
    values = set()
    for _, value in walk(node):
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            values.add(normalized_text(value))
            if isinstance(value, str):
                values.add(normalized_text(re.split(r"[/\\]", value)[-1]))
    return values


def source_category(alert):
    event = alert.get("event_record")
    event = event if isinstance(event, dict) else {}
    summary = alert.get("event_summary")
    summary = summary if isinstance(summary, dict) else {}
    raw = normalized_text(
        event.get("event_category")
        or summary.get("event_category")
        or alert.get("rule_category")
    )
    title = normalized_text(alert.get("rule_title"))
    combined = f"{raw} {title}"
    if any(term in combined for term in ("correlation", "chain", "sequence")):
        return "correlation"
    if any(term in combined for term in ("auth", "login", "logon", "credential")):
        return "auth"
    if any(term in combined for term in ("process", "execution", "interpreter", "tool")):
        return "process"
    if any(term in combined for term in ("network", "connection", "flow", "outbound", "smb")):
        return "network"
    if any(term in combined for term in ("file", "registry", "autorun")):
        return "file"
    return raw or "unknown"


def explicit_violation(alert):
    accepted_false = {
        "baseline_seen", "within_baseline", "baseline_match", "is_baseline",
    }
    accepted_true = {
        "baseline_violation", "violates_baseline", "is_anomaly", "anomalous",
    }
    for path, value in walk(alert):
        field = path[-1].casefold() if path else ""
        if field in accepted_false and value is False:
            return ".".join(path), value, "is false"
        if field in accepted_true and value is True:
            return ".".join(path), value, "is true"
        if field == "anomaly_type" and value not in (None, "", "none"):
            return ".".join(path), value, "identifies an anomaly"
    return None


def profile_slices(alert):
    profile = alert.get("baseline_host_profile")
    if not isinstance(profile, dict):
        return []
    slices = profile.get("slices")
    return slices if isinstance(slices, list) else [profile]


def event_value(alert, *names):
    event = alert.get("event_record")
    event = event if isinstance(event, dict) else {}
    summary = alert.get("event_summary")
    summary = summary if isinstance(summary, dict) else {}
    for name in names:
        if event.get(name) not in (None, ""):
            return event[name]
        if summary.get(name) not in (None, ""):
            return summary[name]
    return None


def linked_references(alert):
    references = []

    def add(value):
        if isinstance(value, str) and value and value not in references:
            references.append(value)
        elif isinstance(value, list):
            for item in value:
                add(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                if "ref" in str(key).casefold():
                    add(item)

    add(alert.get("event_ref"))
    for field in (
        "correlation_primitives", "linked_event_refs", "event_refs", "related_events"
    ):
        add(alert.get(field))
        event = alert.get("event_record")
        if isinstance(event, dict):
            add(event.get(field))
    return references


def baseline_violation(alert):
    explicit = explicit_violation(alert)
    if explicit:
        return explicit

    slices = profile_slices(alert)
    if not slices:
        return None
    known = scalar_strings(slices)
    category = source_category(alert)

    if category == "auth":
        user = event_value(alert, "user", "username", "account")
        if user and normalized_text(user) not in known:
            return "baseline_host_profile.known_users", user, "was not observed"
        source = event_value(alert, "src_ip", "source_ip")
        if source and normalized_text(source) not in known:
            return "baseline_host_profile.known_source_ips", source, "was not observed"

    if category == "process":
        process = event_value(alert, "process_name", "image", "process")
        process_name = (
            normalized_text(re.split(r"[/\\]", str(process))[-1]) if process else ""
        )
        if process_name and process_name not in known:
            return "baseline_host_profile.known_processes", process, "was not observed"

    if category == "network":
        destination = event_value(
            alert, "dst_ip", "destination_ip", "domain", "destination_domain"
        )
        if destination and normalized_text(destination) not in known:
            return (
                "baseline_host_profile.known_destinations",
                destination,
                "was not observed",
            )

    if category == "file":
        file_value = event_value(alert, "file_hash", "file_path", "registry_path")
        if file_value and normalized_text(file_value) not in known:
            return "baseline_host_profile.known_files", file_value, "was not observed"

    if category == "correlation":
        references = linked_references(alert)
        if len(references) > 1:
            return (
                "baseline_host_profile.correlation_primitives",
                len(references),
                "linked events exceed the single-event baseline",
            )
    return None


def malicious_hit(alert):
    hits = alert.get("ioc_hits")
    if not isinstance(hits, list):
        return None
    for hit in hits:
        if isinstance(hit, dict) and normalized_text(hit.get("reputation")) == "malicious":
            return hit
    return None


def created_at(alert):
    for value in (alert.get("generated_at"), event_value(alert, "timestamp")):
        if not isinstance(value, str):
            continue
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
    return "1970-01-01T00:00:00Z"


def ioc_category(hit):
    categories = hit.get("categories")
    if isinstance(categories, list) and categories:
        return ", ".join(str(item) for item in categories)
    return str(hit.get("category") or "malicious")


def ioc_indicator(hit):
    for field in ("indicator", "ioc", "value", "ip", "domain"):
        if hit.get(field) not in (None, ""):
            return str(hit[field])
    return "unknown indicator"


queue = load_json(input_path)
if not isinstance(queue, list):
    raise SystemExit("ERROR: enriched_queue.json must contain a JSON array")

tickets = []
summary_rows = []
for alert in queue:
    if not isinstance(alert, dict) or alert.get("priority_band") != "critical":
        continue
    hit = malicious_hit(alert)
    if hit is None:
        continue
    violation = baseline_violation(alert)
    if violation is None:
        continue

    baseline_field, observed_value, reason = violation
    category = ioc_category(hit)
    indicator = ioc_indicator(hit)
    alert_id = str(alert.get("alert_id"))
    justification = (
        f"IOC {indicator} has reputation=malicious and category={category}. "
        f"Baseline field {baseline_field} was violated because observed value "
        f"{observed_value!r} {reason}."
    )
    ticket = {
        "ticket_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"ticket:{alert_id}")),
        "alert_id": alert_id,
        "classification": "true_positive",
        "justification": justification,
        "evidence_refs": linked_references(alert),
        "ioc_hits": alert.get("ioc_hits", []),
        "attack_techniques": alert.get("attack_techniques", []),
        "recommended_action": "escalate_tier2",
        "analyst_time_seconds": int(alert.get("analyst_time_seconds") or 120),
        "created_at": created_at(alert),
    }
    tickets.append(ticket)
    summary = alert.get("event_summary")
    summary = summary if isinstance(summary, dict) else {}
    summary_rows.append((
        alert_id,
        str(alert.get("rule_title") or "unknown"),
        str(summary.get("hostname") or "unknown"),
    ))

tickets.sort(key=lambda item: (item["created_at"], item["alert_id"]))
output = pathlib.Path(output_path)
output.parent.mkdir(parents=True, exist_ok=True)
temporary = output.with_name(f".{output.name}.tmp")
with temporary.open("w", encoding="utf-8") as stream:
    json.dump(tickets, stream, indent=2, ensure_ascii=False)
    stream.write("\n")
os.replace(temporary, output)

print("batch 1 clear-cut true positives")
for alert_id, rule_title, hostname in summary_rows:
    print(
        f"  {alert_id[:14]:<14}  {rule_title[:32]:<32}  "
        f"{hostname[:18]:<18} malicious  ESCALATE"
    )
print(f"batch size               : {len(tickets)}")
print(f"tickets written          : {len(tickets)}")
print(output_path)
PY

