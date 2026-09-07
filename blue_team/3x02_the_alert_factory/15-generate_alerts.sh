#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
RULES_DIR="${RULES_DIR:-$SCRIPT_DIR/rules/sigma}"
RUNNER="${SIGMA_RUNNER:-$SCRIPT_DIR/3-sigma_runner.sh}"
PRIORITY_FILE="${RULE_PRIORITIZATION_FILE:-$SCRIPT_DIR/rule_prioritization.json}"
SUMMARY_FILE="$BASELINE_PKG/baselines/baseline_summary.json"
EVIDENCE_FILE="$HANDOFF_DIR/data/normalized_events.json"
ASSET_FILE="$HANDOFF_DIR/context/asset_inventory.json"
QUEUE_FILE="${ALERT_QUEUE_FILE:-$SCRIPT_DIR/alert_queue.json}"
SCHEMA_FILE="${ALERT_SCHEMA_FILE:-$SCRIPT_DIR/alert_queue_schema.json}"

for dependency in \
    "$RUNNER" "$PRIORITY_FILE" "$SUMMARY_FILE" "$EVIDENCE_FILE" "$ASSET_FILE"; do
    [[ -r "$dependency" ]] || {
        printf 'ERROR: required dependency is not readable: %s\n' "$dependency" >&2
        exit 1
    }
done

[[ -x "$RUNNER" ]] || {
    printf 'ERROR: Sigma runner is not executable: %s\n' "$RUNNER" >&2
    exit 1
}

python3 -W error /dev/fd/3 \
    "$RULES_DIR" "$RUNNER" "$PRIORITY_FILE" "$SUMMARY_FILE" \
    "$EVIDENCE_FILE" "$ASSET_FILE" "$QUEUE_FILE" "$SCHEMA_FILE" 3<<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import uuid

import yaml


def load_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def utc_text(value):
    parsed = parse_time(value)
    if parsed is None:
        raise ValueError(f"invalid ISO 8601 timestamp: {value}")
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def boundary(document, paths):
    for path in paths:
        value = document
        for key in path:
            if not isinstance(value, dict) or key not in value:
                break
            value = value[key]
        else:
            if isinstance(value, str) and value:
                return value
    raise ValueError("evaluation window boundary missing from baseline_summary.json")


def active_rules(root):
    root = pathlib.Path(root)
    originals = sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml"))
    tuned_root = root / "tuned"
    tuned = []
    if tuned_root.is_dir():
        tuned = sorted(tuned_root.glob("*.yml")) + sorted(tuned_root.glob("*.yaml"))

    def number(path):
        match = re.match(r"^(\d{3})_", path.name)
        return match.group(1) if match else path.stem

    selected = {number(path): path for path in originals}
    for path in tuned:
        selected[number(path)] = path

    answer = []
    for rule_number, path in sorted(selected.items()):
        with path.open("r", encoding="utf-8") as stream:
            rule = yaml.safe_load(stream)
        if str(rule.get("status", "")).casefold() in {"deprecated", "unsupported"}:
            continue
        answer.append((rule_number, path, rule))
    return answer


def walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def asset_context(document, event):
    hostname = str(event.get("hostname") or event.get("host") or "").casefold()
    addresses = {
        str(event.get(name)).casefold()
        for name in ("asset_id", "src_ip", "dst_ip")
        if event.get(name) not in (None, "")
    }
    for record in walk(document):
        record_hosts = {
            str(record.get(name)).casefold()
            for name in ("hostname", "host", "asset", "asset_id", "name")
            if record.get(name) not in (None, "")
        }
        record_addresses = {
            str(record.get(name)).casefold()
            for name in ("ip", "ip_address", "address", "asset_id")
            if record.get(name) not in (None, "")
        }
        if (hostname and hostname in record_hosts) or (addresses & record_addresses):
            return record
    return None


def event_reference(event, line_number):
    explicit = event.get("event_ref") or event.get("event_uuid")
    if explicit:
        return str(explicit)
    return f'{event.get("source_type", "unknown")}:{event.get("event_id")}:line:{line_number}'


def event_records(path, wanted):
    found = {}
    with open(path, "r", encoding="utf-8") as stream:
        first = ""
        while True:
            character = stream.read(1)
            if not character:
                return found
            if not character.isspace():
                first = character
                break
        stream.seek(0)
        if first == "[":
            document = json.load(stream)
            iterable = (
                (number, event, json.dumps(event, separators=(",", ":"), ensure_ascii=False))
                for number, event in enumerate(document, start=1)
                if isinstance(event, dict)
            )
        else:
            def ndjson():
                for number, line in enumerate(stream, start=1):
                    raw = line.rstrip("\r\n")
                    if not raw.strip():
                        continue
                    try:
                        event = json.loads(raw)
                    except json.JSONDecodeError as error:
                        raise ValueError(
                            f"invalid normalized NDJSON at line {number}: {error}"
                        ) from error
                    if isinstance(event, dict):
                        yield number, event, raw
            iterable = ndjson()

        for number, event, raw in iterable:
            reference = event_reference(event, number)
            if reference in wanted:
                found[reference] = {
                    "event": event,
                    "hash": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                }
                if len(found) == len(wanted):
                    break
    return found


def attack_techniques(rule):
    answer = []
    for tag in rule.get("tags", []):
        match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag), re.I)
        if match:
            answer.append(match.group(1).upper())
    return sorted(set(answer))


def summary(event):
    return {
        name: event.get(name)
        for name in (
            "timestamp", "hostname", "user", "src_ip", "dst_ip",
            "process_name", "canonical_label", "event_category",
        )
    }


def schema_document():
    nullable_string = {"type": ["string", "null"]}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://meddefense.local/schemas/alert_queue_schema.json",
        "title": "MedDefense Alert Queue",
        "description": "Locked input contract for the 3x03 Tier 1 triage queue.",
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "alert_id", "generated_at", "rule_id", "rule_title",
                "rule_level", "priority_score", "event_ref", "event_summary",
                "asset_context", "attack_techniques", "status", "evidence_hash",
            ],
            "properties": {
                "alert_id": {"type": "string", "format": "uuid"},
                "generated_at": {"type": "string", "format": "date-time"},
                "rule_id": {"type": "string", "format": "uuid"},
                "rule_title": {"type": "string"},
                "rule_level": {
                    "enum": ["informational", "low", "medium", "high", "critical"]
                },
                "priority_score": {"type": "number", "minimum": 0},
                "event_ref": {"type": "string", "minLength": 1},
                "event_summary": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "timestamp", "hostname", "user", "src_ip", "dst_ip",
                        "process_name", "canonical_label", "event_category",
                    ],
                    "properties": {
                        name: dict(nullable_string)
                        for name in (
                            "timestamp", "hostname", "user", "src_ip", "dst_ip",
                            "process_name", "canonical_label", "event_category",
                        )
                    },
                },
                "asset_context": {"type": ["object", "null"]},
                "attack_techniques": {
                    "type": "array",
                    "items": {"type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"},
                    "uniqueItems": True,
                },
                "status": {"const": "new"},
                "evidence_hash": {
                    "type": "string", "pattern": "^[a-f0-9]{64}$"
                },
            },
        },
    }


rules_dir, runner, priority_path, summary_path, evidence_path, asset_path, queue_path, schema_path = sys.argv[1:]
rules = active_rules(rules_dir)
if not rules:
    raise SystemExit("ERROR: no active Sigma rules found")

priority_document = load_json(priority_path)
priority_entries = (
    priority_document
    if isinstance(priority_document, list)
    else priority_document.get("rules", [])
)
priority = {
    str(item["rule_id"]): float(item.get("priority_score", 0))
    for item in priority_entries
    if isinstance(item, dict) and item.get("rule_id")
}

summary_input = load_json(summary_path)
window_start = boundary(summary_input, (
    ("evaluation_window_start",), ("evaluation_window", "start"),
    ("evaluation", "window_start"), ("evaluation", "start"),
    ("eval_window_start",), ("windows", "evaluation", "start"),
))
window_end = boundary(summary_input, (
    ("evaluation_window_end",), ("evaluation_window", "end"),
    ("evaluation", "window_end"), ("evaluation", "end"),
    ("eval_window_end",), ("windows", "evaluation", "end"),
))
generated_at = utc_text(window_end)

raw_matches = []
rule_metadata = {}
for rule_number, path, rule in rules:
    rule_id = str(rule["id"])
    if rule_id not in priority:
        raise SystemExit(f"ERROR: priority score missing for rule {rule_id}")
    execution = subprocess.run(
        [runner, str(path), "--window", f"{window_start},{window_end}"],
        check=True, capture_output=True, text=True,
    )
    result = json.loads(execution.stdout)
    rule_metadata[rule_id] = {
        "number": rule_number,
        "title": str(rule["title"]),
        "level": str(rule["level"]),
        "techniques": attack_techniques(rule),
    }
    for match in result.get("matches", []):
        if isinstance(match, dict) and match.get("event_ref"):
            raw_matches.append((rule_id, str(match["event_ref"])))

wanted_refs = {reference for _, reference in raw_matches}
records = event_records(evidence_path, wanted_refs)
missing = sorted(wanted_refs - set(records))
if missing:
    raise SystemExit(
        f"ERROR: {len(missing)} matched event references were not found in normalized evidence"
    )

assets = load_json(asset_path)
alerts = []
for rule_id, reference in raw_matches:
    metadata = rule_metadata[rule_id]
    record = records[reference]
    event = record["event"]
    alerts.append({
        "alert_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{rule_id}+{reference}")),
        "generated_at": generated_at,
        "rule_id": rule_id,
        "rule_title": metadata["title"],
        "rule_level": metadata["level"],
        "priority_score": round(priority[rule_id], 4),
        "event_ref": reference,
        "event_summary": summary(event),
        "asset_context": asset_context(assets, event),
        "attack_techniques": metadata["techniques"],
        "status": "new",
        "evidence_hash": record["hash"],
        "_number": metadata["number"],
    })

alerts.sort(key=lambda item: (
    item["rule_id"],
    str(item["event_summary"].get("hostname") or ""),
    str(item["event_summary"].get("user") or ""),
    str(item["event_summary"].get("timestamp") or ""),
    item["event_ref"],
))

deduplicated = []
last_by_key = {}
for alert in alerts:
    event_time = parse_time(alert["event_summary"].get("timestamp"))
    key = (
        alert["rule_id"],
        alert["event_summary"].get("hostname"),
        alert["event_summary"].get("user"),
    )
    previous = last_by_key.get(key)
    if event_time is not None and previous is not None:
        if (event_time - previous).total_seconds() <= 60:
            continue
    deduplicated.append(alert)
    if event_time is not None:
        last_by_key[key] = event_time

deduplicated.sort(key=lambda item: (
    -item["priority_score"],
    str(item["event_summary"].get("timestamp") or "9999"),
    item["alert_id"],
))

serializable = [
    {key: value for key, value in alert.items() if key != "_number"}
    for alert in deduplicated
]
with open(queue_path, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(serializable, stream, indent=2, ensure_ascii=False)
    stream.write("\n")
with open(schema_path, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(schema_document(), stream, indent=2, ensure_ascii=False)
    stream.write("\n")

print(f"rules executed            : {len(rules)}")
print(f"raw matches               : {len(raw_matches)}")
print(f"after deduplication       : {len(deduplicated)}")
print("top 5 alerts")
for position, alert in enumerate(deduplicated[:5], start=1):
    host = alert["event_summary"].get("hostname") or "unknown"
    short = re.sub(r"[^a-z0-9]+", "_", alert["rule_title"].casefold()).strip("_")
    print(
        f'{position:2d}  {alert["priority_score"]:5.1f}  '
        f'{alert["rule_level"]:<8}  {alert["_number"]} {short[:32]:<32}  {host}'
    )
print(f"alert_queue.json        : {len(deduplicated)} alerts")
print("alert_queue_schema.json : written")
PY
