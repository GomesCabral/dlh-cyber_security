#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
QUEUE_FILE="$CATALOG_DIR/alerts/alert_queue.json"
SCHEMA_FILE="$CATALOG_DIR/alerts/alert_queue_schema.json"
OUTPUT_FILE="${QUEUE_ASSESSMENT_FILE:-$SCRIPT_DIR/queue_assessment.json}"

for dependency in "$QUEUE_FILE" "$SCHEMA_FILE"; do
    [[ -r "$dependency" ]] || {
        printf 'ERROR: required input is not readable: %s\n' "$dependency" >&2
        exit 1
    }
done

python3 -W error /dev/fd/3 \
    "$QUEUE_FILE" "$SCHEMA_FILE" "$CATALOG_DIR" "$OUTPUT_FILE" 3<<'PY'
import collections
import datetime as dt
import json
import os
import pathlib
import re
import sys
import uuid

try:
    import yaml
except ImportError:
    yaml = None


queue_path, schema_path, catalog_dir, output_path = sys.argv[1:]


def load_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def json_type_matches(value, expected):
    checks = {
        "array": lambda item: isinstance(item, list),
        "boolean": lambda item: isinstance(item, bool),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "null": lambda item: item is None,
        "number": lambda item: (
            isinstance(item, (int, float)) and not isinstance(item, bool)
        ),
        "object": lambda item: isinstance(item, dict),
        "string": lambda item: isinstance(item, str),
    }
    names = expected if isinstance(expected, list) else [expected]
    return any(name in checks and checks[name](value) for name in names)


def valid_format(value, format_name):
    if not isinstance(value, str):
        return False
    if format_name == "uuid":
        try:
            uuid.UUID(value)
        except (ValueError, AttributeError):
            return False
        return True
    if format_name == "date-time":
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
        return parsed.tzinfo is not None
    return True


def validate(value, schema, location="$"):
    errors = []
    if not isinstance(schema, dict):
        return [f"{location}: schema node is not an object"]

    expected_type = schema.get("type")
    if expected_type is not None and not json_type_matches(value, expected_type):
        return [f"{location}: expected type {expected_type}"]

    if "const" in schema and value != schema["const"]:
        errors.append(f"{location}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{location}: value is not in enum")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{location}: string is shorter than minLength")
        pattern = schema.get("pattern")
        if pattern and re.search(pattern, value) is None:
            errors.append(f"{location}: string does not match {pattern}")
        format_name = schema.get("format")
        if format_name and not valid_format(value, format_name):
            errors.append(f"{location}: invalid {format_name}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{location}: number is below minimum")

    if isinstance(value, list):
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{location}: array items are not unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(validate(item, item_schema, f"{location}[{index}]"))

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{location}: missing required field {name}")
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    errors.append(f"{location}.{name}: additional property")
        for name, child_schema in properties.items():
            if name in value:
                errors.extend(validate(value[name], child_schema, f"{location}.{name}"))
    return errors


def normalized_tactic(tag):
    value = str(tag).casefold()
    if not value.startswith("attack.") or re.fullmatch(
        r"attack\.t\d{4}(?:\.\d{3})?", value
    ):
        return None
    return value.removeprefix("attack.").replace("_", "-")


def rule_tactics(root):
    answer = collections.defaultdict(set)
    if yaml is None:
        return answer
    candidates = []
    for relative in ("rules/sigma", "rules"):
        folder = pathlib.Path(root) / relative
        if folder.is_dir():
            candidates.extend(folder.rglob("*.yml"))
            candidates.extend(folder.rglob("*.yaml"))
    for path in sorted(set(candidates)):
        try:
            with path.open("r", encoding="utf-8") as stream:
                rule = yaml.safe_load(stream)
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(rule, dict) or not rule.get("id"):
            continue
        for tag in rule.get("tags", []):
            tactic = normalized_tactic(tag)
            if tactic:
                answer[str(rule["id"])].add(tactic)
    return answer


technique_tactics = {
    "T1003": {"credential-access"},
    "T1012": {"discovery"},
    "T1021": {"lateral-movement"},
    "T1041": {"exfiltration"},
    "T1046": {"discovery"},
    "T1048": {"exfiltration"},
    "T1053": {"execution", "persistence", "privilege-escalation"},
    "T1059": {"execution"},
    "T1071": {"command-and-control"},
    "T1078": {
        "defense-evasion", "initial-access", "persistence",
        "privilege-escalation",
    },
    "T1082": {"discovery"},
    "T1087": {"discovery"},
    "T1095": {"command-and-control"},
    "T1110": {"credential-access"},
    "T1213": {"collection"},
    "T1547": {"persistence", "privilege-escalation"},
    "T1567": {"exfiltration"},
}


def fallback_tactics(techniques):
    answer = set()
    for technique in techniques:
        root = str(technique).upper().split(".", 1)[0]
        answer.update(technique_tactics.get(root, set()))
    return answer


queue = load_json(queue_path)
schema = load_json(schema_path)
if not isinstance(queue, list):
    raise SystemExit("ERROR: alert_queue.json must contain a JSON array")
if not isinstance(schema, dict):
    raise SystemExit("ERROR: alert_queue_schema.json must contain a JSON object")

item_schema = schema.get("items")
if not isinstance(item_schema, dict):
    raise SystemExit("ERROR: queue schema does not define an items schema")

validation_errors = []
for index, alert in enumerate(queue):
    errors = validate(alert, item_schema)
    if errors:
        validation_errors.append({
            "index": index,
            "alert_id": alert.get("alert_id") if isinstance(alert, dict) else None,
            "errors": errors,
        })

priority_bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
rule_counts = collections.Counter()
rule_titles = {}
host_counts = collections.Counter()
host_scores = collections.defaultdict(float)
tactic_counts = collections.Counter()
timestamps = []
tactics_by_rule = rule_tactics(catalog_dir)

for alert in queue:
    if not isinstance(alert, dict):
        continue
    score_value = alert.get("priority_score", 0)
    score = float(score_value) if isinstance(score_value, (int, float)) else 0.0
    if score >= 20:
        priority_bands["critical"] += 1
    elif score >= 10:
        priority_bands["high"] += 1
    elif score >= 5:
        priority_bands["medium"] += 1
    elif score >= 1:
        priority_bands["low"] += 1

    rule_id = str(alert.get("rule_id") or "unknown")
    rule_counts[rule_id] += 1
    rule_titles[rule_id] = str(alert.get("rule_title") or "unknown")

    summary = alert.get("event_summary")
    summary = summary if isinstance(summary, dict) else {}
    hostname = str(summary.get("hostname") or "unknown")
    host_counts[hostname] += 1
    host_scores[hostname] += score
    timestamp = summary.get("timestamp")
    if isinstance(timestamp, str) and timestamp:
        timestamps.append(timestamp)

    tactics = set(tactics_by_rule.get(rule_id, set()))
    if not tactics:
        tactics = fallback_tactics(alert.get("attack_techniques", []))
    for tactic in tactics or {"unknown"}:
        tactic_counts[tactic] += 1

by_rule = [
    {"rule_id": rule_id, "rule_title": rule_titles[rule_id], "count": count}
    for rule_id, count in sorted(
        rule_counts.items(), key=lambda item: (-item[1], rule_titles[item[0]], item[0])
    )
]
by_hostname = [
    {"hostname": hostname, "count": count}
    for hostname, count in sorted(host_counts.items(), key=lambda item: (-item[1], item[0]))
]
top_targets = [
    {
        "hostname": hostname,
        "priority_score_total": round(score, 4),
        "alert_count": host_counts[hostname],
    }
    for hostname, score in sorted(
        host_scores.items(), key=lambda item: (-item[1], item[0])
    )[:3]
]

assessment = {
    "queue_size": len(queue),
    "validation_errors": validation_errors,
    "by_priority_band": priority_bands,
    "by_rule": by_rule,
    "by_hostname": by_hostname,
    "by_attack_tactic": dict(sorted(tactic_counts.items())),
    "time_span": {
        "first": min(timestamps) if timestamps else None,
        "last": max(timestamps) if timestamps else None,
    },
    "top_targets": top_targets,
}

output = pathlib.Path(output_path)
output.parent.mkdir(parents=True, exist_ok=True)
temporary = output.with_name(f".{output.name}.tmp")
with temporary.open("w", encoding="utf-8") as stream:
    json.dump(assessment, stream, indent=2, ensure_ascii=False)
    stream.write("\n")
os.replace(temporary, output)

briefing_date = assessment["time_span"]["first"]
briefing_date = briefing_date[:10] if briefing_date else "UNKNOWN DATE"
print(f"=== SHIFT BRIEFING {briefing_date} ===")
print(f"queue size           : {len(queue)} alerts")
print(f"validation errors    : {len(validation_errors):2d}")
print(
    "time span            : "
    f"{assessment['time_span']['first']} -> {assessment['time_span']['last']}"
)
print("priority bands")
for name in ("critical", "high", "medium", "low"):
    print(f"  {name:<10}: {priority_bands[name]:2d}")
print("top rules (5)")
for item in by_rule[:5]:
    print(f"  {item['rule_title'][:34]:<34} {item['count']:3d}")
print("top hosts (3 by cumulative score)")
for item in top_targets:
    print(
        f"  {item['hostname'][:24]:<24} "
        f"score {item['priority_score_total']:g}"
    )
known_tactics = len([name for name in tactic_counts if name != "unknown"])
print(f"attack tactics covered : {known_tactics}")
print(f"{output.name} written")
PY

