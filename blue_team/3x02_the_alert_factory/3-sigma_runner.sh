#!/bin/bash
set -Eeuo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DEFAULT_EVIDENCE="$HANDOFF_DIR/data/normalized_events.json"

python3 -W error /dev/fd/3 "$DEFAULT_EVIDENCE" "$@" 3<<'PY'
import argparse
import collections
import datetime as dt
import json
import re
import sys
import time

import yaml


def arguments():
    parser = argparse.ArgumentParser(description="Run Sigma logic against JSON evidence")
    parser.add_argument("default_evidence", help=argparse.SUPPRESS)
    parser.add_argument("rule_file")
    parser.add_argument("evidence_file", nargs="?")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--count-only", action="store_true")
    parser.add_argument("--window", metavar="START_ISO,END_ISO")
    return parser.parse_args()


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=dt.timezone.utc)
    return result.astimezone(dt.timezone.utc)


def window(value):
    if value is None:
        return None
    parts = value.split(",", 1)
    if len(parts) != 2:
        raise ValueError("--window must be START_ISO,END_ISO")
    start, end = timestamp(parts[0]), timestamp(parts[1])
    if start is None or end is None or start > end:
        raise ValueError("invalid or reversed --window timestamps")
    return start, end


def events(path):
    with open(path, "r", encoding="utf-8") as stream:
        first = ""
        while True:
            character = stream.read(1)
            if not character:
                return
            if not character.isspace():
                first = character
                break
        stream.seek(0)
        if first == "[":
            document = json.load(stream)
            if not isinstance(document, list):
                raise ValueError("JSON evidence must be an array")
            for number, event in enumerate(document, start=1):
                if isinstance(event, dict):
                    yield number, event
            return
        for number, line in enumerate(stream, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                event = json.loads(text)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid NDJSON line {number}: {error}") from error
            if isinstance(event, dict):
                yield number, event


def field(event, requested):
    if requested == "hour_of_day":
        parsed = timestamp(event.get("timestamp"))
        return parsed.hour if parsed else None
    aliases = {
        "event_id": {"event_id", "eventid"},
        "logontype": {"logontype", "logon_type"},
        "src_ip": {"src_ip", "source_ip", "srcip"},
    }
    names = aliases.get(requested.lower(), {requested.lower()})
    for name, value in event.items():
        if name.lower() in names:
            return value
    return None


def equal(actual, expected):
    if isinstance(actual, list):
        return any(equal(item, expected) for item in actual)
    return actual is not None and str(actual).casefold() == str(expected).casefold()


def value_matches(actual, expected, modifier):
    expected = expected if isinstance(expected, list) else [expected]
    if modifier in {"lt", "lte", "gt", "gte"}:
        try:
            left = float(actual)
            operations = {
                "lt": lambda right: left < float(right),
                "lte": lambda right: left <= float(right),
                "gt": lambda right: left > float(right),
                "gte": lambda right: left >= float(right),
            }
            return any(operations[modifier](item) for item in expected)
        except (TypeError, ValueError):
            return False
    if modifier in {"contains", "startswith", "endswith"}:
        if actual is None:
            return False
        actual = str(actual).casefold()
        operations = {
            "contains": lambda item: str(item).casefold() in actual,
            "startswith": lambda item: actual.startswith(str(item).casefold()),
            "endswith": lambda item: actual.endswith(str(item).casefold()),
        }
        return any(operations[modifier](item) for item in expected)
    return any(equal(actual, item) for item in expected)


def selection_matches(event, selection):
    if not isinstance(selection, dict):
        return False
    for expression, expected in selection.items():
        parts = expression.split("|", 1)
        name = parts[0]
        modifier = parts[1] if len(parts) == 2 else "equals"
        if not value_matches(field(event, name), expected, modifier):
            return False
    return True


def boolean_condition(condition, answers):
    expression = condition
    for name in sorted(answers, key=len, reverse=True):
        expression = re.sub(
            rf"\b{re.escape(name)}\b", str(bool(answers[name])), expression
        )
    if not re.fullmatch(r"[TrueFalsandornot()\s]+", expression):
        raise ValueError(f"unsupported condition: {condition}")
    return bool(eval(expression, {"__builtins__": {}}, {}))


def logsource_matches(event, logsource):
    product = str(logsource.get("product", "")).casefold()
    event_product = str(event.get("product", "")).casefold()
    source_type = str(event.get("source_type", "")).casefold()
    return not product or product in {event_product, source_type} or product in source_type


def seconds(value):
    match = re.fullmatch(r"(\d+)(s|m|h)", str(value))
    if not match:
        raise ValueError(f"unsupported timeframe: {value}")
    return int(match.group(1)) * {"s": 1, "m": 60, "h": 3600}[match.group(2)]


def reference(event, path, number):
    return {
        "event_ref": str(
            event.get("event_ref") or event.get("event_uuid") or f"{path}:{number}"
        ),
        "timestamp": event.get("timestamp"),
        "hostname": event.get("hostname") or event.get("host"),
    }


def validate(rule):
    required = {
        "title", "id", "status", "description", "logsource", "detection",
        "falsepositives", "level", "tags",
    }
    if not isinstance(rule, dict):
        raise ValueError("rule is not a YAML mapping")
    missing = sorted(required - set(rule))
    if missing:
        raise ValueError(f'missing fields: {", ".join(missing)}')
    if not isinstance(rule["detection"], dict) or "condition" not in rule["detection"]:
        raise ValueError("detection.condition is required")


args = arguments()
try:
    with open(args.rule_file, "r", encoding="utf-8") as stream:
        rule = yaml.safe_load(stream)
    validate(rule)
except (OSError, ValueError, yaml.YAMLError) as error:
    print(f"INVALID: {error}", file=sys.stderr)
    sys.exit(1)

if args.dry_run:
    print("VALID")
    sys.exit(0)

evidence_path = args.evidence_file or args.default_evidence
try:
    chosen_window = window(args.window)
except ValueError as error:
    print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)

started = time.perf_counter()
detection = rule["detection"]
condition = str(detection["condition"])
selections = {
    name: item
    for name, item in detection.items()
    if name not in {"condition", "timeframe"}
}
aggregation = re.fullmatch(
    r"\s*(\w+)\s*\|\s*count\(\)\s+by\s+(\w+)\s*"
    r"(>=|>|==|<=|<)\s*(\d+)(?:\s+within\s+(\d+[smh]))?\s*",
    condition,
    flags=re.IGNORECASE,
)
matches = []
groups = collections.defaultdict(list)

try:
    for number, event in events(evidence_path):
        event_time = timestamp(event.get("timestamp"))
        if chosen_window and (
            event_time is None
            or not chosen_window[0] <= event_time <= chosen_window[1]
        ):
            continue
        if not logsource_matches(event, rule.get("logsource", {})):
            continue
        if aggregation:
            selection_name, group_name = aggregation.group(1), aggregation.group(2)
            if selection_name not in selections:
                raise ValueError(f"unknown selection: {selection_name}")
            group_value = field(event, group_name)
            if selection_matches(event, selections[selection_name]) and event_time and group_value:
                groups[str(group_value)].append((event_time, number, event))
        else:
            answers = {
                name: selection_matches(event, item)
                for name, item in selections.items()
            }
            if boolean_condition(condition, answers):
                matches.append((number, event))
except (OSError, ValueError) as error:
    print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)

if aggregation:
    operator, threshold = aggregation.group(3), int(aggregation.group(4))
    timeframe = aggregation.group(5) or detection.get("timeframe")
    if timeframe is None:
        print("ERROR: aggregation requires timeframe", file=sys.stderr)
        sys.exit(1)
    interval = seconds(timeframe)
    compare = {
        ">": lambda count: count > threshold,
        ">=": lambda count: count >= threshold,
        "==": lambda count: count == threshold,
        "<=": lambda count: count <= threshold,
        "<": lambda count: count < threshold,
    }[operator]
    qualified = {}
    for group in groups.values():
        group.sort(key=lambda item: item[0])
        left = 0
        for right, current in enumerate(group):
            while (current[0] - group[left][0]).total_seconds() > interval:
                left += 1
            if compare(right - left + 1):
                for item in group[left:right + 1]:
                    qualified[item[1]] = item[2]
    matches = sorted(qualified.items())

references = [reference(event, evidence_path, number) for number, event in matches]
elapsed = round((time.perf_counter() - started) * 1000, 3)

if args.count_only:
    print(len(references))
else:
    print(json.dumps({
        "rule_id": str(rule["id"]),
        "rule_title": rule["title"],
        "level": rule["level"],
        "match_count": len(references),
        "matches": references,
        "execution_time_ms": elapsed,
    }, indent=2, ensure_ascii=False))
PY
