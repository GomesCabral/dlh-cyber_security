#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INPUT_FILE="${ENRICHED_QUEUE_FILE:-$SCRIPT_DIR/enriched_queue.json}"
TICKETS_DIR="${TICKETS_DIR:-$SCRIPT_DIR/tickets}"
OUTPUT_FILE="$TICKETS_DIR/batch2_clearcut_fp.json"

[[ -r "$INPUT_FILE" ]] || {
    printf 'ERROR: required input is not readable: %s\n' "$INPUT_FILE" >&2
    exit 1
}
mkdir -p "$TICKETS_DIR"

python3 -W error /dev/fd/3 "$INPUT_FILE" "$OUTPUT_FILE" 3<<'PY'
import datetime as dt
import ipaddress
import json
import os
import pathlib
import re
import sys
import uuid

input_path, output_path = sys.argv[1:]


def walk(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            child = path + (str(key),)
            yield child, value
            yield from walk(value, child)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, path + (str(index),))


def text(value):
    return str(value).strip().casefold() if value not in (None, "") else ""


def event_value(alert, *names):
    event = alert.get("event_record") if isinstance(alert.get("event_record"), dict) else {}
    summary = alert.get("event_summary") if isinstance(alert.get("event_summary"), dict) else {}
    for name in names:
        if event.get(name) not in (None, ""):
            return event[name]
        if summary.get(name) not in (None, ""):
            return summary[name]
    return None


def category(alert):
    raw = text(alert.get("rule_category") or event_value(alert, "event_category"))
    combined = f"{raw} {text(alert.get('rule_title'))}"
    groups = (
        ("auth", ("auth", "login", "logon", "credential")),
        ("process", ("process", "execution", "interpreter", "tool")),
        ("network", ("network", "flow", "outbound", "destination", "smb")),
        ("file", ("file", "registry", "autorun")),
        ("correlation", ("correlation", "chain", "sequence")),
    )
    for name, terms in groups:
        if any(term in combined for term in terms):
            return name
    return raw or "unknown"


def keyed_values(document, names):
    wanted = {name.casefold() for name in names}
    answer = []
    for path, value in walk(document):
        if path and path[-1].casefold() in wanted:
            answer.extend(value if isinstance(value, list) else [value])
    return [value for value in answer if value not in (None, "")]


def prefixes(asset):
    answer = []
    for value in keyed_values(asset, {"service_account_prefix", "service_account_prefixes"}):
        if isinstance(value, str):
            answer.extend(part.strip() for part in value.split(",") if part.strip())
    return answer


def management_subnets(asset):
    answer = []
    names = {"management_subnet", "management_subnets", "mgmt_subnet", "mgmt_subnets"}
    for value in keyed_values(asset, names):
        try:
            answer.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError:
            continue
    return answer


def expected_processes(profile):
    answer = set()
    for path, value in walk(profile):
        lowered = {part.casefold() for part in path}
        if not any("process" in part for part in lowered):
            continue
        if not lowered.intersection({"expected", "expected_processes", "known_processes", "processes"}):
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if isinstance(item, str):
                answer.add(text(re.split(r"[/\\]", item)[-1]))
            elif isinstance(item, dict):
                for field in ("process_name", "name", "image"):
                    if isinstance(item.get(field), str):
                        answer.add(text(re.split(r"[/\\]", item[field])[-1]))
    return answer


def has_deviation(alert):
    false_fields = {"baseline_seen", "within_baseline", "baseline_match", "is_baseline"}
    true_fields = {"baseline_violation", "violates_baseline", "is_anomaly", "anomalous"}
    for path, value in walk(alert):
        field = path[-1].casefold() if path else ""
        if field in false_fields and value is False:
            return True
        if field in true_fields and value is True:
            return True
        if field == "anomaly_type" and value not in (None, "", "none"):
            return True
    return False


def all_iocs_clean(alert):
    hits = alert.get("ioc_hits")
    return isinstance(hits, list) and bool(hits) and all(
        isinstance(hit, dict) and text(hit.get("reputation")) == "clean"
        for hit in hits
    )


def match(alert):
    rule_group = category(alert)
    asset = alert.get("asset") if isinstance(alert.get("asset"), dict) else {}
    user = event_value(alert, "user", "username", "account")
    if rule_group in {"auth", "process"} and isinstance(user, str):
        for prefix in prefixes(asset):
            if text(user).startswith(text(prefix)):
                return "service_account_activity", (
                    f"Field user={user!r} matches service_account_prefix={prefix!r} "
                    f"for an authorized {rule_group} rule."
                )

    if rule_group == "network":
        source = event_value(alert, "src_ip", "source_ip")
        try:
            address = ipaddress.ip_address(str(source))
        except ValueError:
            address = None
        if address is not None:
            for subnet in management_subnets(asset):
                if address in subnet:
                    return "management_subnet", (
                        f"Field src_ip={source!r} belongs to authorized "
                        f"management_subnets={str(subnet)!r}."
                    )

    process = event_value(alert, "process_name", "image", "process")
    if process:
        process_name = text(re.split(r"[/\\]", str(process))[-1])
        if process_name in expected_processes(alert.get("baseline_host_profile", {})):
            return "baseline_match", (
                f"Field process_name={process!r} appears in "
                "baseline_host_profile.process.expected for this host."
            )

    if all_iocs_clean(alert) and not has_deviation(alert):
        indicators = [
            str(hit.get("indicator") or hit.get("ioc") or hit.get("value") or "unknown")
            for hit in alert["ioc_hits"]
        ]
        return "clean_ioc_no_deviation", (
            f"Fields ioc_hits={indicators!r} all have reputation='clean' and "
            "baseline_violation is absent."
        )
    return None


def references(alert):
    answer = []
    def add(value):
        if isinstance(value, str) and value and value not in answer:
            answer.append(value)
        elif isinstance(value, list):
            for item in value:
                add(item)
    add(alert.get("event_ref"))
    for document in (alert, alert.get("event_record")):
        if isinstance(document, dict):
            for key in ("event_refs", "linked_event_refs", "correlation_primitives"):
                add(document.get(key))
    return answer


def created_at(alert):
    value = alert.get("generated_at") or event_value(alert, "timestamp")
    if isinstance(value, str):
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return "1970-01-01T00:00:00Z"


with open(input_path, "r", encoding="utf-8") as stream:
    queue = json.load(stream)
if not isinstance(queue, list):
    raise SystemExit("ERROR: enriched_queue.json must contain a JSON array")

tickets = []
rows = []
for alert in queue:
    if not isinstance(alert, dict):
        continue
    signature = match(alert)
    if signature is None:
        continue
    reason, justification = signature
    alert_id = str(alert.get("alert_id"))
    evidence = references(alert)
    if not evidence:
        raise SystemExit(f"ERROR: alert {alert_id} has no evidence reference")
    tickets.append({
        "ticket_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"ticket:{alert_id}")),
        "alert_id": alert_id,
        "classification": "false_positive",
        "justification": justification,
        "evidence_refs": evidence,
        "ioc_hits": alert.get("ioc_hits", []),
        "attack_techniques": alert.get("attack_techniques", []),
        "recommended_action": "tune_rule",
        "analyst_time_seconds": int(alert.get("analyst_time_seconds") or 60),
        "created_at": created_at(alert),
        "fp_reason": reason,
    })
    rows.append((alert_id, str(alert.get("rule_title") or "unknown"), reason))

tickets.sort(key=lambda item: (item["created_at"], item["alert_id"]))
output = pathlib.Path(output_path)
temporary = output.with_name(f".{output.name}.tmp")
with temporary.open("w", encoding="utf-8") as stream:
    json.dump(tickets, stream, indent=2, ensure_ascii=False)
    stream.write("\n")
os.replace(temporary, output)

print("batch 2 clear-cut false positives")
for alert_id, title, reason in rows:
    print(f"  {alert_id[:14]:<14}  {title[:34]:<34}  CLOSE  {reason}")
print(f"batch size               : {len(tickets)}")
print(f"tickets written          : {len(tickets)}")
print(output_path)
PY
