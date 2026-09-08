#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x03_assets}"
INPUT_FILE="${ENRICHED_QUEUE_FILE:-$SCRIPT_DIR/enriched_queue.json}"
IOC_FILE="$ASSETS_DIR/ioc_context.json"
TICKETS_DIR="${TICKETS_DIR:-$SCRIPT_DIR/tickets}"
OUTPUT_FILE="$TICKETS_DIR/batch5_proc_net.json"

for dependency in "$INPUT_FILE" "$IOC_FILE"; do
    [[ -r "$dependency" ]] || {
        printf 'ERROR: required input is not readable: %s\n' "$dependency" >&2
        exit 1
    }
done
mkdir -p "$TICKETS_DIR"

python3 -W error /dev/fd/3 \
    "$INPUT_FILE" "$IOC_FILE" "$TICKETS_DIR" "$OUTPUT_FILE" 3<<'PY'
import datetime as dt
import ipaddress
import json
import os
import pathlib
import re
import sys
import uuid

input_path, ioc_path, tickets_dir, output_path = sys.argv[1:]


def load_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def text(value):
    return str(value).strip().casefold() if value not in (None, "") else ""


def walk(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            child = path + (str(key),)
            yield child, value
            yield from walk(value, child)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, path + (str(index),))


def event(alert):
    value = alert.get("event_record")
    return value if isinstance(value, dict) else {}


def summary(alert):
    value = alert.get("event_summary")
    return value if isinstance(value, dict) else {}


def event_value(alert, *names):
    for name in names:
        if event(alert).get(name) not in (None, ""):
            return event(alert)[name]
        if summary(alert).get(name) not in (None, ""):
            return summary(alert)[name]
    return None


def alert_category(alert):
    combined = " ".join((
        text(alert.get("rule_category")),
        text(alert.get("rule_title")),
        text(event_value(alert, "event_category", "canonical_label")),
    ))
    if any(word in combined for word in ("process", "execution", "interpreter", "tool")):
        return "process"
    if any(word in combined for word in (
        "network", "connection", "flow", "outbound", "destination", "smb"
    )):
        return "network"
    return "other"


def handled_ids(folder):
    answer = set()
    for path in sorted(pathlib.Path(folder).glob("batch[1-4]_*.json")):
        try:
            document = load_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(document, list):
            answer.update(
                str(item["alert_id"])
                for item in document
                if isinstance(item, dict) and item.get("alert_id")
            )
    return answer


def ioc_index(document):
    source = document.get("indicators", document) if isinstance(document, dict) else document
    answer = {}
    if isinstance(source, dict):
        for indicator, value in source.items():
            if isinstance(value, dict):
                answer[text(indicator)] = dict(value, indicator=indicator)
    elif isinstance(source, list):
        for value in source:
            if not isinstance(value, dict):
                continue
            indicator = value.get("indicator") or value.get("ioc") or value.get("value")
            if indicator:
                answer[text(indicator)] = dict(value, indicator=indicator)
    return answer


def destination_values(alert):
    answer = {"dst_ip": [], "dst_host": [], "dst_port": []}
    aliases = {
        "dst_ip": {"dst_ip", "destination_ip"},
        "dst_host": {"dst_host", "destination_host", "dst_domain", "destination_domain"},
        "dst_port": {"dst_port", "destination_port"},
    }
    for path, value in walk(event(alert)):
        if not path or value in (None, ""):
            continue
        field = path[-1].casefold()
        for output_name, names in aliases.items():
            if field in names:
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if item not in answer[output_name]:
                        answer[output_name].append(item)
    for output_name in answer:
        fallback = event_value(alert, output_name)
        if fallback not in (None, "") and fallback not in answer[output_name]:
            answer[output_name].append(fallback)
    return answer


def process_context(alert):
    return {
        "process_name": event_value(alert, "process_name", "image", "process"),
        "parent_process": event_value(
            alert, "parent_process", "parent_process_name", "parent_image"
        ),
        "command_line": event_value(alert, "command_line", "process_command_line"),
    }


def ioc_hits(alert, index, destinations):
    hits = []
    seen = set()

    def add(hit):
        if not isinstance(hit, dict):
            return
        indicator = str(
            hit.get("indicator") or hit.get("ioc") or hit.get("value") or "unknown"
        )
        key = (text(indicator), text(hit.get("reputation")))
        if key not in seen:
            record = dict(hit)
            record.setdefault("indicator", indicator)
            record["ioc_flag"] = text(record.get("reputation")) != "clean"
            hits.append(record)
            seen.add(key)

    for hit in alert.get("ioc_hits", []):
        add(hit)
    for value in destinations["dst_ip"] + destinations["dst_host"]:
        if text(value) in index:
            add(index[text(value)])
    return hits


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


def profile_strings(profile):
    answer = set()
    for _, value in walk(profile):
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            answer.add(text(value))
            if isinstance(value, str):
                answer.add(text(re.split(r"[/\\]", value)[-1]))
    return answer


def other_host_match(alert, queue, candidate):
    wanted = text(re.split(r"[/\\]", str(candidate))[-1])
    current_host = text(event_value(alert, "hostname", "host"))
    if not wanted:
        return None
    for other in queue:
        if not isinstance(other, dict):
            continue
        other_host = text(event_value(other, "hostname", "host"))
        if not other_host or other_host == current_host:
            continue
        if wanted in profile_strings(other.get("baseline_host_profile", {})):
            return other_host
    profile = alert.get("baseline_host_profile", {})
    for path, node in walk(profile):
        if current_host and any(text(part) == current_host for part in path):
            continue
        if isinstance(node, dict) and wanted in profile_strings(node):
            host = node.get("hostname") or node.get("host")
            if host and text(host) != current_host:
                return str(host)
    return None


def criticality(alert):
    asset = alert.get("asset") if isinstance(alert.get("asset"), dict) else {}
    return text(asset.get("criticality") or asset.get("asset_criticality")) or "unknown"


def indicator(hit):
    return str(hit.get("indicator") or hit.get("ioc") or hit.get("value") or "unknown")


def decide(alert, queue, hits, proc, destinations):
    level = criticality(alert)
    malicious = [hit for hit in hits if text(hit.get("reputation")) == "malicious"]
    suspicious = [hit for hit in hits if text(hit.get("reputation")) == "suspicious"]
    clean_only = bool(hits) and all(text(hit.get("reputation")) == "clean" for hit in hits)
    checked = (
        f"process_name={proc['process_name']!r}, parent_process={proc['parent_process']!r}, "
        f"command_line={proc['command_line']!r}, dst_ip={destinations['dst_ip']!r}, "
        f"dst_host={destinations['dst_host']!r}, dst_port={destinations['dst_port']!r}, "
        f"asset.criticality={level!r}, IOC reputations="
        f"{[hit.get('reputation') for hit in hits]!r}"
    )
    if malicious:
        return "true_positive", "escalate_tier2", None, (
            f"IOC indicator={indicator(malicious[0])!r} has reputation='malicious'; {checked}."
        )
    if suspicious and level in {"critical", "high"}:
        return "true_positive", "monitor", None, (
            f"IOC indicator={indicator(suspicious[0])!r} has reputation='suspicious' "
            f"on a {level} asset; {checked}."
        )
    if suspicious and level in {"medium", "low"}:
        candidates = []
        if alert_category(alert) == "process" and proc["process_name"]:
            candidates.append(proc["process_name"])
        candidates.extend(destinations["dst_ip"] + destinations["dst_host"])
        for candidate in candidates:
            known_host = other_host_match(alert, queue, candidate)
            if known_host:
                return "false_positive", "tune_rule", "suspicious_but_baseline_known_elsewhere", (
                    f"Observed value={candidate!r} is present in baseline_host_profile for "
                    f"different host={known_host!r}; IOC reputation='suspicious' and "
                    f"asset.criticality={level!r}."
                )
    if clean_only and not has_deviation(alert):
        return "false_positive", "tune_rule", "clean_ioc_no_deviation", (
            f"All IOC reputations are 'clean' and baseline_violation is absent; {checked}."
        )
    return "true_positive", "monitor", None, (
        f"No decisive malicious, suspicious-high-risk, or clean-baseline condition matched; {checked}."
    )


def references(alert):
    answer = []
    for value in (alert.get("event_ref"), event(alert).get("event_ref")):
        if isinstance(value, str) and value and value not in answer:
            answer.append(value)
    for document in (alert, event(alert)):
        for key in ("event_refs", "linked_event_refs", "correlation_primitives"):
            values = document.get(key, []) if isinstance(document, dict) else []
            values = values if isinstance(values, list) else [values]
            for value in values:
                if isinstance(value, str) and value and value not in answer:
                    answer.append(value)
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


queue = load_json(input_path)
index = ioc_index(load_json(ioc_path))
if not isinstance(queue, list):
    raise SystemExit("ERROR: enriched_queue.json must contain a JSON array")

handled = handled_ids(tickets_dir)
tickets = []
rows = []
for alert in queue:
    if (
        not isinstance(alert, dict)
        or alert_category(alert) not in {"process", "network"}
        or str(alert.get("alert_id")) in handled
    ):
        continue
    proc = process_context(alert)
    destinations = destination_values(alert)
    hits = ioc_hits(alert, index, destinations)
    classification, action, reason, justification = decide(
        alert, queue, hits, proc, destinations
    )
    alert_id = str(alert.get("alert_id"))
    evidence = references(alert)
    if not evidence:
        raise SystemExit(f"ERROR: alert {alert_id} has no evidence reference")
    ticket = {
        "ticket_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"ticket:{alert_id}")),
        "alert_id": alert_id,
        "classification": classification,
        "justification": justification,
        "evidence_refs": evidence,
        "ioc_hits": hits,
        "attack_techniques": alert.get("attack_techniques", []),
        "recommended_action": action,
        "analyst_time_seconds": int(alert.get("analyst_time_seconds") or 240),
        "created_at": created_at(alert),
        "process_context": proc,
        "network_context": destinations,
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

print("batch 5 ambiguous process and network")
for alert_id, title, classification, action in rows:
    shown = "escalate" if action == "escalate_tier2" else action
    print(f"  {alert_id[:14]:<14}  {title[:34]:<34}  {classification:<16} {shown}")
print(f"batch size               : {len(tickets)}")
print(f"tickets written          : {len(tickets)}")
print(output_path)
PY
