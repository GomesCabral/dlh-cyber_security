#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x03_assets}"

QUEUE_FILE="$CATALOG_DIR/alerts/alert_queue.json"
ASSET_FILE="$HANDOFF_DIR/context/asset_inventory.json"
EVENT_FILE="$HANDOFF_DIR/data/enriched_events.json"
BASELINE_FILE="$BASELINE_PKG/baselines/baseline_summary.json"
IOC_FILE="$ASSETS_DIR/ioc_context.json"
OUTPUT_FILE="${ENRICHED_QUEUE_FILE:-$SCRIPT_DIR/enriched_queue.json}"
TICKETS_DIR="${TICKETS_DIR:-$SCRIPT_DIR/tickets}"

for dependency in \
    "$QUEUE_FILE" "$ASSET_FILE" "$EVENT_FILE" "$BASELINE_FILE" "$IOC_FILE"; do
    [[ -r "$dependency" ]] || {
        printf 'ERROR: required input is not readable: %s\n' "$dependency" >&2
        exit 1
    }
done

mkdir -p "$TICKETS_DIR"

python3 -W error /dev/fd/3 \
    "$QUEUE_FILE" "$ASSET_FILE" "$EVENT_FILE" "$BASELINE_FILE" \
    "$IOC_FILE" "$OUTPUT_FILE" 3<<'PY'
import collections
import ipaddress
import json
import os
import pathlib
import re
import sys


(
    queue_path,
    asset_path,
    event_path,
    baseline_path,
    ioc_path,
    output_path,
) = sys.argv[1:]


def load_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def walk(node, path=()):
    if isinstance(node, dict):
        yield path, node
        for key, value in node.items():
            yield from walk(value, path + (str(key),))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, path + (str(index),))


def text(value):
    return str(value).strip().casefold() if value not in (None, "") else ""


def event_hostname(alert):
    summary = alert.get("event_summary")
    if isinstance(summary, dict):
        return summary.get("hostname") or summary.get("host")
    return None


def asset_records(document):
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if isinstance(document, dict):
        for key in ("assets", "inventory", "records", "hosts"):
            value = document.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                records = []
                for name, item in value.items():
                    if isinstance(item, dict):
                        record = dict(item)
                        record.setdefault("hostname", name)
                        records.append(record)
                return records
        if any(key in document for key in ("hostname", "host", "asset_id")):
            return [document]
    return []


def normalized_asset(record):
    if record is None:
        return None
    result = dict(record)
    result["criticality"] = (
        record.get("criticality") or record.get("asset_criticality") or "unknown"
    )
    result["role"] = record.get("role") or record.get("asset_role") or "unknown"
    result["data_classification"] = (
        record.get("data_classification")
        or record.get("data_sensitivity")
        or "unknown"
    )
    result["owner"] = record.get("owner") or record.get("asset_owner") or "unknown"
    result["network_zone"] = (
        record.get("network_zone") or record.get("zone") or "unknown"
    )
    return result


def build_asset_index(document):
    index = {}
    for record in asset_records(document):
        normalized = normalized_asset(record)
        for field in (
            "hostname", "host", "name", "asset", "asset_id", "ip", "ip_address"
        ):
            key = text(record.get(field))
            if key:
                index.setdefault(key, normalized)
    return index


def find_asset(alert, index):
    summary = alert.get("event_summary")
    summary = summary if isinstance(summary, dict) else {}
    candidates = [
        summary.get("hostname"),
        summary.get("src_ip"),
        summary.get("dst_ip"),
    ]
    context = alert.get("asset_context")
    if isinstance(context, dict):
        candidates.extend(
            context.get(name)
            for name in ("hostname", "host", "asset_id", "ip", "ip_address")
        )
    for candidate in candidates:
        if text(candidate) in index:
            return index[text(candidate)]
    if isinstance(context, dict):
        return normalized_asset(context)
    return None


def reference_line(reference):
    value = str(reference or "")
    match = re.search(r":line:(\d+)$", value)
    if match:
        return int(match.group(1))
    match = re.search(r":(\d+)$", value)
    if match and ("/" in value or "\\" in value):
        return int(match.group(1))
    return None


def generated_reference(event, number):
    explicit = event.get("event_ref") or event.get("event_uuid")
    if explicit:
        return str(explicit)
    return (
        f'{event.get("source_type", "unknown")}:'
        f'{event.get("event_id")}:line:{number}'
    )


def dereference_events(path, references):
    found = {}
    lines = collections.defaultdict(set)
    unresolved = set()
    for reference in references:
        number = reference_line(reference)
        if number is None:
            unresolved.add(reference)
        else:
            lines[number].add(reference)

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
            if not isinstance(document, list):
                raise ValueError("enriched_events.json must be an array or NDJSON")
            iterable = enumerate(document, start=1)
        else:
            def ndjson():
                for number, line in enumerate(stream, start=1):
                    if number not in lines and not unresolved:
                        continue
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        event = json.loads(raw)
                    except json.JSONDecodeError as error:
                        raise ValueError(
                            f"invalid enriched NDJSON at line {number}: {error}"
                        ) from error
                    yield number, event
            iterable = ndjson()

        for number, event in iterable:
            if not isinstance(event, dict):
                continue
            for reference in lines.get(number, set()):
                found[reference] = event
            event_ref = generated_reference(event, number)
            if event_ref in unresolved:
                found[event_ref] = event
                unresolved.remove(event_ref)
            if len(found) == len(references):
                break
    return found


category_terms = {
    "authentication": {"authentication", "auth", "login", "logon", "account"},
    "process": {"process", "execution", "parent", "child"},
    "network": {"network", "flow", "connection", "destination", "port"},
    "file": {"file", "path", "hash", "integrity"},
    "registry": {"registry", "autorun", "persistence"},
}


def baseline_profile(document, hostname, category):
    wanted_host = text(hostname)
    wanted_category = text(category)
    terms = category_terms.get(wanted_category, {wanted_category})
    slices = []
    seen = set()

    for path, node in walk(document):
        path_text = ".".join(path).casefold()
        direct_host = any(
            text(node.get(field)) == wanted_host
            for field in ("hostname", "host", "asset", "asset_id")
        )
        keyed_host = wanted_host and any(part.casefold() == wanted_host for part in path)
        category_match = not terms or any(term and term in path_text for term in terms)
        if wanted_host and (direct_host or keyed_host) and category_match:
            encoded = json.dumps(node, sort_keys=True, ensure_ascii=False)
            if encoded not in seen:
                slices.append(node)
                seen.add(encoded)
        if len(slices) >= 20:
            break

    return {
        "hostname": hostname,
        "event_category": category,
        "slices": slices,
    }


def ioc_entries(document):
    if isinstance(document, dict):
        source = document.get("indicators", document)
        if isinstance(source, dict):
            return {
                text(indicator): dict(value, indicator=indicator)
                for indicator, value in source.items()
                if isinstance(value, dict)
            }
        if isinstance(source, list):
            document = source
    if isinstance(document, list):
        answer = {}
        for entry in document:
            if not isinstance(entry, dict):
                continue
            indicator = (
                entry.get("indicator") or entry.get("ioc") or entry.get("value")
            )
            if indicator:
                answer[text(indicator)] = dict(entry, indicator=indicator)
        return answer
    return {}


def candidate_iocs(*documents):
    answer = set()
    domain_pattern = re.compile(
        r"(?i)(?<![a-z0-9-])(?:[a-z0-9-]+\.)+[a-z]{2,63}(?![a-z0-9-])"
    )

    def inspect(name, value):
        if isinstance(value, dict):
            for key, child in value.items():
                inspect(str(key), child)
        elif isinstance(value, list):
            for child in value:
                inspect(name, child)
        elif isinstance(value, str):
            field = name.casefold()
            if "ip" in field:
                try:
                    answer.add(str(ipaddress.ip_address(value.strip())).casefold())
                except ValueError:
                    pass
            if "domain" in field or "host" in field or "url" in field:
                answer.update(match.casefold() for match in domain_pattern.findall(value))

    for document in documents:
        inspect("", document)
    return answer


def priority_band(score):
    if score >= 20:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


queue = load_json(queue_path)
assets_document = load_json(asset_path)
baseline_document = load_json(baseline_path)
ioc_document = load_json(ioc_path)
if not isinstance(queue, list):
    raise SystemExit("ERROR: alert_queue.json must contain a JSON array")

references = {
    str(alert.get("event_ref"))
    for alert in queue
    if isinstance(alert, dict) and alert.get("event_ref")
}
events = dereference_events(event_path, references)
missing_events = sorted(references - set(events))
if missing_events:
    preview = "\n".join(missing_events[:10])
    raise SystemExit(
        f"ERROR: {len(missing_events)} event references could not be dereferenced"
        f"\n{preview}"
    )

asset_index = build_asset_index(assets_document)
ioc_index = ioc_entries(ioc_document)
enriched = []
assets_joined = 0
baseline_joined = 0
ioc_alerts = 0
reputation_counts = collections.Counter()

for alert in queue:
    if not isinstance(alert, dict):
        continue
    result = dict(alert)
    reference = str(alert.get("event_ref"))
    event = events[reference]
    asset = find_asset(alert, asset_index)
    if asset is not None:
        assets_joined += 1

    summary = alert.get("event_summary")
    summary = summary if isinstance(summary, dict) else {}
    hostname = summary.get("hostname") or event.get("hostname") or event.get("host")
    category = summary.get("event_category") or event.get("event_category")
    profile = baseline_profile(baseline_document, hostname, category)
    if profile["slices"]:
        baseline_joined += 1

    hits = []
    for indicator in sorted(candidate_iocs(alert, event)):
        if indicator not in ioc_index:
            continue
        hit = dict(ioc_index[indicator])
        reputation = text(hit.get("reputation")) or "unknown"
        hit["ioc_flag"] = reputation != "clean"
        hits.append(hit)
        reputation_counts[reputation] += 1
    if hits:
        ioc_alerts += 1

    score_value = alert.get("priority_score", 0)
    score = float(score_value) if isinstance(score_value, (int, float)) else 0.0
    result.update({
        "asset": asset,
        "baseline_host_profile": profile,
        "event_record": event,
        "ioc_hits": hits,
        "priority_band": priority_band(score),
    })
    enriched.append(result)

output = pathlib.Path(output_path)
output.parent.mkdir(parents=True, exist_ok=True)
temporary = output.with_name(f".{output.name}.tmp")
with temporary.open("w", encoding="utf-8") as stream:
    json.dump(enriched, stream, indent=2, ensure_ascii=False)
    stream.write("\n")
os.replace(temporary, output)

print(f"alerts processed          : {len(enriched)}")
print(f"assets joined             : {assets_joined}")
print(f"missing asset records     : {len(enriched) - assets_joined:2d}")
print(f"alerts with IOC hits      : {ioc_alerts}")
for reputation in ("malicious", "suspicious", "unknown"):
    print(f"  {reputation:<23}: {reputation_counts[reputation]:2d}")
print(f"baseline profiles joined  : {baseline_joined}")
print(f"{output.name} written ({output.stat().st_size // 1024} KB)")
PY

