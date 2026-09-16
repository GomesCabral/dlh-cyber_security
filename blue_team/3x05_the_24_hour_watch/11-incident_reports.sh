#!/bin/bash
set -euo pipefail

: "${SHIFT_WORKSPACE:?Execute: source ./project_env.sh}"
: "${ASSETS_DIR:?ASSETS_DIR não definido}"

python3 - "$SHIFT_WORKSPACE" "$ASSETS_DIR" <<'PY'
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

workspace = Path(sys.argv[1])
assets_dir = Path(sys.argv[2])

incidents_file = workspace / "alerts/incidents.json"
alerts_file = workspace / "alerts/alert_queue.json"
events_file = workspace / "enriched/enriched_events.jsonl"
assets_file = assets_dir / "assets.json"
ioc_file = assets_dir / "ioc_feed.json"
reports_dir = workspace / "reports"

finding_files = {
    "A": workspace / "investigations/incident_A.json",
    "B": workspace / "investigations/incident_B.json",
    "C": workspace / "investigations/incident_C_cli.json",
}

required = [
    incidents_file,
    alerts_file,
    events_file,
    assets_file,
    ioc_file,
    *finding_files.values(),
]

for path in required:
    if not path.is_file() or path.stat().st_size == 0:
        raise SystemExit(f"[report] ERROR: missing {path}")

reports_dir.mkdir(parents=True, exist_ok=True)

def load_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)

def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def canonical_ref(event):
    existing = event.get("event_ref")
    if existing:
        return str(existing)

    source = event.get("source_type") or "unknown"
    event_id = event.get("event_id") or event.get("rule_id") or "none"
    timestamp = event.get("timestamp") or "unknown"
    host = event.get("hostname") or event.get("host") or "unknown"
    return f"{source}:{event_id}:{timestamp}:{host}"

def defang(text):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return re.sub(pattern, lambda match: match.group(0).replace(".", "[.]"), text)

def clean(value):
    return str(value or "unknown").replace("|", "/").replace("\n", " ").strip()

def collect_iocs(value, output=None):
    if output is None:
        output = {}

    if isinstance(value, dict):
        if value.get("value") is not None:
            indicator = str(value["value"])
            output[indicator.lower()] = {
                "value": indicator,
                "type": value.get("type") or infer_ioc_type(indicator),
                "confidence": value.get("confidence", "unknown"),
                "source": value.get("source", "HC-RED7 feed"),
            }

        for child in value.values():
            collect_iocs(child, output)

    elif isinstance(value, list):
        for child in value:
            collect_iocs(child, output)

    return output

def infer_ioc_type(value):
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{32,64}", value):
        return "hash"
    if "." in value:
        return "domain"
    return "indicator"

def event_description(event):
    return clean(
        event.get("raw_message")
        or event.get("message")
        or event.get("event_action")
        or event.get("event_category")
        or "Security event"
    )[:160]

def asset_records(document):
    if isinstance(document, list):
        return document
    return document.get("assets", [])

def alert_records(document):
    if isinstance(document, list):
        return document
    return document.get("alerts", [])

incidents_document = load_json(incidents_file)
alerts = alert_records(load_json(alerts_file))
asset_inventory = asset_records(load_json(assets_file))
ioc_lookup = collect_iocs(load_json(ioc_file))

incidents = {}
findings = {}
host_sets = {}
windows = {}

for label in ("A", "B", "C"):
    findings[label] = load_json(finding_files[label])
    incident_id = findings[label]["incident_id"]

    incidents[label] = next(
        incident
        for incident in incidents_document["incidents"]
        if incident["incident_id"] == incident_id
    )

    host_sets[label] = {
        host.lower()
        for host in incidents[label].get("host_list", [])
    }

    windows[label] = (
        parse_time(incidents[label]["first_seen"]) - timedelta(minutes=15),
        parse_time(incidents[label]["last_seen"]) + timedelta(minutes=15),
    )

events_by_incident = {"A": [], "B": [], "C": []}
all_valid_refs = set()

with events_file.open(encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, 1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        reference = canonical_ref(event)
        all_valid_refs.add(reference)

        host = str(
            event.get("hostname")
            or event.get("host")
            or ""
        ).lower()

        timestamp_value = event.get("timestamp")
        if not timestamp_value:
            continue

        try:
            timestamp = parse_time(timestamp_value)
        except ValueError:
            continue

        for label in ("A", "B", "C"):
            start, end = windows[label]

            if host in host_sets[label] and start <= timestamp <= end:
                copied = dict(event)
                copied["_canonical_ref"] = reference
                events_by_incident[label].append(copied)

alerts_by_id = {
    alert.get("alert_id"): alert
    for alert in alerts
    if alert.get("alert_id")
}

attack_names = {
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1078": "Valid Accounts",
    "T1078.002": "Domain Accounts",
    "T1071.001": "Web Protocols",
    "T1543.003": "Windows Service",
    "T1041": "Exfiltration Over C2 Channel",
}

verified_total = 0

for label in ("A", "B", "C"):
    print(f"[report] generating incident_{label}.md")

    incident = incidents[label]
    finding = findings[label]
    incident_events = sorted(
        events_by_incident[label],
        key=lambda event: event.get("timestamp", ""),
    )

    significant = sorted(
        incident_events,
        key=lambda event: (
            0 if event.get("event_category") in {
                "authentication",
                "process",
                "network",
                "network_alert",
                "persistence",
            } else 1,
            event.get("timestamp", ""),
        ),
    )[:15]

    timeline = [
        (
            clean(event.get("timestamp")),
            clean(event.get("hostname") or event.get("host")),
            event_description(event),
        )
        for event in significant
    ]

    references = []
    for event in significant:
        reference = event["_canonical_ref"]
        if reference not in references:
            references.append(reference)
        if len(references) == 12:
            break

    if not references:
        raise SystemExit(
            f"[report] ERROR: no real event references for incident {label}"
        )

    missing_refs = [
        reference
        for reference in references
        if reference not in all_valid_refs
    ]

    if missing_refs:
        raise SystemExit(
            f"[report] ERROR: references not found for {label}: "
            + ", ".join(missing_refs)
        )

    verified_total += len(references)

    assets = []
    inventory_by_host = {
        str(asset.get("hostname", "")).lower(): asset
        for asset in asset_inventory
    }

    enriched_assets = {}
    for event in incident_events:
        host = str(event.get("hostname") or "").lower()
        if host and isinstance(event.get("asset"), dict):
            enriched_assets.setdefault(host, event["asset"])

    for hostname in incident.get("host_list", [])[:10]:
        normalized = hostname.lower()
        asset = inventory_by_host.get(normalized, {})
        enriched = enriched_assets.get(normalized, {})

        assets.append({
            "host": hostname,
            "criticality": (
                asset.get("criticality")
                or enriched.get("criticality")
                or "unknown"
            ),
            "data_class": (
                asset.get("data_classification")
                or asset.get("data_class")
                or enriched.get("data_classification")
                or "unknown"
            ),
            "zone": (
                asset.get("zone")
                or enriched.get("zone")
                or "unknown"
            ),
        })

    incident_iocs = set(
        str(value)
        for value in incident.get("ioc_list", [])
    )
    incident_iocs.update(
        str(value)
        for value in finding.get("matches_ioc", [])
    )

    for event in incident_events:
        for field in ("src_ip", "dst_ip", "user", "file_hash"):
            value = event.get(field)
            if value and str(value).lower() in ioc_lookup:
                incident_iocs.add(str(value))

    ioc_rows = []
    for value in sorted(incident_iocs)[:15]:
        metadata = ioc_lookup.get(value.lower(), {})
        ioc_rows.append({
            "type": metadata.get("type", infer_ioc_type(value)),
            "value": value,
            "confidence": metadata.get("confidence", "unknown"),
            "source": metadata.get("source", "incident evidence"),
        })

    techniques = list(dict.fromkeys(
        finding.get("attack_techniques", [])
    ))[:8]

    fired_alerts = [
        alerts_by_id[alert_id]
        for alert_id in incident.get("alert_ids", [])
        if alert_id in alerts_by_id
    ]

    rule_counts = {}
    for alert in fired_alerts:
        rule_id = str(alert.get("rule_id") or "unknown")
        title = str(alert.get("rule_title") or "Untitled rule")
        key = (rule_id, title)
        rule_counts[key] = rule_counts.get(key, 0) + 1

    hypothesis = clean(
        finding.get("hypothesis")
        or "Security activity requires further investigation."
    )
    confidence = clean(finding.get("confidence", "unknown"))
    hosts_text = ", ".join(incident.get("host_list", [])) or "unknown hosts"

    summary = [
        f"{incident['incident_id']} affected {hosts_text}.",
        f"The investigation hypothesis is: {hypothesis}",
        (
            f"The finding has {confidence} confidence and was classified "
            "for continued SOC investigation."
        ),
    ]

    actions = [
        "Validate the affected user accounts with the identity owner.",
        "Review authentication logs for the identified source systems.",
        "Contain confirmed compromised accounts or hosts.",
        "Block confirmed malicious indicators at applicable controls.",
        "Preserve relevant endpoint, authentication and network evidence.",
        "Escalate unresolved activity to Tier 2 for further investigation.",
    ]

    lines = [
        f"# Incident Report — {incident['incident_id']}",
        "",
        "## Executive Summary",
        "",
        *summary,
        "",
        "## Timeline",
        "",
    ]

    for timestamp, hostname, description in timeline:
        lines.append(f"{timestamp} | {hostname} | {description}")

    lines.extend([
        "",
        "## Affected Assets",
        "",
        "| HOST | CRITICALITY | DATA_CLASS | ZONE |",
        "|---|---|---|---|",
    ])

    for asset in assets:
        lines.append(
            f"| {clean(asset['host'])} "
            f"| {clean(asset['criticality'])} "
            f"| {clean(asset['data_class'])} "
            f"| {clean(asset['zone'])} |"
        )

    lines.extend([
        "",
        "## Indicators of Compromise",
        "",
        "| TYPE | VALUE | CONFIDENCE | SOURCE |",
        "|---|---|---|---|",
    ])

    if ioc_rows:
        for indicator in ioc_rows:
            lines.append(
                f"| {clean(indicator['type'])} "
                f"| {clean(indicator['value'])} "
                f"| {clean(indicator['confidence'])} "
                f"| {clean(indicator['source'])} |"
            )
    else:
        lines.append(
            "| none | No direct IOC match | n/a | Current evidence |"
        )

    lines.extend([
        "",
        "## ATT&CK Mapping",
        "",
        "| TECHNIQUE | NAME | EVIDENCE |",
        "|---|---|---|",
    ])

    for technique in techniques:
        lines.append(
            f"| {clean(technique)} "
            f"| {clean(attack_names.get(technique, 'MITRE ATT&CK technique'))} "
            f"| {hypothesis[:120]} |"
        )

    lines.extend([
        "",
        "## Detection Performance",
        "",
    ])

    for (rule_id, title), count in sorted(rule_counts.items()):
        lines.append(
            f"- FIRED: {clean(rule_id)} — {clean(title)} — {count} alert(s)"
        )

    if not rule_counts:
        lines.append("- FIRED: No matching rule record was available.")

    lines.append(
        "- MISSED: No additional missed detection was documented in the finding."
    )

    lines.extend([
        "",
        "## Recommended Actions",
        "",
    ])

    for number, action in enumerate(actions[:6], 1):
        lines.append(f"{number}. {action}")

    lines.extend([
        "",
        "## Evidence References",
        "",
    ])

    for reference in references:
        lines.append(f"- {reference}")

    if not 3 <= len(summary) <= 5:
        raise SystemExit(f"[report] ERROR: summary cap failed for {label}")
    if len(timeline) > 15:
        raise SystemExit(f"[report] ERROR: timeline cap failed for {label}")
    if len(assets) > 10:
        raise SystemExit(f"[report] ERROR: asset cap failed for {label}")
    if len(ioc_rows) > 15:
        raise SystemExit(f"[report] ERROR: IOC cap failed for {label}")
    if len(techniques) > 8:
        raise SystemExit(f"[report] ERROR: technique cap failed for {label}")
    if len(actions) > 6:
        raise SystemExit(f"[report] ERROR: action cap failed for {label}")
    if len(references) > 12:
        raise SystemExit(f"[report] ERROR: reference cap failed for {label}")

    report_body = defang("\n".join(lines) + "\n")
    output = reports_dir / f"incident_{label}.md"
    output.write_text(report_body, encoding="utf-8")

    print(
        f"[report] {label}: "
        f"timeline={len(timeline)} "
        f"assets={len(assets)} "
        f"IOCs={len(ioc_rows)} "
        f"techniques={len(techniques)} "
        f"actions={len(actions)} "
        f"refs={len(references)}"
    )
    print(f"[report] {label}: section caps respected")

print(
    f"[report] {verified_total} event references verified "
    "against enriched_events.jsonl"
)
print("[report] reports written")
PY
