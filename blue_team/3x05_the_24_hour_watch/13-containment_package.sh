#!/bin/bash
set -euo pipefail

: "${SHIFT_WORKSPACE:?Execute: source ./project_env.sh}"
: "${ASSETS_DIR:?ASSETS_DIR não definido}"

python3 - "$SHIFT_WORKSPACE" "$ASSETS_DIR" <<'PY'
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

workspace = Path(sys.argv[1])
assets_dir = Path(sys.argv[2])

campaign_file = workspace / "campaign/campaign_assessment.json"
incidents_file = workspace / "alerts/incidents.json"
ioc_feed_file = assets_dir / "ioc_feed.json"
response_dir = workspace / "response"

finding_files = {
    "A": workspace / "investigations/incident_A.json",
    "B": workspace / "investigations/incident_B.json",
    "C": workspace / "investigations/incident_C_cli.json",
}

required = [
    campaign_file,
    incidents_file,
    ioc_feed_file,
    *finding_files.values(),
]

for path in required:
    if not path.is_file() or path.stat().st_size == 0:
        raise SystemExit(f"[resp] ERROR: missing {path}")

response_dir.mkdir(parents=True, exist_ok=True)

def load_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)

def collect_feed_iocs(value, result=None):
    if result is None:
        result = {}

    if isinstance(value, dict):
        if value.get("value") is not None:
            indicator = str(value["value"])
            result[indicator.lower()] = {
                "value": indicator,
                "type": value.get("type") or infer_type(indicator),
                "confidence": value.get("confidence", "high"),
            }

        for child in value.values():
            collect_feed_iocs(child, result)

    elif isinstance(value, list):
        for child in value:
            collect_feed_iocs(child, result)

    return result

def infer_type(value):
    value = str(value)

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{32,64}", value):
        return "hash"
    if value.isdigit() and 0 <= int(value) <= 65535:
        return "port"
    if "." in value and "@" not in value:
        return "domain"
    return "account"

def defang(value, indicator_type):
    value = str(value)

    if indicator_type in {"ip", "domain"}:
        return value.replace(".", "[.]")

    return value

def add_action(
    actions,
    priority,
    action,
    target_type,
    target_value,
    incident_id,
    impact,
    approval,
):
    if not target_value:
        return

    action = action[:160]
    impact = impact[:160]

    actions.append({
        "action_id": f"ACT-{len(actions) + 1:03d}",
        "priority": priority,
        "action": action,
        "target_type": target_type,
        "target_value": str(target_value),
        "incident_id": incident_id,
        "operational_impact": impact,
        "requires_approval_from": approval,
    })

print("[resp] loading campaign_assessment and incidents")

campaign = load_json(campaign_file)
incident_document = load_json(incidents_file)
incidents = incident_document["incidents"]
feed_iocs = collect_feed_iocs(load_json(ioc_feed_file))

incident_ids = {
    incident["incident_id"]
    for incident in incidents
}

shift_id = (
    incident_document.get("shift_id")
    or f"SHIFT-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
)

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

findings = {}
for label, path in finding_files.items():
    findings[label] = load_json(path)

actions = []

for label in ("A", "B", "C"):
    finding = findings[label]
    incident_id = finding["incident_id"]

    incident = next(
        item
        for item in incidents
        if item["incident_id"] == incident_id
    )

    hosts = incident.get("host_list", [])
    users = [
        user
        for user in incident.get("user_list", [])
        if user
    ]

    primary_host = hosts[0] if hosts else None
    user_target = ", ".join(users[:3]) if users else None

    add_action(
        actions,
        "immediate",
        f"Temporarily isolate {primary_host} pending Tier 2 validation.",
        "host",
        primary_host,
        incident_id,
        "Host loses normal network connectivity; clinical or business services may be interrupted.",
        "SOC Incident Commander",
    )

    add_action(
        actions,
        "short_term",
        f"Reset credentials and revoke active sessions for {user_target}.",
        "user",
        user_target,
        incident_id,
        "Users must authenticate again and may require service-desk assistance.",
        "Identity and Access Management",
    )

    add_action(
        actions,
        "medium_term",
        f"Review and tighten firewall access affecting {primary_host}.",
        "rule",
        primary_host,
        incident_id,
        "Firewall changes may interrupt legitimate application traffic.",
        "Security Architecture",
    )

    add_action(
        actions,
        "medium_term",
        f"Deploy additional Sysmon or audit coverage on {primary_host}.",
        "host",
        primary_host,
        incident_id,
        "Additional telemetry may increase endpoint and SIEM resource usage.",
        "Endpoint Engineering",
    )

actions = actions[:12]

for action in actions:
    if action["incident_id"] not in incident_ids:
        raise SystemExit(
            f"[resp] ERROR: invalid incident in {action['action_id']}"
        )

    if len(action["action"]) > 160:
        raise SystemExit(
            f"[resp] ERROR: action text too long in {action['action_id']}"
        )

    if len(action["operational_impact"]) > 160:
        raise SystemExit(
            f"[resp] ERROR: impact text too long in {action['action_id']}"
        )

containment = {
    "shift_id": shift_id,
    "generated_at": generated_at,
    "actions": actions,
}

containment_file = response_dir / "containment.json"
with containment_file.open("w", encoding="utf-8") as handle:
    json.dump(containment, handle, indent=2)
    handle.write("\n")

iocs = []
seen_iocs = set()
newly_discovered = 0

for label in ("A", "B", "C"):
    finding = findings[label]
    incident_id = finding["incident_id"]

    incident = next(
        item
        for item in incidents
        if item["incident_id"] == incident_id
    )

    event_refs = [
        ref
        for ref in finding.get("event_refs", [])
        if ref
    ]

    candidates = []

    for value in finding.get("matches_ioc", []):
        candidates.append((str(value), infer_type(value)))

    for value in incident.get("ioc_list", []):
        candidates.append((str(value), infer_type(value)))

    for user in incident.get("user_list", []):
        if user:
            candidates.append((str(user), "account"))

    for value, indicator_type in candidates:
        normalized = value.lower()
        dedup_key = (incident_id, indicator_type, normalized)

        if dedup_key in seen_iocs:
            continue

        if not event_refs:
            raise SystemExit(
                f"[resp] ERROR: IOC {value} has no event backing "
                f"in {incident_id}"
            )

        seen_iocs.add(dedup_key)

        feed_match = feed_iocs.get(normalized)
        source = "ioc_feed" if feed_match else "shift_discovered"

        if not feed_match:
            newly_discovered += 1

        iocs.append({
            "type": (
                feed_match.get("type", indicator_type)
                if feed_match
                else indicator_type
            ),
            "value": defang(value, indicator_type),
            "first_seen": incident["first_seen"],
            "last_seen": incident["last_seen"],
            "incident_id": incident_id,
            "source": source,
            "confidence": finding.get("confidence", "medium"),
            "event_refs": event_refs[:12],
        })

for indicator in iocs:
    if not indicator.get("event_refs"):
        raise SystemExit(
            f"[resp] ERROR: untraceable IOC {indicator['value']}"
        )

ioc_package = {
    "shift_id": shift_id,
    "tlp": "AMBER",
    "cluster_id": campaign.get("cluster_id", "unknown"),
    "generated_at": generated_at,
    "iocs": iocs,
}

ioc_package_file = response_dir / "ioc_package.json"
with ioc_package_file.open("w", encoding="utf-8") as handle:
    json.dump(ioc_package, handle, indent=2)
    handle.write("\n")

priorities = {
    "immediate": 0,
    "short_term": 0,
    "medium_term": 0,
}

for action in actions:
    priorities[action["priority"]] += 1

types = {
    "ip": 0,
    "domain": 0,
    "hash": 0,
    "account": 0,
    "service_name": 0,
    "port": 0,
}

for indicator in iocs:
    indicator_type = indicator["type"]
    types[indicator_type] = types.get(indicator_type, 0) + 1

print(
    "[resp] actions: "
    f"immediate={priorities['immediate']} "
    f"short_term={priorities['short_term']} "
    f"medium_term={priorities['medium_term']} "
    f"total={len(actions)}"
)

print(
    "[resp] IOCs: "
    f"ip={types['ip']} "
    f"domain={types['domain']} "
    f"hash={types['hash']} "
    f"account={types['account']} "
    f"service={types['service_name']} "
    f"total={len(iocs)}"
)

print(f"[resp] newly discovered (not in feed): {newly_discovered}")
print("[resp] all IOCs traced to events: OK")
print("[resp] containment.json written")
print("[resp] ioc_package.json written")
PY
