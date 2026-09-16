#!/usr/bin/env bash
set -euo pipefail

: "${SHIFT_WORKSPACE:?Execute: source ./project_env.sh}"
: "${ASSETS_DIR:?ASSETS_DIR não definido}"
: "${WAZUH_EXPORTS:?WAZUH_EXPORTS não definido}"

FILES=(
  "$SHIFT_WORKSPACE/investigations/incident_A.json"
  "$SHIFT_WORKSPACE/investigations/incident_B.json"
  "$SHIFT_WORKSPACE/investigations/incident_C_cli.json"
  "$SHIFT_WORKSPACE/alerts/incidents.json"
  "$SHIFT_WORKSPACE/alerts/alert_queue.json"
  "$ASSETS_DIR/ioc_feed.json"
  "$WAZUH_EXPORTS/campaign_dashboard_summary.md"
  "$WAZUH_EXPORTS/exported_dashboard_workflow.json"
)

for file in "${FILES[@]}"; do
    [[ -s "$file" ]] || {
        echo "[campaign] ERROR: missing $file" >&2
        exit 1
    }
done

mkdir -p "$SHIFT_WORKSPACE/campaign"

echo "[campaign] loading 3 incident findings"

python3 - \
  "$SHIFT_WORKSPACE/investigations/incident_A.json" \
  "$SHIFT_WORKSPACE/investigations/incident_B.json" \
  "$SHIFT_WORKSPACE/investigations/incident_C_cli.json" \
  "$SHIFT_WORKSPACE/alerts/incidents.json" \
  "$SHIFT_WORKSPACE/alerts/alert_queue.json" \
  "$ASSETS_DIR/ioc_feed.json" \
  "$WAZUH_EXPORTS/campaign_dashboard_summary.md" \
  "$WAZUH_EXPORTS/exported_dashboard_workflow.json" \
  "$SHIFT_WORKSPACE/campaign/campaign_assessment.json" <<'PY'
import json
import re
import sys
from datetime import datetime

(
    finding_a_path,
    finding_b_path,
    finding_c_path,
    incidents_path,
    alerts_path,
    ioc_path,
    summary_path,
    workflow_path,
    output_path,
) = sys.argv[1:]

def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)

def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def collect_ioc_values(value):
    found = set()

    if isinstance(value, dict):
        if value.get("value") is not None:
            found.add(str(value["value"]).lower())

        for child in value.values():
            found.update(collect_ioc_values(child))

    elif isinstance(value, list):
        for child in value:
            found.update(collect_ioc_values(child))

    return found

findings = {
    "A": load_json(finding_a_path),
    "B": load_json(finding_b_path),
    "C": load_json(finding_c_path),
}

incident_document = load_json(incidents_path)
incident_records = incident_document["incidents"]
alerts_document = load_json(alerts_path)
alerts = alerts_document.get("alerts", []) if isinstance(alerts_document, dict) else alerts_document
ioc_feed = load_json(ioc_path)
workflow = load_json(workflow_path)

with open(summary_path, encoding="utf-8") as handle:
    summary_text = handle.read()

incidents = {}

for label in ("A", "B", "C"):
    incident_id = findings[label]["incident_id"]
    incidents[label] = next(
        record
        for record in incident_records
        if record["incident_id"] == incident_id
    )

ioc_values = collect_ioc_values(ioc_feed)
print(f"[campaign] ioc feed: {len(ioc_values)} IOCs loaded")

alerts_by_id = {
    alert.get("alert_id"): alert
    for alert in alerts
    if alert.get("alert_id")
}

feed_matches = {}

for label, incident in incidents.items():
    matches = set()

    for alert_id in incident.get("alert_ids", []):
        alert = alerts_by_id.get(alert_id, {})

        candidates = [
            alert.get("src_ip"),
            alert.get("dst_ip"),
            alert.get("user"),
        ]

        for candidate in candidates:
            if candidate is not None:
                normalized = str(candidate).lower()
                if normalized in ioc_values:
                    matches.add(normalized)

    feed_matches[label] = len(matches)

pairs = [("A", "B"), ("A", "C"), ("B", "C")]

ioc_matrix = {}
tactic_matrix = {}
temporal_matrix = {}
linked_pairs = []

for left, right in pairs:
    pair_name = f"{left}-{right}"

    left_iocs = {
        str(value).lower()
        for value in incidents[left].get("ioc_list", [])
    }
    right_iocs = {
        str(value).lower()
        for value in incidents[right].get("ioc_list", [])
    }

    shared_iocs = left_iocs & right_iocs

    left_tactics = set(findings[left].get("attack_techniques", []))
    right_tactics = set(findings[right].get("attack_techniques", []))
    shared_tactics = left_tactics & right_tactics

    left_first = parse_time(incidents[left]["first_seen"])
    left_last = parse_time(incidents[left]["last_seen"])
    right_first = parse_time(incidents[right]["first_seen"])
    right_last = parse_time(incidents[right]["last_seen"])

    if left_last < right_first:
        distance = int((right_first - left_last).total_seconds() / 60)
    elif right_last < left_first:
        distance = int((left_first - right_last).total_seconds() / 60)
    else:
        distance = 0

    shared_hosts = (
        {host.lower() for host in incidents[left].get("host_list", [])}
        & {host.lower() for host in incidents[right].get("host_list", [])}
    )

    shared_users = (
        {
            user.lower()
            for user in incidents[left].get("user_list", [])
            if user
        }
        & {
            user.lower()
            for user in incidents[right].get("user_list", [])
            if user
        }
    )

    ioc_rule = (
        len(shared_iocs) >= 1
        and (feed_matches[left] > 0 or feed_matches[right] > 0)
    )
    tactic_rule = len(shared_tactics) >= 2 and distance <= 360
    identity_rule = bool(shared_hosts or shared_users)

    if ioc_rule or tactic_rule or identity_rule:
        linked_pairs.append(pair_name)

    ioc_matrix[pair_name] = len(shared_iocs)
    tactic_matrix[pair_name] = len(shared_tactics)
    temporal_matrix[pair_name] = distance

    reasons = []
    if ioc_rule:
        reasons.append("shared_ioc")
    if tactic_rule:
        reasons.append("tactic_temporal")
    if shared_hosts:
        reasons.append("shared_host")
    if shared_users:
        reasons.append("shared_user")

    reason_text = "+".join(reasons) if reasons else "not_linked"

    print(
        f"[campaign] {pair_name}: "
        f"ioc_overlap={len(shared_iocs)} "
        f"tactic_overlap={len(shared_tactics)} "
        f"temporal_dist={distance}min "
        f"result={reason_text}"
    )

campaign_linked = len(linked_pairs) >= 1

linked_labels = set()
for pair_name in linked_pairs:
    linked_labels.update(pair_name.split("-"))

linked_has_feed_match = any(
    feed_matches[label] > 0
    for label in linked_labels
)

cluster_id = (
    "HC-RED7"
    if campaign_linked and linked_has_feed_match
    else "unknown"
)

if campaign_linked and cluster_id == "HC-RED7":
    confidence = "high"
elif campaign_linked:
    confidence = "medium"
else:
    confidence = "low"

campaign_match = re.search(
    r"campaign_linked:\*\*\s*(true|false)",
    summary_text,
    re.IGNORECASE,
)
cluster_match = re.search(
    r"cluster_id:\*\*\s*([A-Za-z0-9-]+)",
    summary_text,
    re.IGNORECASE,
)
confidence_match = re.search(
    r"confidence:\*\*\s*(low|medium|high)",
    summary_text,
    re.IGNORECASE,
)

export_campaign = (
    campaign_match.group(1).lower()
    if campaign_match
    else workflow.get("verdict", "unknown")
)
export_cluster = (
    cluster_match.group(1)
    if cluster_match
    else workflow.get("cluster", "unknown")
)
export_confidence = (
    confidence_match.group(1).lower()
    if confidence_match
    else "unknown"
)

export_verdict = (
    f"campaign_linked={export_campaign} "
    f"cluster={export_cluster} "
    f"confidence={export_confidence}"
)

result = {
    "incidents": [
        incidents["A"]["incident_id"],
        incidents["B"]["incident_id"],
        incidents["C"]["incident_id"],
    ],
    "ioc_overlap_matrix": ioc_matrix,
    "tactic_overlap_matrix": tactic_matrix,
    "temporal_distance_minutes": temporal_matrix,
    "ioc_feed_matches": feed_matches,
    "linked_pairs": linked_pairs,
    "campaign_linked": campaign_linked,
    "cluster_id": cluster_id,
    "confidence": confidence,
    "export_view_verdict": export_verdict,
    "supporting_counts": {
        "shared_iocs_total": sum(ioc_matrix.values()),
        "shared_tactics_total": sum(tactic_matrix.values()),
    },
}

with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(result, handle, indent=2)
    handle.write("\n")

print(
    f"[campaign] feed matches: "
    f"A={feed_matches['A']} "
    f"B={feed_matches['B']} "
    f"C={feed_matches['C']}"
)
print(
    "[campaign] linked pairs: "
    + (" ".join(linked_pairs) if linked_pairs else "none")
)
print(f"[campaign] export view: {export_verdict}")
print(
    f"[campaign] verdict: "
    f"campaign_linked={str(campaign_linked).lower()} "
    f"cluster={cluster_id} "
    f"confidence={confidence}"
)
print("[campaign] campaign_assessment.json written")
PY
