#!/bin/bash
set -euo pipefail

: "${SHIFT_WORKSPACE:?Execute: source ./project_env.sh}"

python3 - "$SHIFT_WORKSPACE" <<'PY'
import hashlib
import json
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

workspace = Path(sys.argv[1])
handoff_dir = workspace / "handoff"
handoff_dir.mkdir(parents=True, exist_ok=True)

def choose(*paths):
    for path in paths:
        candidate = workspace / path
        if candidate.is_file() and candidate.stat().st_size > 0:
            return path
    return paths[0]

required = [
    "runtime/shift_start.json",
    "runtime/pipeline_run.json",
    "runtime/baseline_run.json",
    "runtime/catalog_run.json",
    choose(
        "enriched/enriched_events.jsonl",
        "enriched/enriched_events.json",
    ),
    choose(
        "enriched/timeline.jsonl",
        "enriched/timeline_index.json",
    ),
    "enriched/source_stats.json",
    "enriched/baseline.json",
    "alerts/alert_queue.json",
    "alerts/shift_briefing.json",
    "alerts/triage_log.jsonl",
    "alerts/incidents.json",
    "investigations/incident_A.json",
    "investigations/incident_B.json",
    "investigations/incident_C_cli.json",
    "campaign/campaign_assessment.json",
    "reports/incident_A.md",
    "reports/incident_B.md",
    "reports/incident_C.md",
    "response/containment.json",
    "response/ioc_package.json",
]

print("[handoff] checking workspace layout...")

for relative_path in required:
    path = workspace / relative_path

    if not path.is_file():
        raise SystemExit(
            f"[handoff] ERROR: missing {relative_path}"
        )

    if path.stat().st_size == 0:
        raise SystemExit(
            f"[handoff] ERROR: empty {relative_path}"
        )

    print(f"[handoff] OK: {relative_path}")

def load_json(relative_path):
    with (workspace / relative_path).open(encoding="utf-8") as handle:
        return json.load(handle)

def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()

def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

shift = load_json("runtime/shift_start.json")
incidents_document = load_json("alerts/incidents.json")
campaign = load_json("campaign/campaign_assessment.json")
briefing = load_json("alerts/shift_briefing.json")

shift_id = shift.get("shift_id", "unknown")
analyst_host = (
    shift.get("analyst_host")
    or shift.get("hostname")
    or socket.gethostname()
)
started_at = shift.get("started_at")

if not started_at:
    raise SystemExit("[handoff] ERROR: started_at missing")

ended_dt = datetime.now(timezone.utc)
ended_at = ended_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
duration_hours = round(
    (ended_dt - parse_time(started_at)).total_seconds() / 3600,
    2,
)

incidents = incidents_document.get("incidents", [])
incident_ids = [
    incident["incident_id"]
    for incident in incidents
]

if not incident_ids:
    raise SystemExit("[handoff] ERROR: no incidents found")

findings = {
    "A": load_json("investigations/incident_A.json"),
    "B": load_json("investigations/incident_B.json"),
    "C": load_json("investigations/incident_C_cli.json"),
}

report_paths = {
    "A": "reports/incident_A.md",
    "B": "reports/incident_B.md",
    "C": "reports/incident_C.md",
}

file_entries = []

for relative_path in required:
    path = workspace / relative_path
    file_entries.append({
        "path": relative_path,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    })

ioc_count = briefing.get("ioc_count", 0)
cluster_context = briefing.get("cluster_id", "HC-RED7")

first_seen_values = [
    incident.get("first_seen")
    for incident in incidents
    if incident.get("first_seen")
]
last_seen_values = [
    incident.get("last_seen")
    for incident in incidents
    if incident.get("last_seen")
]

pack_start = min(first_seen_values) if first_seen_values else "unknown"
pack_end = max(last_seen_values) if last_seen_values else "unknown"

lines = [
    "# MedDefense SOC Shift Handoff",
    "",
    "## Shift Identifier",
    "",
    f"- Shift ID: {shift_id}",
    f"- Analyst host: {analyst_host}",
    f"- Started: {started_at}",
    f"- Ended: {ended_at}",
    f"- Duration: {duration_hours} hours",
    "",
    "## Situation",
    "",
    (
        f"MedDefense operated under heightened monitoring following the "
        f"{cluster_context} healthcare-sector advisory."
    ),
    (
        f"The shift briefing contained {ioc_count} threat indicators for "
        "mechanical comparison against observed activity."
    ),
    (
        f"The investigated incident period runs from {pack_start} through "
        f"{pack_end}."
    ),
    (
        "The processed evidence and Wazuh export describe partially "
        "different host sets, so unsupported attribution was avoided."
    ),
    "",
    "## Incidents",
    "",
]

for label in ("A", "B", "C"):
    finding = findings[label]
    incident_id = finding["incident_id"]
    confidence = finding.get("confidence", "unknown")
    techniques = finding.get("attack_techniques", [])
    primary_technique = techniques[0] if techniques else "unmapped"

    verdict = (
        "TP"
        if confidence == "high"
        else "TP with unresolved ambiguity"
    )

    lines.append(
        f"{incident_id}: {verdict}; primary ATT&CK technique "
        f"{primary_technique}. Full report: `{report_paths[label]}`."
    )
    lines.append("")

campaign_linked = campaign.get("campaign_linked", False)
cluster_id = campaign.get("cluster_id", "unknown")
campaign_confidence = campaign.get("confidence", "unknown")

lines.extend([
    "## Campaign Assessment",
    "",
    (
        f"The mechanical assessment found campaign_linked="
        f"{str(campaign_linked).lower()}, cluster_id={cluster_id}, "
        f"and confidence={campaign_confidence}. The Wazuh export reports "
        "HC-RED7, but the processed evidence contains no direct feed match. "
        "See `campaign/campaign_assessment.json`."
    ),
    "",
    "## Open Items for Next Shift",
    "",
])

open_items = []

for label in ("A", "B", "C"):
    finding = findings[label]
    ambiguity = str(finding.get("ambiguity_notes", "")).strip()

    if ambiguity:
        open_items.append(
            f"- {finding['incident_id']}: {ambiguity}"
        )

open_items.extend([
    (
        "- Reconcile the evidence-pack hostnames with the Wazuh export "
        "using the original collection manifest and index metadata."
    ),
    (
        "- Validate affected accounts using identity-provider, VPN and "
        "domain-controller authentication logs."
    ),
    (
        "- Confirm containment execution using firewall, IAM and endpoint "
        "change records."
    ),
])

lines.extend(open_items[:8])

lines.extend([
    "",
    "## Artifact Index",
    "",
    "| Relative path | SHA256 |",
    "|---|---|",
])

for entry in file_entries:
    lines.append(
        f"| `{entry['path']}` | `{entry['sha256']}` |"
    )

lines.append("")

handoff_path = handoff_dir / "shift_handoff.md"
handoff_path.write_text("\n".join(lines), encoding="utf-8")

required_headings = [
    "## Shift Identifier",
    "## Situation",
    "## Incidents",
    "## Campaign Assessment",
    "## Open Items for Next Shift",
    "## Artifact Index",
]

handoff_text = handoff_path.read_text(encoding="utf-8")

for heading in required_headings:
    if heading not in handoff_text:
        raise SystemExit(
            f"[handoff] ERROR: missing section {heading}"
        )

word_count = len(re.findall(r"\b[\w.-]+\b", handoff_text))

if word_count > 900:
    raise SystemExit(
        f"[handoff] ERROR: {word_count} words exceeds 900"
    )

handoff_incident_ids = set(
    re.findall(r"INC-\d{8}-[A-Z]", handoff_text)
)

unknown_incidents = handoff_incident_ids - set(incident_ids)

if unknown_incidents:
    raise SystemExit(
        "[handoff] ERROR: unknown incident IDs: "
        + ", ".join(sorted(unknown_incidents))
    )

file_entries.append({
    "path": "handoff/shift_handoff.md",
    "sha256": sha256_file(handoff_path),
    "size": handoff_path.stat().st_size,
})

artifact_counts = {
    "runtime": 0,
    "enriched": 0,
    "alerts": 0,
    "investigations": 0,
    "campaign": 0,
    "reports": 0,
    "response": 0,
    "handoff": 0,
}

for entry in file_entries:
    top_directory = entry["path"].split("/", 1)[0]

    if top_directory in artifact_counts:
        artifact_counts[top_directory] += 1

manifest = {
    "shift_id": shift_id,
    "analyst_host": analyst_host,
    "started_at": started_at,
    "ended_at": ended_at,
    "duration_hours": duration_hours,
    "files": file_entries,
    "artifact_counts": artifact_counts,
    "incident_ids": incident_ids,
    "campaign_linked": campaign_linked,
    "cluster_id": cluster_id,
}

manifest_path = workspace / "MANIFEST.json"

with manifest_path.open("w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2)
    handle.write("\n")

total_size = sum(entry["size"] for entry in file_entries)
total_kb = round(total_size / 1024, 1)

print(f"[handoff] checking workspace layout... {len(file_entries)} files OK")
print(f"[handoff] shift_id: {shift_id}")
print(f"[handoff] duration: {duration_hours} hours")
print(
    f"[handoff] shift_handoff.md: {word_count} words, "
    "6 sections OK"
)
print(
    "[handoff] incident IDs in handoff: "
    + " ".join(sorted(handoff_incident_ids))
    + " (all in incidents.json: OK)"
)
print(
    f"[handoff] MANIFEST.json: {len(file_entries)} files, "
    f"{total_kb} KB total"
)
print(
    f"[handoff] campaign_linked="
    f"{str(campaign_linked).lower()} cluster={cluster_id}"
)
print("[handoff] handoff package complete")
PY
