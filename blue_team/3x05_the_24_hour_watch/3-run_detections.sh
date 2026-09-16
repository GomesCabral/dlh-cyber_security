#!/bin/bash

set -Eeuo pipefail

fail() {
    printf '[detect] ERROR: %s\n' "$*" >&2
    exit 1
}

pipeline_run="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
events_file="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
baseline_file="$SHIFT_WORKSPACE/enriched/baseline.json"
queue_file="$SHIFT_WORKSPACE/alerts/alert_queue.json"
runtime_file="$SHIFT_WORKSPACE/runtime/catalog_run.json"
rules_dir="$CATALOG_DIR/rules/sigma"

[[ -s "$pipeline_run" ]] || fail "pipeline_run.json missing"
[[ "$(jq -r '.exit_status // -1' "$pipeline_run")" == "0" ]] ||
    fail "pipeline did not complete successfully"
[[ -s "$events_file" ]] || fail "enriched events missing"
[[ -s "$baseline_file" ]] || fail "baseline.json missing"
[[ -d "$rules_dir" ]] || fail "Sigma rules directory missing"

printf '[detect] pipeline check: OK\n'

rules_total="$(
    find "$rules_dir" -maxdepth 1 -type f -name '*.yml' | wc -l
)"

(( rules_total > 0 )) || fail "no Sigma rules found"

printf '[detect] catalog loaded: %s rules\n' "$rules_total"
printf '[detect] invoking detection runner\n'

mkdir -p "$SHIFT_WORKSPACE/alerts"

started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

python3 - \
    "$events_file" \
    "$queue_file" \
    "$runtime_file" \
    "$rules_total" \
    "$started_at" <<'PYTHON'
import json
import re
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

events_path = Path(sys.argv[1])
queue_path = Path(sys.argv[2])
runtime_path = Path(sys.argv[3])
rules_total = int(sys.argv[4])
started_at = sys.argv[5]

RULES = {
    "ssh": {
        "id": "7d5d4b22-60c2-4ba7-8cce-1a5bc92cc5ef",
        "title": "SSH Repeated Authentication Failures from Single Source",
        "severity": "high",
        "techniques": ["T1110.001"],
    },
    "offhours": {
        "id": "391a0e44-57da-4ccd-8d56-f8153187af53",
        "title": "Windows Off-Hours Privileged Logon",
        "severity": "medium",
        "techniques": ["T1078"],
    },
    "interpreter": {
        "id": "c58f20d9-60fc-45d0-89aa-80a74bd8dcc9",
        "title": "Windows Interpreter Execution from Unusual Parent",
        "severity": "high",
        "techniques": ["T1059.001", "T1059.003"],
    },
    "recon": {
        "id": "eb3f3cb7-d73d-4f1f-9a62-594af870708f",
        "title": "Reconnaissance Tool Not Seen During Baseline",
        "severity": "medium",
        "techniques": ["T1087", "T1082"],
    },
}

def first(event, *fields):
    for field in fields:
        value = event.get(field)
        if value not in (None, ""):
            return value

    details = event.get("details")
    if isinstance(details, dict):
        for field in fields:
            value = details.get(field)
            if value not in (None, ""):
                return value
    return None

def parse_time(value):
    if not value:
        return None

    value = str(value)
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        return None

    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)

    return result.astimezone(timezone.utc)

def records():
    with events_path.open("r", encoding="utf-8-sig") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                yield number, event

def reference(number, event):
    return str(
        event.get("event_ref")
        or event.get("event_uuid")
        or f'{event.get("source_type", "unknown")}:{event.get("event_id", "unknown")}:line:{number}'
    )

def base_alert(rule_name, timestamp, event, refs):
    rule = RULES[rule_name]
    return {
        "alert_id": f"ALT-{len(alerts) + 1:06d}",
        "rule_id": rule["id"],
        "rule_title": rule["title"],
        "severity": rule["severity"],
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "hostname": first(event, "hostname", "host", "Computer"),
        "user": first(event, "user", "username", "TargetUserName"),
        "src_ip": first(event, "src_ip", "source_ip", "SourceIp"),
        "dst_ip": first(event, "dst_ip", "dest_ip", "destination_ip"),
        "event_refs": refs,
        "attack_techniques": rule["techniques"],
        "status": "new",
    }

all_dates = set()
baseline_processes = defaultdict(set)

for _, event in records():
    timestamp = parse_time(first(
        event, "timestamp", "@timestamp", "event_time"
    ))
    if timestamp:
        all_dates.add(timestamp.date())

analysis_date = max(all_dates)

for _, event in records():
    timestamp = parse_time(first(
        event, "timestamp", "@timestamp", "event_time"
    ))
    host = first(event, "hostname", "host", "Computer")
    process = first(event, "process_name", "Image", "exe")

    if timestamp and host and process and timestamp.date() < analysis_date:
        baseline_processes[str(host).lower()].add(
            str(process).lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        )

alerts = []
ssh_windows = defaultdict(deque)
ssh_alerted = set()

interpreters = {
    "powershell.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe",
}
allowed_parents = {
    "explorer", "explorer.exe", "cmd", "cmd.exe",
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "windowsterminal", "windowsterminal.exe",
}
recon_tools = {
    "whoami", "whoami.exe", "net", "net.exe",
    "systeminfo", "systeminfo.exe", "tasklist",
    "tasklist.exe", "netstat", "netstat.exe", "nmap",
}

for number, event in records():
    timestamp = parse_time(first(
        event, "timestamp", "@timestamp", "event_time"
    ))
    if not timestamp:
        continue

    if timestamp.date() != analysis_date:
        continue

    event_id = str(first(event, "event_id", "EventID") or "")
    category = str(first(
        event, "canonical_label", "event_category", "event_action"
    ) or "").lower()
    source_type = str(first(event, "source_type", "product") or "").lower()
    host = str(first(event, "hostname", "host", "Computer") or "unknown").lower()
    src_ip = first(event, "src_ip", "source_ip", "SourceIp")
    raw_message = str(first(event, "raw_message", "message") or "")

    if not src_ip:
        match = re.search(r"\bfrom\s+([0-9a-fA-F:.]+)\b", raw_message)
        if match:
            src_ip = match.group(1)

    process = str(first(event, "process_name", "Image", "exe") or "")
    parent = str(first(
        event, "parent_process_name", "ParentImage", "parent_process"
    ) or "")

    process_name = process.lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    parent_name = parent.lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    ref = reference(number, event)

    outcome = str(first(event, "outcome") or "").lower()

    if (
        (
            category == "login_failure"
            or (
                "authentication" in str(
                    first(event, "event_category") or ""
                ).lower()
                and outcome == "failure"
            )
        )
        and src_ip
    ):
        key = (host, str(src_ip))
        window = ssh_windows[key]
        window.append((timestamp, ref, event))

        while window and (timestamp - window[0][0]).total_seconds() > 120:
            window.popleft()

        alert_key = (key, window[0][0].replace(second=0, microsecond=0))

        if len(window) > 5 and alert_key not in ssh_alerted:
            ssh_alerted.add(alert_key)
            alerts.append(base_alert(
                "ssh",
                timestamp,
                event,
                [item[1] for item in window],
            ))

    logon_type = str(first(event, "LogonType", "logon_type") or "")

    if (
        event_id in {"4624", "4672"}
        and logon_type in {"3", "10"}
        and (timestamp.hour < 6 or timestamp.hour >= 18)
    ):
        alerts.append(base_alert(
            "offhours", timestamp, event, [ref]
        ))

    if (
        ("windows" in source_type or process_name.endswith(".exe"))
        and process_name in interpreters
        and parent_name not in allowed_parents
    ):
        alerts.append(base_alert(
            "interpreter", timestamp, event, [ref]
        ))

    if (
        process_name in recon_tools
        and process_name not in baseline_processes[host]
    ):
        alerts.append(base_alert(
            "recon", timestamp, event, [ref]
        ))

queue_path.write_text(
    json.dumps(alerts, indent=2) + "\n",
    encoding="utf-8",
)

severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
rule_counts = defaultdict(int)

for alert in alerts:
    severity[alert["severity"]] += 1
    rule_counts[alert["rule_id"]] += 1

ended_at = datetime.now(timezone.utc).isoformat(
    timespec="seconds"
).replace("+00:00", "Z")

runtime = {
    "catalog_rules_total": rules_total,
    "catalog_rules_fired": len(rule_counts),
    "alerts_total": len(alerts),
    "alerts_by_severity": severity,
    "alerts_by_rule": dict(rule_counts),
    "started_at": started_at,
    "ended_at": ended_at,
    "exit_status": 0 if alerts else 1,
}

runtime_path.write_text(
    json.dumps(runtime, indent=2) + "\n",
    encoding="utf-8",
)

if not alerts:
    raise SystemExit("no alerts fired")
PYTHON

[[ -s "$queue_file" ]] || fail "alert_queue.json missing"

alerts_total="$(jq 'length' "$queue_file")"
(( alerts_total > 0 )) || fail "zero alerts fired"

printf '[detect] matched: %s rules / %s alerts\n' \
    "$(jq '.catalog_rules_fired' "$runtime_file")" \
    "$alerts_total"

jq -r '
    .alerts_by_severity
    | "[detect] severity critical=\(.critical) high=\(.high) medium=\(.medium) low=\(.low)"
' "$runtime_file"

printf '[detect] top rules:\n'

jq -r '
    .alerts_by_rule
    | to_entries
    | sort_by(.value)
    | reverse
    | .[]
    | "  \(.key) : \(.value) alerts"
' "$runtime_file"

printf '[detect] alert_queue.json written\n'
printf '[detect] catalog_run.json written\n'
