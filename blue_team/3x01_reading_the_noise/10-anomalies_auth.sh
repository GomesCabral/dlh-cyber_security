#!/bin/bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"
readonly SUMMARY_FILE="${BASELINE_SUMMARY:-${SCRIPT_DIR}/baseline_summary.json}"
readonly LABELED_EVENTS="${LABELED_EVENTS:-${SCRIPT_DIR}/labeled_events.json}"
readonly OUTPUT_FILE="${SCRIPT_DIR}/anomalies_auth.json"

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || die "python3 is required"
[[ -d "$HANDOFF_DIR" ]] || die "handoff directory is not accessible: $HANDOFF_DIR"
[[ -r "$SUMMARY_FILE" ]] || die "baseline summary is not readable: $SUMMARY_FILE"
[[ -r "$LABELED_EVENTS" ]] || die "labeled dataset is not readable: $LABELED_EVENTS"

output_tmp=$(mktemp "${SCRIPT_DIR}/.anomalies_auth.XXXXXX")
cleanup() {
    rm -f -- "$output_tmp"
}
trap cleanup EXIT

python3 -W error - "$SUMMARY_FILE" "$LABELED_EVENTS" "$output_tmp" <<'PY'
import collections
import datetime as dt
import json
import pathlib
import sys


AUTH_LABELS = {
    "login_success",
    "login_failure",
    "logout",
    "account_lockout",
    "privilege_escalation",
}


def concise_error(error_type, error, traceback):
    del error_type, traceback
    print(f"Error: {error}", file=sys.stderr)


sys.excepthook = concise_error


def parse_timestamp(value: object, field_name: str) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing {field_name}")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"invalid ISO-8601 {field_name}: {value}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def iso_z(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def threshold_value(thresholds: dict, name: str) -> float:
    entry = thresholds.get(name)
    value = entry.get("value") if isinstance(entry, dict) else entry
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"thresholds.{name} must contain a numeric value")
    return value


def event_reference(event: dict, line_number: int) -> str:
    for field in ("event_ref", "event_uuid", "id"):
        value = event.get(field)
        if value not in (None, ""):
            return str(value)
    source = event.get("source_type", "unknown")
    event_id = event.get("event_id", "na")
    return f"{source}:{event_id}:line:{line_number}"


def normalized_value(value: object, default: str = "unknown") -> str:
    return default if value in (None, "", "-") else str(value)


summary_path = pathlib.Path(sys.argv[1])
events_path = pathlib.Path(sys.argv[2])
output_path = pathlib.Path(sys.argv[3])

try:
    with summary_path.open("r", encoding="utf-8") as stream:
        summary = json.load(stream)
except json.JSONDecodeError as error:
    raise ValueError(f"invalid baseline summary JSON: {error}") from error

if not isinstance(summary, dict):
    raise ValueError("baseline summary must be a JSON object")

evaluation = summary.get("evaluation_window")
if not isinstance(evaluation, dict):
    raise ValueError("baseline summary has no evaluation_window")
evaluation_start = parse_timestamp(evaluation.get("start"), "evaluation_window.start")
evaluation_end = parse_timestamp(evaluation.get("end"), "evaluation_window.end")
if evaluation_end <= evaluation_start:
    raise ValueError("evaluation window end must be after start")

auth = summary.get("auth")
if not isinstance(auth, dict):
    raise ValueError("baseline summary has no auth section")
known_accounts_raw = auth.get("known_accounts")
per_user_raw = auth.get("per_user")
per_host = auth.get("per_host")
if not isinstance(known_accounts_raw, list):
    raise ValueError("auth.known_accounts must be a list")
if not isinstance(per_user_raw, list):
    raise ValueError("auth.per_user must be a list")
if not isinstance(per_host, dict):
    raise ValueError("auth.per_host must be an object")

known_accounts = {str(user) for user in known_accounts_raw}
business_only_users = set()
for record in per_user_raw:
    if not isinstance(record, dict) or "user" not in record:
        raise ValueError("each auth.per_user entry must contain user")
    if "business_hours_success" not in record or "offhours_success" not in record:
        raise ValueError(
            "auth.per_user lacks business/off-hours counters; rerun the updated Task 4"
        )
    business_success = record["business_hours_success"]
    offhours_success = record["offhours_success"]
    if not isinstance(business_success, int) or not isinstance(offhours_success, int):
        raise ValueError("per-user business/off-hours counters must be integers")
    if business_success > 0 and offhours_success == 0:
        business_only_users.add(str(record["user"]))

thresholds = summary.get("thresholds")
if not isinstance(thresholds, dict):
    raise ValueError("baseline summary has no thresholds section")
failure_multiplier = threshold_value(thresholds, "failure_rate_multiplier")
privilege_surge_limit = int(
    threshold_value(thresholds, "privilege_escalation_surge_threshold")
)
baseline_failure_max = auth.get("max_failures_1h_window")
if not isinstance(baseline_failure_max, (int, float)) or isinstance(
    baseline_failure_max, bool
):
    raise ValueError("auth.max_failures_1h_window must be numeric")
failure_burst_limit = baseline_failure_max * failure_multiplier

evaluation_events = []
with events_path.open("r", encoding="utf-8") as stream:
    for line_number, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid NDJSON on line {line_number}: {error}") from error
        if not isinstance(event, dict):
            raise ValueError(f"line {line_number} is not a JSON object")
        event_time = parse_timestamp(event.get("timestamp"), f"line {line_number}.timestamp")
        if evaluation_start <= event_time < evaluation_end:
            event["_time"] = event_time
            event["_line"] = line_number
            event["_ref"] = event_reference(event, line_number)
            evaluation_events.append(event)

anomalies = []

for event in evaluation_events:
    label = event.get("canonical_label")
    user_value = event.get("user")
    if label not in AUTH_LABELS or user_value in (None, "", "-", "unknown"):
        continue
    user = str(user_value)
    if user not in known_accounts:
        anomalies.append(
            {
                "timestamp": iso_z(event["_time"]),
                "host": normalized_value(event.get("hostname")),
                "user": user,
                "src_ip": normalized_value(event.get("src_ip")),
                "anomaly_type": "unknown_account",
                "baseline_value": "account absent from known_accounts",
                "observed_value": user,
                "severity": "high",
                "event_refs": [event["_ref"]],
            }
        )

for event in evaluation_events:
    if event.get("canonical_label") != "login_success":
        continue
    user = normalized_value(event.get("user"))
    if event["_time"].hour not in range(6, 18) and user in business_only_users:
        anomalies.append(
            {
                "timestamp": iso_z(event["_time"]),
                "host": normalized_value(event.get("hostname")),
                "user": user,
                "src_ip": normalized_value(event.get("src_ip")),
                "anomaly_type": "offhours_login",
                "baseline_value": {
                    "business_hours_success": next(
                        record["business_hours_success"]
                        for record in per_user_raw
                        if str(record["user"]) == user
                    ),
                    "offhours_success": 0,
                },
                "observed_value": event["_time"].hour,
                "severity": "medium",
                "event_refs": [event["_ref"]],
            }
        )

failures_by_ip = collections.defaultdict(list)
for event in evaluation_events:
    if event.get("canonical_label") == "login_failure":
        source_ip = event.get("src_ip")
        if source_ip not in (None, "", "-"):
            failures_by_ip[str(source_ip)].append(event)

for source_ip in sorted(failures_by_ip):
    failures = sorted(failures_by_ip[source_ip], key=lambda event: event["_time"])
    left = 0
    best = []
    for right, event in enumerate(failures):
        while event["_time"] - failures[left]["_time"] >= dt.timedelta(hours=1):
            left += 1
        current = failures[left : right + 1]
        if len(current) > len(best):
            best = current
    if len(best) > failure_burst_limit:
        representative = best[-1]
        anomalies.append(
            {
                "timestamp": iso_z(representative["_time"]),
                "host": normalized_value(representative.get("hostname")),
                "user": normalized_value(representative.get("user")),
                "src_ip": source_ip,
                "anomaly_type": "failure_rate_burst",
                "baseline_value": {
                    "max_failures_1h_window": baseline_failure_max,
                    "failure_rate_multiplier": failure_multiplier,
                    "trigger_above": failure_burst_limit,
                },
                "observed_value": len(best),
                "severity": "high",
                "event_refs": [event["_ref"] for event in best],
            }
        )

privilege_by_host = collections.defaultdict(list)
for event in evaluation_events:
    if event.get("canonical_label") == "privilege_escalation":
        privilege_by_host[normalized_value(event.get("hostname"))].append(event)

for host in sorted(privilege_by_host):
    baseline_host = per_host.get(host, {})
    baseline_count = baseline_host.get("privilege_escalation", 0)
    if not isinstance(baseline_count, int):
        raise ValueError(f"auth.per_host.{host}.privilege_escalation must be an integer")
    events = sorted(privilege_by_host[host], key=lambda event: event["_time"])
    if baseline_count == 0 and len(events) > privilege_surge_limit:
        representative = events[privilege_surge_limit]
        anomalies.append(
            {
                "timestamp": iso_z(representative["_time"]),
                "host": host,
                "user": normalized_value(representative.get("user")),
                "src_ip": normalized_value(representative.get("src_ip")),
                "anomaly_type": "privilege_escalation_surge",
                "baseline_value": {
                    "host_privilege_escalations": 0,
                    "surge_threshold": privilege_surge_limit,
                },
                "observed_value": len(events),
                "severity": "high",
                "event_refs": [event["_ref"] for event in events],
            }
        )

anomalies.sort(
    key=lambda item: (
        item["timestamp"],
        item["anomaly_type"],
        item["host"],
        item["user"],
        item["src_ip"],
    )
)

with output_path.open("w", encoding="utf-8", newline="\n") as output:
    json.dump(anomalies, output, indent=2, sort_keys=False)
    output.write("\n")

counts = collections.Counter(item["anomaly_type"] for item in anomalies)
print(f"evaluation window  : {iso_z(evaluation_start)} -> {iso_z(evaluation_end)}")
print(f"unknown_account           : {counts['unknown_account']}")
print(f"failure_rate_burst        : {counts['failure_rate_burst']}")
print(f"offhours_login            : {counts['offhours_login']}")
print(f"privilege_escalation_surge: {counts['privilege_escalation_surge']}")
print(f"total anomalies           : {len(anomalies)}")
PY

mv -f -- "$output_tmp" "$OUTPUT_FILE"
chmod 0644 "$OUTPUT_FILE"
printf 'anomalies_auth.json written\n'


