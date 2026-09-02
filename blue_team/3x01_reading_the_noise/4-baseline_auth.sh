#!/bin/bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"
readonly LABELED_EVENTS="${LABELED_EVENTS:-${SCRIPT_DIR}/labeled_events.json}"
readonly OUTPUT_FILE="${SCRIPT_DIR}/baseline_auth.json"
readonly BASELINE_DAYS="${BASELINE_DAYS:-7}"

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || die "python3 is required"
[[ -d "$HANDOFF_DIR" ]] || die "handoff directory is not accessible: $HANDOFF_DIR"
[[ -r "$LABELED_EVENTS" ]] || die "labeled dataset is not readable: $LABELED_EVENTS"
[[ "$BASELINE_DAYS" =~ ^[1-9][0-9]*$ ]] || die "BASELINE_DAYS must be a positive integer"

output_tmp=$(mktemp "${SCRIPT_DIR}/.baseline_auth.XXXXXX")
cleanup() {
    rm -f -- "$output_tmp"
}
trap cleanup EXIT

python3 -W error - "$LABELED_EVENTS" "$output_tmp" "$BASELINE_DAYS" <<'PY'
import collections
import datetime as dt
import json
import pathlib
import sys


AUTH_LABELS = (
    "login_success",
    "login_failure",
    "logout",
    "account_lockout",
    "privilege_escalation",
)


def concise_error(error_type, error, traceback):
    del error_type, traceback
    print(f"Error: {error}", file=sys.stderr)


sys.excepthook = concise_error


def parse_timestamp(value: object) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("missing or non-string timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def iso_z(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def iter_events(path: pathlib.Path):
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid NDJSON on line {line_number}: {error}") from error
            if not isinstance(event, dict):
                raise ValueError(f"line {line_number} is not a JSON object")
            yield line_number, event


input_path = pathlib.Path(sys.argv[1])
output_path = pathlib.Path(sys.argv[2])
baseline_days = int(sys.argv[3])

minimum_time = None
maximum_time = None
for line_number, event in iter_events(input_path):
    try:
        event_time = parse_timestamp(event.get("timestamp"))
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid timestamp on line {line_number}: {error}") from error
    minimum_time = event_time if minimum_time is None else min(minimum_time, event_time)
    maximum_time = event_time if maximum_time is None else max(maximum_time, event_time)

if minimum_time is None or maximum_time is None:
    raise ValueError("labeled dataset contains no events")

window_start = minimum_time
window_end = window_start + dt.timedelta(days=baseline_days)
if window_end > maximum_time:
    raise ValueError(
        "BASELINE_DAYS exceeds the available dataset span: "
        f"requested end {iso_z(window_end)}, dataset maximum {iso_z(maximum_time)}"
    )

empty_counts = {label: 0 for label in AUTH_LABELS}
per_host = collections.defaultdict(lambda: dict(empty_counts))
per_user = collections.defaultdict(
    lambda: {"login_success": 0, "login_failure": 0}
)
known_accounts = set()
business_counts = {"login_success": 0, "login_failure": 0}
offhours_counts = {"login_success": 0, "login_failure": 0}
failure_times_by_ip = collections.defaultdict(list)

for line_number, event in iter_events(input_path):
    try:
        event_time = parse_timestamp(event.get("timestamp"))
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid timestamp on line {line_number}: {error}") from error
    if not (window_start <= event_time < window_end):
        continue

    label = event.get("canonical_label")
    if label not in AUTH_LABELS:
        continue

    hostname = event.get("hostname")
    host_key = str(hostname) if hostname not in (None, "") else "unknown"
    per_host[host_key][label] += 1

    username = event.get("user")
    if username not in (None, "", "-", "unknown"):
        user_key = str(username)
        known_accounts.add(user_key)
        if label in ("login_success", "login_failure"):
            per_user[user_key][label] += 1

    if label in ("login_success", "login_failure"):
        period = business_counts if 6 <= event_time.hour <= 17 else offhours_counts
        period[label] += 1

    if label == "login_failure":
        source_ip = event.get("src_ip")
        if source_ip not in (None, "", "-"):
            failure_times_by_ip[str(source_ip)].append(event_time)

max_failures_1h = 0
for timestamps in failure_times_by_ip.values():
    timestamps.sort()
    left = 0
    for right, current in enumerate(timestamps):
        while current - timestamps[left] >= dt.timedelta(hours=1):
            left += 1
        max_failures_1h = max(max_failures_1h, right - left + 1)

hours_per_period = baseline_days * 12
business_average = {
    "login_success": round(business_counts["login_success"] / hours_per_period, 6),
    "login_failure": round(business_counts["login_failure"] / hours_per_period, 6),
}
offhours_average = {
    "login_success": round(offhours_counts["login_success"] / hours_per_period, 6),
    "login_failure": round(offhours_counts["login_failure"] / hours_per_period, 6),
}

result = {
    "window": {
        "start": iso_z(window_start),
        "end": iso_z(window_end),
        "end_exclusive": True,
        "baseline_days": baseline_days,
    },
    "per_host": {host: per_host[host] for host in sorted(per_host)},
    "per_user": [
        {
            "user": username,
            "login_success": per_user[username]["login_success"],
            "login_failure": per_user[username]["login_failure"],
        }
        for username in sorted(known_accounts)
    ],
    "known_accounts": sorted(known_accounts),
    "business_hours_avg": business_average,
    "offhours_avg": offhours_average,
    "max_failures_1h_window": max_failures_1h,
}

with output_path.open("w", encoding="utf-8", newline="\n") as output:
    json.dump(result, output, indent=2, sort_keys=False)
    output.write("\n")

print(f"baseline window : {iso_z(window_start)} -> {iso_z(window_end)}")
print(f"hosts           : {len(per_host)}")
print(f"known accounts  : {len(known_accounts)}")
print(
    "business hours  : "
    f"{business_average['login_success']:.2f} success/h  |  "
    f"{business_average['login_failure']:.2f} failure/h"
)
print(
    "off hours       : "
    f"{offhours_average['login_success']:.2f} success/h  |  "
    f"{offhours_average['login_failure']:.2f} failure/h"
)
print(f"max 1h src_ip failures : {max_failures_1h}")
PY

mv -f -- "$output_tmp" "$OUTPUT_FILE"
chmod 0644 "$OUTPUT_FILE"
printf 'baseline_auth.json written\n'

