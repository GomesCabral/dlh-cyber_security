#!/bin/bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"
readonly AUTH_ANOMALIES="${AUTH_ANOMALIES:-${SCRIPT_DIR}/anomalies_auth.json}"
readonly PROCESS_ANOMALIES="${PROCESS_ANOMALIES:-${SCRIPT_DIR}/anomalies_process.json}"
readonly NETWORK_ANOMALIES="${NETWORK_ANOMALIES:-${SCRIPT_DIR}/anomalies_network.json}"
readonly OUTPUT_FILE="${SCRIPT_DIR}/correlated_anomalies.json"
readonly CORRELATION_WINDOW_SECONDS="${CORRELATION_WINDOW_SECONDS:-300}"

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || die "python3 is required"
[[ -d "$HANDOFF_DIR" ]] || die "handoff directory is not accessible: $HANDOFF_DIR"
[[ "$CORRELATION_WINDOW_SECONDS" =~ ^[1-9][0-9]*$ ]] ||
    die "CORRELATION_WINDOW_SECONDS must be a positive integer"

for input_file in "$AUTH_ANOMALIES" "$PROCESS_ANOMALIES" "$NETWORK_ANOMALIES"; do
    [[ -r "$input_file" ]] || die "required anomaly file is not readable: $input_file"
done

output_tmp=$(mktemp "${SCRIPT_DIR}/.correlated_anomalies.XXXXXX")
cleanup() {
    rm -f -- "$output_tmp"
}
trap cleanup EXIT

python3 -W error - \
    "$AUTH_ANOMALIES" "$PROCESS_ANOMALIES" "$NETWORK_ANOMALIES" \
    "$output_tmp" "$CORRELATION_WINDOW_SECONDS" <<'PY'
import collections
import datetime as dt
import hashlib
import json
import pathlib
import sys


SOURCE_ORDER = {"auth": 0, "process": 1, "network": 2}
CRITICALITY_MULTIPLIER = {
    "UNKNOWN": 1,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
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
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def load_anomalies(path: pathlib.Path, source: str) -> list[dict]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            items = json.load(stream)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(items, list):
        raise ValueError(f"{path} must contain a JSON array")
    normalized = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"{path} entry {index} is not an object")
        host = item.get("host")
        anomaly_type = item.get("anomaly_type")
        if host in (None, "") or anomaly_type in (None, ""):
            raise ValueError(f"{path} entry {index} requires host and anomaly_type")
        timestamp = parse_timestamp(item.get("timestamp"), f"{path} entry {index}.timestamp")
        criticality = str(item.get("asset_criticality", "UNKNOWN")).upper()
        if criticality not in CRITICALITY_MULTIPLIER:
            criticality = "UNKNOWN"
        normalized.append({
            "source": source,
            "member_ref": f"{source}:{index:06d}",
            "host": str(host),
            "timestamp": timestamp,
            "anomaly_type": str(anomaly_type),
            "asset_criticality": criticality,
        })
    return normalized


auth_path = pathlib.Path(sys.argv[1])
process_path = pathlib.Path(sys.argv[2])
network_path = pathlib.Path(sys.argv[3])
output_path = pathlib.Path(sys.argv[4])
window_seconds = int(sys.argv[5])
window_delta = dt.timedelta(seconds=window_seconds)

all_anomalies = []
all_anomalies.extend(load_anomalies(auth_path, "auth"))
all_anomalies.extend(load_anomalies(process_path, "process"))
all_anomalies.extend(load_anomalies(network_path, "network"))

by_host = collections.defaultdict(list)
for anomaly in all_anomalies:
    by_host[anomaly["host"]].append(anomaly)

findings = []
for host in sorted(by_host):
    items = sorted(by_host[host], key=lambda item: (
        item["timestamp"], SOURCE_ORDER[item["source"]], item["member_ref"]
    ))
    index = 0
    while index < len(items):
        anchor = items[index]["timestamp"]
        end_index = index
        while (
            end_index + 1 < len(items)
            and items[end_index + 1]["timestamp"] - anchor <= window_delta
        ):
            end_index += 1
        members = items[index : end_index + 1]
        sources = sorted({item["source"] for item in members}, key=SOURCE_ORDER.get)
        if len(sources) < 2:
            index += 1
            continue

        anomaly_types = sorted({item["anomaly_type"] for item in members})
        member_refs = [item["member_ref"] for item in members]
        highest_criticality = max(
            (item["asset_criticality"] for item in members),
            key=lambda value: CRITICALITY_MULTIPLIER[value],
        )
        multiplier = CRITICALITY_MULTIPLIER[highest_criticality]
        score = len(sources) + len(anomaly_types) + multiplier
        window_start = members[0]["timestamp"]
        window_end = members[-1]["timestamp"]
        identity = "|".join(
            [host, iso_z(window_start), iso_z(window_end), *member_refs]
        )
        correlation_id = "corr-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
        findings.append({
            "correlation_id": correlation_id,
            "host": host,
            "window_start": iso_z(window_start),
            "window_end": iso_z(window_end),
            "sources_involved": sources,
            "anomaly_types": anomaly_types,
            "member_refs": member_refs,
            "asset_criticality": highest_criticality,
            "asset_criticality_multiplier": multiplier,
            "score": score,
        })
        index = end_index + 1

findings.sort(key=lambda item: (-item["score"], item["window_start"], item["host"], item["correlation_id"]))
with output_path.open("w", encoding="utf-8", newline="\n") as output:
    json.dump(findings, output, indent=2)
    output.write("\n")

multi_host = sum(1 for item in findings if isinstance(item["host"], list) and len(item["host"]) > 1)
max_score = max((item["score"] for item in findings), default=0)
print(f"single-source anomalies  : {len(all_anomalies)}")
print(f"correlated findings      : {len(findings)}")
print(f"multi-host findings      : {multi_host}")
print(f"max score                : {max_score}")
PY

mv -f -- "$output_tmp" "$OUTPUT_FILE"
chmod 0644 "$OUTPUT_FILE"
printf 'correlated_anomalies.json written\n'


