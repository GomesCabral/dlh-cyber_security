#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_ROOT="${1:-${EVIDENCE_ROOT:-$HOME/evidence_pack_primary}}"
OUTPUT_FILE="${2:-${OUTPUT_FILE:-$SCRIPT_DIR/source_inventory.json}}"

if [[ ! -d "$EVIDENCE_ROOT" ]]; then
    echo "ERROR: evidence pack not found: $EVIDENCE_ROOT" >&2
    exit 1
fi

for required_dir in windows linux network; do
    if [[ ! -d "$EVIDENCE_ROOT/$required_dir" ]]; then
        echo "ERROR: required directory missing: $required_dir" >&2
        exit 1
    fi
done

python3 - "$EVIDENCE_ROOT" "$OUTPUT_FILE" <<'PYTHON'
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


evidence_root = Path(sys.argv[1]).resolve()
output_file = Path(sys.argv[2]).resolve()

categories = ("windows", "linux", "network")
file_counts = {category: 0 for category in categories}
byte_counts = {category: 0 for category in categories}
manifest_files = []


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def parse_iso8601(value):
    if not isinstance(value, str) or not value.strip():
        return None

    value = value.strip()

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    if re.search(r"[+-]\d{4}$", value):
        value = value[:-5] + value[-5:-2] + ":" + value[-2:]

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def parse_epoch(value):
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def parse_pcap_time(value):
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.strptime(value, "%m/%d/%Y %I:%M:%S %p")
    except ValueError:
        return None

    return parsed.replace(tzinfo=timezone.utc)


def format_timestamp(value):
    if value is None:
        return None

    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def update_bounds(first_time, last_time, candidate):
    if candidate is None:
        return first_time, last_time

    if first_time is None or candidate < first_time:
        first_time = candidate

    if last_time is None or candidate > last_time:
        last_time = candidate

    return first_time, last_time


def iter_ndjson(path):
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue

            try:
                yield json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    f"invalid JSON in {path} at line {line_number}: {error}"
                ) from error


def infer_pack_year():
    for path in sorted((evidence_root / "windows").glob("*.json")):
        for record in iter_ndjson(path):
            timestamp = parse_iso8601(record.get("timestamp_raw"))

            if timestamp is not None:
                return timestamp.year

    return datetime.now(timezone.utc).year


pack_year = infer_pack_year()


def inspect_windows_json(path):
    count = 0
    first_time = None
    last_time = None

    for record in iter_ndjson(path):
        count += 1
        timestamp = parse_iso8601(record.get("timestamp_raw"))
        first_time, last_time = update_bounds(
            first_time, last_time, timestamp
        )

    return "record_count", count, first_time, last_time


def inspect_linux_text(path):
    count = 0
    first_time = None
    last_time = None
    audit_pattern = re.compile(r"audit\((\d+(?:\.\d+)?):\d+\)")

    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            count += 1
            timestamp = None

            if path.name == "audit.log":
                match = audit_pattern.search(line)

                if match:
                    timestamp = parse_epoch(match.group(1))
            else:
                try:
                    timestamp = datetime.strptime(
                        f"{pack_year} {line[:15]}",
                        "%Y %b %d %H:%M:%S",
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    timestamp = None

            first_time, last_time = update_bounds(
                first_time, last_time, timestamp
            )

    return "line_count", count, first_time, last_time


def inspect_network_csv(path):
    count = 0
    first_time = None
    last_time = None

    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)

        for record in reader:
            count += 1
            timestamp = parse_epoch(record.get("timestamp"))
            first_time, last_time = update_bounds(
                first_time, last_time, timestamp
            )

    return "record_count", count, first_time, last_time


def inspect_network_json(path):
    count = 0
    first_time = None
    last_time = None

    for record in iter_ndjson(path):
        count += 1
        timestamps = []

        if path.name == "suricata_eve.json":
            timestamps.append(parse_iso8601(record.get("timestamp")))
        elif path.name == "pcap_summary.json":
            timestamps.append(parse_pcap_time(record.get("start_time")))
            timestamps.append(parse_pcap_time(record.get("end_time")))
        else:
            timestamps.append(
                parse_iso8601(
                    record.get("timestamp")
                    or record.get("timestamp_raw")
                    or record.get("start_time")
                )
            )

        for timestamp in timestamps:
            first_time, last_time = update_bounds(
                first_time, last_time, timestamp
            )

    return "record_count", count, first_time, last_time


for category in categories:
    category_root = evidence_root / category

    for path in sorted(item for item in category_root.rglob("*") if item.is_file()):
        relative_path = path.relative_to(evidence_root).as_posix()
        size_bytes = path.stat().st_size

        if category == "windows" and path.suffix == ".json":
            source_type = "windows_json"
            inspection = inspect_windows_json(path)
        elif category == "linux":
            source_type = "linux_text"
            inspection = inspect_linux_text(path)
        elif category == "network" and path.suffix == ".csv":
            source_type = "network_csv"
            inspection = inspect_network_csv(path)
        elif category == "network" and path.suffix == ".json":
            source_type = "network_json"
            inspection = inspect_network_json(path)
        else:
            print(
                f"WARNING: unsupported file skipped: {relative_path}",
                file=sys.stderr,
            )
            continue

        count_field, count, first_time, last_time = inspection

        entry = {
            "path": relative_path,
            "source_type": source_type,
            "size_bytes": size_bytes,
            "sha256": sha256_file(path),
            count_field: count,
            "first_event_time": format_timestamp(first_time),
            "last_event_time": format_timestamp(last_time),
        }

        manifest_files.append(entry)
        file_counts[category] += 1
        byte_counts[category] += size_bytes


output_file.parent.mkdir(parents=True, exist_ok=True)

with output_file.open("w", encoding="utf-8") as stream:
    json.dump(
        {"files": manifest_files},
        stream,
        indent=2,
        ensure_ascii=False,
    )
    stream.write("\n")


def format_bytes(value):
    return f"{value / 1_000_000:.1f} MB"


total_files = sum(file_counts.values())
total_bytes = sum(byte_counts.values())

for category in categories:
    print(
        f"{category:<7} : {file_counts[category]} files"
        f" | {format_bytes(byte_counts[category]):>9}"
    )

print(
    f"{'total':<7} : {total_files} files"
    f" | {format_bytes(total_bytes):>9}"
)
print(f"manifest written to {output_file}")
PYTHON
