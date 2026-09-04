#!/bin/bash
set -Eeuo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

EVENTS="$HANDOFF_DIR/data/enriched_events.json"
SCHEMA="$HANDOFF_DIR/schema/event_schema.json"
BASELINE="$BASELINE_PKG/baselines/baseline_summary.json"
OUTPUT="${OUTPUT_FILE:-detection_matrix.json}"

for input in "$EVENTS" "$SCHEMA" "$BASELINE"; do
    if [[ ! -r "$input" ]]; then
        printf 'ERROR: required input is not readable: %s\n' "$input" >&2
        exit 1
    fi
done

python3 -W error /dev/fd/3 \
    "$EVENTS" "$SCHEMA" "$BASELINE" "$OUTPUT" 3<<'PY'
import collections
import json
import sys


def iter_events(path):
    """NDJSON input supported: read one JSON event per line."""
    with open(path, "r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            text = line.strip()

            if not text:
                continue

            try:
                event = json.loads(text)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"invalid NDJSON at line {line_number}: {error}"
                ) from error

            if not isinstance(event, dict):
                raise ValueError(
                    f"record at line {line_number} is not a JSON object"
                )

            yield event


def canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def detection_policy(source_type):
    name = source_type.lower()

    if "windows" in name or "linux" in name:
        return (
            ["signature", "anomaly", "behavioral", "correlation"],
            ["TA0002", "TA0003", "TA0004", "TA0005", "TA0006"],
        )

    if "suricata" in name:
        return (
            ["signature", "correlation"],
            ["TA0010", "TA0011"],
        )

    if "firewall" in name:
        return (
            ["anomaly", "correlation"],
            ["TA0008", "TA0010", "TA0011"],
        )

    if "pcap" in name or "flow" in name:
        return (
            ["anomaly", "behavioral"],
            ["TA0043", "TA0008", "TA0010", "TA0011"],
        )

    return (
        ["signature"],
        [],
    )


REASONS = {
    "signature":
        "stable_fields_support_exact_indicator_or_pattern_matching",
    "anomaly":
        "baseline_supports_comparison_with_normal_frequency_or_values",
    "behavioral":
        "event_fields_support_suspicious_activity_pattern_detection",
    "correlation":
        "shared_time_and_entity_fields_support_cross_event_linking",
}

events_path = sys.argv[1]
schema_path = sys.argv[2]
baseline_path = sys.argv[3]
output_path = sys.argv[4]

# Read and validate the two mandatory dependency files.
with open(schema_path, "r", encoding="utf-8") as stream:
    schema = json.load(stream)

with open(baseline_path, "r", encoding="utf-8") as stream:
    baseline = json.load(stream)

if not isinstance(schema, (dict, list)):
    raise ValueError("event_schema.json must contain an object or array")

if not isinstance(baseline, (dict, list)):
    raise ValueError("baseline_summary.json must contain an object or array")

record_counts = collections.Counter()
field_presence = collections.defaultdict(collections.Counter)
distinct_values = collections.defaultdict(
    lambda: collections.defaultdict(set)
)

for event in iter_events(events_path):
    source_type = event.get("source_type")

    if not isinstance(source_type, str) or not source_type:
        continue

    record_counts[source_type] += 1

    for field, value in event.items():
        if value is None:
            continue

        field_presence[source_type][field] += 1
        distinct_values[source_type][field].add(canonical(value))

matrix = []

for source_type in sorted(record_counts):
    record_count = record_counts[source_type]

    stable_fields = sorted(
        field
        for field, count in field_presence[source_type].items()
        if count / record_count >= 0.95
    )

    high_cardinality_fields = sorted(
        field
        for field, values in distinct_values[source_type].items()
        if len(values) > 0.5 * record_count
    )

    supported_types, tactics = detection_policy(source_type)

    matrix.append({
        "source_type": source_type,
        "record_count": record_count,
        "stable_fields": stable_fields,
        "high_cardinality_fields": high_cardinality_fields,
        "supported_detection_types": supported_types,
        "rationale": {
            detection_type: REASONS[detection_type]
            for detection_type in supported_types
        },
        "recommended_attack_tactics": tactics,
    })

with open(output_path, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(matrix, stream, indent=2, ensure_ascii=False)
    stream.write("\n")

for entry in matrix:
    supported = entry["supported_detection_types"]
    types_text = " ".join(supported)

    print(
        f'{entry["source_type"]}\t'
        f'{len(supported)} types\t'
        f'[{types_text}]'
    )

print(f"{len(matrix)} source types analyzed")
PY

printf '%s written\n' "$OUTPUT"
