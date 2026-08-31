#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_ROOT="${1:-${EVIDENCE_ROOT:-$HOME/evidence_pack_primary}}"
WORK_DIR="${2:-${WORK_DIR:-$SCRIPT_DIR}}"
NETWORK_DIR="$EVIDENCE_ROOT/network"
SCHEMA_FILE="${SCHEMA_FILE:-$WORK_DIR/event_schema.json}"
NORMALIZED_FILE="${NORMALIZED_FILE:-$WORK_DIR/normalized_events.json}"
NETWORK_OUTPUT="${NETWORK_OUTPUT:-$WORK_DIR/network_events.json}"

FIREWALL_FILE="$NETWORK_DIR/firewall.csv"
SURICATA_FILE="$NETWORK_DIR/suricata_eve.json"
PCAP_FILE="$NETWORK_DIR/pcap_summary.json"

for input_file in \
    "$SCHEMA_FILE" \
    "$NORMALIZED_FILE" \
    "$FIREWALL_FILE" \
    "$SURICATA_FILE" \
    "$PCAP_FILE"; do
    if [[ ! -f "$input_file" ]]; then
        printf 'ERROR: required file not found: %s\n' \
            "$input_file" >&2
        exit 1
    fi

    if [[ ! -r "$input_file" ]]; then
        printf 'ERROR: file is not readable: %s\n' \
            "$input_file" >&2
        exit 1
    fi
done

mkdir -p -- "$(dirname -- "$NORMALIZED_FILE")"
mkdir -p -- "$(dirname -- "$NETWORK_OUTPUT")"

python3 -W error - \
    "$SCHEMA_FILE" \
    "$NORMALIZED_FILE" \
    "$NETWORK_OUTPUT" \
    "$FIREWALL_FILE" \
    "$SURICATA_FILE" \
    "$PCAP_FILE" <<'PYTHON'
import csv
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


schema_file = Path(sys.argv[1])
normalized_file = Path(sys.argv[2]).resolve()
network_output = Path(sys.argv[3]).resolve()
firewall_file = Path(sys.argv[4])
suricata_file = Path(sys.argv[5])
pcap_file = Path(sys.argv[6])

NETWORK_SOURCE_TYPES = {"firewall", "suricata", "pcap"}
ALLOWED_TYPES = {
    "string",
    "integer",
    "float",
    "boolean",
    "timestamp",
    "object",
    "array",
}


def load_schema(path):
    with path.open("r", encoding="utf-8") as stream:
        schema = json.load(stream)

    definitions = {}

    if not isinstance(schema.get("version"), str):
        raise ValueError("schema version must be a string")

    if not isinstance(schema.get("fields"), list):
        raise ValueError("schema fields must be an array")

    for definition in schema["fields"]:
        name = definition.get("name")
        field_type = definition.get("type")

        if not isinstance(name, str) or not name:
            raise ValueError("every schema field requires a name")

        if name in definitions:
            raise ValueError(f"duplicate schema field: {name}")

        if field_type not in ALLOWED_TYPES:
            raise ValueError(
                f"unsupported type for {name}: {field_type}"
            )

        if not isinstance(definition.get("required"), bool):
            raise ValueError(
                f"required must be boolean for field: {name}"
            )

        definitions[name] = definition

    for required_network_field in ("action", "signature"):
        if required_network_field not in definitions:
            raise ValueError(
                "schema must define network field: "
                + required_network_field
            )

    return schema, definitions


schema, field_definitions = load_schema(schema_file)
schema_fields = list(field_definitions)
schema_field_set = set(schema_fields)
required_fields = [
    name
    for name, definition in field_definitions.items()
    if definition["required"]
]


def empty_record():
    return {name: None for name in schema_fields}


def parse_integer(value):
    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    if isinstance(value, float) and value.is_integer():
        return int(value)

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return None

        try:
            return int(value, 0)
        except ValueError:
            try:
                numeric = float(value)
            except ValueError:
                return None

            if numeric.is_integer():
                return int(numeric)

    return None


def parse_float(value):
    if value is None or isinstance(value, bool):
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def format_timestamp(value):
    value = value.astimezone(timezone.utc)

    if value.microsecond:
        rendered = value.isoformat(timespec="microseconds")
    else:
        rendered = value.isoformat(timespec="seconds")

    return rendered.replace("+00:00", "Z")


def parse_epoch(value):
    numeric = parse_float(value)

    if numeric is None:
        return None

    try:
        return format_timestamp(
            datetime.fromtimestamp(numeric, tz=timezone.utc)
        )
    except (ValueError, OverflowError):
        return None


def parse_iso8601(value):
    if not isinstance(value, str) or not value.strip():
        return None

    text = value.strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    if re.search(r"[+-]\d{4}$", text):
        text = text[:-5] + text[-5:-2] + ":" + text[-2:]

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return format_timestamp(parsed.astimezone(timezone.utc))


def parse_pcap_time(value):
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.strptime(
            value,
            "%m/%d/%Y %I:%M:%S %p",
        )
    except ValueError:
        return None

    return format_timestamp(
        parsed.replace(tzinfo=timezone.utc)
    )


def write_ndjson(stream, record):
    stream.write(
        json.dumps(
            record,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    stream.write("\n")


def value_matches_type(value, field_type):
    if value is None:
        return True

    if field_type in {"string", "timestamp"}:
        return isinstance(value, str)

    if field_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)

    if field_type == "float":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
        )

    if field_type == "boolean":
        return isinstance(value, bool)

    if field_type == "object":
        return isinstance(value, dict)

    if field_type == "array":
        return isinstance(value, list)

    return False


def validate_record(record, source_name, record_number):
    if set(record) != schema_field_set:
        missing = sorted(schema_field_set - set(record))
        extra = sorted(set(record) - schema_field_set)
        raise ValueError(
            f"{source_name} record {record_number} does not "
            f"match schema; missing={missing}, extra={extra}"
        )

    for name in required_fields:
        value = record.get(name)

        if value is None or value == "":
            raise ValueError(
                f"{source_name} record {record_number} "
                f"missing required field: {name}"
            )

    for name, definition in field_definitions.items():
        if not value_matches_type(
            record[name],
            definition["type"],
        ):
            raise ValueError(
                f"{source_name} record {record_number} has "
                f"invalid type for {name}; expected "
                f"{definition['type']}"
            )


def firewall_severity(action):
    if str(action).upper() in {"BLOCK", "DENY", "DROP"}:
        return "low"

    return "informational"


def normalize_firewall(row, record_number):
    timestamp = parse_epoch(row.get("timestamp"))

    if timestamp is None:
        raise ValueError(
            f"firewall.csv record {record_number} has "
            "an unparseable timestamp"
        )

    action = str(row.get("action") or "").upper()
    record = empty_record()
    record.update(
        {
            "timestamp": timestamp,
            "hostname": None,
            "source_type": "firewall",
            "source_origin": "evidence_pack",
            "event_category": "network",
            "severity": firewall_severity(action),
            "event_id": None,
            "event_action": action.lower() if action else None,
            "action": action or None,
            "outcome": (
                "allowed"
                if action == "ALLOW"
                else "blocked"
                if action in {"BLOCK", "DENY", "DROP"}
                else None
            ),
            "src_ip": row.get("src_ip") or None,
            "src_port": parse_integer(row.get("src_port")),
            "dst_ip": row.get("dst_ip") or None,
            "dst_port": parse_integer(row.get("dst_port")),
            "network_protocol": row.get("protocol") or None,
            "bytes_in": parse_integer(row.get("bytes_in")),
            "bytes_out": parse_integer(row.get("bytes_out")),
            "rule_id": row.get("rule_id") or None,
            "rule_name": None,
            "signature": None,
            "channel": row.get("interface") or "firewall",
            "provider": "firewall",
            "tags": [
                "network",
                action.lower() if action else "unknown_action",
            ],
            "raw_message": json.dumps(
                row,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            "details": dict(row),
        }
    )
    validate_record(record, "firewall.csv", record_number)
    return record


def suricata_severity(value):
    numeric = parse_integer(value)

    if numeric == 1:
        return "high"

    if numeric == 2:
        return "medium"

    if numeric == 3:
        return "low"

    return "informational"


def normalize_suricata(source, record_number):
    timestamp = parse_iso8601(source.get("timestamp"))

    if timestamp is None:
        raise ValueError(
            f"suricata_eve.json record {record_number} has "
            "an unparseable timestamp"
        )

    alert = source.get("alert")
    flow = source.get("flow")

    if not isinstance(alert, dict):
        alert = {}

    if not isinstance(flow, dict):
        flow = {}

    signature = alert.get("signature")
    action = alert.get("action")
    signature_id = parse_integer(alert.get("signature_id"))
    record = empty_record()
    record.update(
        {
            "timestamp": timestamp,
            "hostname": source.get("host"),
            "source_type": "suricata",
            "source_origin": source.get(
                "source_origin",
                "evidence_pack",
            ),
            "event_category": "network_alert",
            "severity": suricata_severity(
                alert.get("severity")
            ),
            "event_id": signature_id,
            "event_action": (
                str(action).lower()
                if action is not None
                else "alert"
            ),
            "action": str(action) if action is not None else None,
            "outcome": str(action) if action is not None else None,
            "src_ip": source.get("src_ip"),
            "src_port": parse_integer(source.get("src_port")),
            "dst_ip": source.get("dest_ip") or source.get("dst_ip"),
            "dst_port": parse_integer(
                source.get("dest_port") or source.get("dst_port")
            ),
            "network_protocol": (
                source.get("proto") or source.get("app_proto")
            ),
            "bytes_in": parse_integer(
                flow.get("bytes_toclient")
            ),
            "bytes_out": parse_integer(
                flow.get("bytes_toserver")
            ),
            "rule_id": (
                str(signature_id)
                if signature_id is not None
                else None
            ),
            "rule_name": signature,
            "signature": signature,
            "channel": source.get("event_type") or "alert",
            "provider": "suricata",
            "tags": [
                "network_alert",
                str(alert.get("category") or "uncategorized"),
            ],
            "raw_message": (
                str(signature)
                if signature is not None
                else json.dumps(
                    source,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            ),
            "details": dict(source),
        }
    )
    validate_record(
        record,
        "suricata_eve.json",
        record_number,
    )
    return record


def normalize_pcap(source, record_number):
    timestamp = parse_pcap_time(source.get("start_time"))

    if timestamp is None:
        raise ValueError(
            f"pcap_summary.json record {record_number} has "
            "an unparseable start_time"
        )

    session_id = parse_integer(source.get("session_id"))
    record = empty_record()
    record.update(
        {
            "timestamp": timestamp,
            "hostname": None,
            "source_type": "pcap",
            "source_origin": source.get(
                "source_origin",
                "evidence_pack",
            ),
            "event_category": "network_flow",
            "severity": "informational",
            "event_id": session_id,
            "event_action": "flow_observed",
            "action": None,
            "outcome": None,
            "src_ip": source.get("src_ip"),
            "src_port": parse_integer(source.get("src_port")),
            "dst_ip": source.get("dst_ip") or source.get("dest_ip"),
            "dst_port": parse_integer(
                source.get("dst_port") or source.get("dest_port")
            ),
            "network_protocol": source.get("protocol"),
            "rule_id": None,
            "rule_name": None,
            "signature": None,
            "channel": "pcap_summary",
            "provider": "pcap_summary",
            "tags": ["network_flow"],
            "raw_message": json.dumps(
                source,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            "details": dict(source),
        }
    )
    validate_record(record, "pcap_summary.json", record_number)
    return record


def iter_ndjson(path, source_name):
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"invalid JSON in {source_name} at line "
                    f"{line_number}: {error}"
                ) from error

            if not isinstance(record, dict):
                raise ValueError(
                    f"{source_name} line {line_number} is not "
                    "a JSON object"
                )

            yield line_number, record


def copy_endpoint_records(input_path, output_stream):
    retained_count = 0

    for line_number, record in iter_ndjson(
        input_path,
        "normalized_events.json",
    ):
        if record.get("source_type") in NETWORK_SOURCE_TYPES:
            continue

        if set(record) != schema_field_set:
            raise ValueError(
                "normalized_events.json does not conform to "
                f"schema {schema['version']} at line {line_number}; "
                "rerun 5-normalize.sh with the current schema"
            )

        validate_record(
            record,
            "normalized_events.json",
            line_number,
        )
        write_ndjson(output_stream, record)
        retained_count += 1

    return retained_count


normalized_file.parent.mkdir(parents=True, exist_ok=True)
network_output.parent.mkdir(parents=True, exist_ok=True)

combined_temp = None
network_temp = None

try:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=normalized_file.parent,
        prefix=".combined_normalized.",
        suffix=".tmp",
        delete=False,
    ) as combined_stream, tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=network_output.parent,
        prefix=".network_events.",
        suffix=".tmp",
        delete=False,
    ) as network_stream:
        combined_temp = Path(combined_stream.name)
        network_temp = Path(network_stream.name)

        endpoint_count = copy_endpoint_records(
            normalized_file,
            combined_stream,
        )

        firewall_count = 0

        with firewall_file.open(
            "r",
            encoding="utf-8",
            newline="",
        ) as stream:
            reader = csv.DictReader(stream)

            for record_number, row in enumerate(reader, start=1):
                record = normalize_firewall(row, record_number)
                write_ndjson(network_stream, record)
                write_ndjson(combined_stream, record)
                firewall_count += 1

        suricata_count = 0

        for record_number, source in iter_ndjson(
            suricata_file,
            "suricata_eve.json",
        ):
            record = normalize_suricata(source, record_number)
            write_ndjson(network_stream, record)
            write_ndjson(combined_stream, record)
            suricata_count += 1

        pcap_count = 0

        for record_number, source in iter_ndjson(
            pcap_file,
            "pcap_summary.json",
        ):
            record = normalize_pcap(source, record_number)
            write_ndjson(network_stream, record)
            write_ndjson(combined_stream, record)
            pcap_count += 1

    os.replace(network_temp, network_output)
    os.replace(combined_temp, normalized_file)

except Exception:
    for temporary_path in (combined_temp, network_temp):
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    raise

print(
    f"firewall.csv        : {firewall_count:7d} records normalized"
)
print(
    "suricata_eve.json  : "
    f"{suricata_count:7d} records normalized"
)
print(
    f"pcap_summary.json   : {pcap_count:7d} records normalized"
)
print(
    "appended to normalized_events.json "
    f"after {endpoint_count} endpoint records"
)
print("network_events.json written")
PYTHON