#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${1:-${WORK_DIR:-$SCRIPT_DIR}}"
SCHEMA_FILE="${SCHEMA_FILE:-$WORK_DIR/event_schema.json}"
WINDOWS_FILE="${WINDOWS_FILE:-$WORK_DIR/windows_events.json}"
LINUX_FILE="${LINUX_FILE:-$WORK_DIR/linux_events.json}"
NORMALIZED_FILE="${NORMALIZED_FILE:-$WORK_DIR/normalized_events.json}"
QUARANTINE_FILE="${QUARANTINE_FILE:-$WORK_DIR/quarantine.json}"

for input_file in \
    "$SCHEMA_FILE" \
    "$WINDOWS_FILE" \
    "$LINUX_FILE"; do
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
mkdir -p -- "$(dirname -- "$QUARANTINE_FILE")"

python3 -W error - \
    "$SCHEMA_FILE" \
    "$WINDOWS_FILE" \
    "$LINUX_FILE" \
    "$NORMALIZED_FILE" \
    "$QUARANTINE_FILE" <<'PYTHON'
import copy
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


schema_file = Path(sys.argv[1])
windows_file = Path(sys.argv[2])
linux_file = Path(sys.argv[3])
normalized_file = Path(sys.argv[4]).resolve()
quarantine_file = Path(sys.argv[5]).resolve()

ALLOWED_TYPES = {
    "string",
    "integer",
    "float",
    "boolean",
    "timestamp",
    "object",
    "array",
}

WINDOWS_CATEGORIES = {
    1: "process",
    3: "network",
    11: "file",
    12: "registry",
    13: "registry",
    14: "registry",
    4624: "authentication",
    4625: "authentication",
    4634: "authentication",
    4648: "authentication",
    4672: "privilege",
    4688: "process",
    4720: "account_management",
    4722: "account_management",
    4725: "account_management",
    4726: "account_management",
    4732: "group_management",
    4104: "powershell",
}

WINDOWS_ACTIONS = {
    1: "process_start",
    3: "network_connect",
    11: "file_create",
    12: "registry_create_delete",
    13: "registry_value_set",
    14: "registry_rename",
    4624: "logon",
    4625: "logon",
    4634: "logoff",
    4648: "explicit_credential_logon",
    4672: "privileged_logon",
    4688: "process_start",
    4720: "user_create",
    4722: "user_enable",
    4725: "user_disable",
    4726: "user_delete",
    4732: "group_member_add",
    4104: "script_execute",
}

AUDIT_CATEGORIES = {
    "USER_AUTH": "authentication",
    "USER_LOGIN": "authentication",
    "USER_ACCT": "authentication",
    "USER_START": "session",
    "USER_END": "session",
    "CRED_ACQ": "authentication",
    "EXECVE": "process",
    "SYSCALL": "process",
    "PROCTITLE": "process",
    "PATH": "file",
    "AVC": "access_control",
    "SERVICE_START": "service",
    "SERVICE_STOP": "service",
}


def load_schema(path):
    with path.open("r", encoding="utf-8") as stream:
        schema = json.load(stream)

    if not isinstance(schema.get("version"), str):
        raise ValueError("schema version must be a string")

    if not isinstance(schema.get("fields"), list):
        raise ValueError("schema fields must be an array")

    definitions = {}

    for field in schema["fields"]:
        name = field.get("name")
        field_type = field.get("type")

        if not isinstance(name, str) or not name:
            raise ValueError("every schema field requires a name")

        if name in definitions:
            raise ValueError(f"duplicate schema field: {name}")

        if field_type not in ALLOWED_TYPES:
            raise ValueError(
                f"unsupported type for {name}: {field_type}"
            )

        if not isinstance(field.get("required"), bool):
            raise ValueError(
                f"required must be boolean for field: {name}"
            )

        definitions[name] = field

    return schema, definitions


schema, field_definitions = load_schema(schema_file)
schema_fields = list(field_definitions)
required_fields = [
    name
    for name, definition in field_definitions.items()
    if definition["required"]
]


def iter_ndjson(path):
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue

            try:
                yield line_number, json.loads(line)
            except json.JSONDecodeError as error:
                yield line_number, {
                    "_invalid_json": True,
                    "_raw_record": line.rstrip("\r\n"),
                    "_json_error": str(error),
                }


def parse_integer(value):
    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    if isinstance(value, float) and value.is_integer():
        return int(value)

    if isinstance(value, str):
        candidate = value.strip()

        if not candidate or candidate == "-":
            return None

        try:
            return int(candidate, 0)
        except ValueError:
            try:
                numeric = float(candidate)
            except ValueError:
                return None

            if numeric.is_integer():
                return int(numeric)

    return None


def first_value(*values):
    for value in values:
        if value is not None and value != "":
            return value

    return None


def parse_timestamp(value, evidence_year):
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    audit_match = re.fullmatch(
        r"audit\((\d+(?:\.\d+)?):\d+\)",
        text,
    )

    if audit_match:
        try:
            parsed = datetime.fromtimestamp(
                float(audit_match.group(1)),
                tz=timezone.utc,
            )
        except (ValueError, OverflowError):
            return None

        return format_timestamp(parsed)

    iso_text = text

    if iso_text.endswith("Z"):
        iso_text = iso_text[:-1] + "+00:00"

    if re.search(r"[+-]\d{4}$", iso_text):
        iso_text = (
            iso_text[:-5]
            + iso_text[-5:-2]
            + ":"
            + iso_text[-2:]
        )

    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError:
        parsed = None

    if parsed is not None:
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return format_timestamp(
            parsed.astimezone(timezone.utc)
        )

    for pattern in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, pattern)
        except ValueError:
            continue

        parsed = parsed.replace(
            year=evidence_year,
            tzinfo=timezone.utc,
        )
        return format_timestamp(parsed)

    return None


def format_timestamp(value):
    value = value.astimezone(timezone.utc)

    if value.microsecond:
        rendered = value.isoformat(timespec="microseconds")
    else:
        rendered = value.isoformat(timespec="seconds")

    return rendered.replace("+00:00", "Z")


def infer_evidence_year(path):
    for _, record in iter_ndjson(path):
        if not isinstance(record, dict):
            continue

        value = record.get("timestamp_raw")

        if not isinstance(value, str):
            continue

        match = re.match(r"^(\d{4})-", value)

        if match:
            return int(match.group(1))

    return datetime.now(timezone.utc).year


evidence_year = infer_evidence_year(windows_file)


def empty_normalized_record():
    return {name: None for name in schema_fields}


def windows_category(record, event_id):
    existing = record.get("event_category")

    if existing:
        return str(existing)

    if event_id in WINDOWS_CATEGORIES:
        return WINDOWS_CATEGORIES[event_id]

    channel = str(record.get("channel") or "").lower()

    if "powershell" in channel:
        return "powershell"

    if "sysmon" in channel:
        return "endpoint"

    if "security" in channel:
        return "security"

    return "windows_event"


def windows_severity(event_id):
    if event_id in {4720, 4722, 4725, 4726, 4732}:
        return "medium"

    if event_id in {4104, 4672}:
        return "medium"

    if event_id == 4625:
        return "low"

    return "informational"


def windows_outcome(event_id, event_data):
    if event_id == 4624:
        return "success"

    if event_id == 4625:
        return "failure"

    status = first_value(
        event_data.get("Outcome"),
        event_data.get("Status"),
        event_data.get("FailureReason"),
    )

    return str(status) if status is not None else None


def normalize_windows(record):
    normalized = empty_normalized_record()
    event_data = record.get("event_data")

    if not isinstance(event_data, dict):
        event_data = {}

    event_id = parse_integer(record.get("event_id"))
    category = windows_category(record, event_id)

    normalized.update(
        {
            "timestamp": parse_timestamp(
                record.get("timestamp_raw"),
                evidence_year,
            ),
            "hostname": record.get("hostname"),
            "source_type": "windows",
            "source_origin": record.get("source_origin"),
            "event_category": category,
            "severity": windows_severity(event_id),
            "event_id": event_id,
            "event_action": WINDOWS_ACTIONS.get(event_id),
            "outcome": windows_outcome(
                event_id,
                event_data,
            ),
            "user": first_value(
                event_data.get("TargetUserName"),
                event_data.get("SubjectUserName"),
                event_data.get("User"),
                record.get("user"),
            ),
            "process_name": first_value(
                event_data.get("Image"),
                event_data.get("NewProcessName"),
                event_data.get("ProcessName"),
            ),
            "process_id": parse_integer(
                first_value(
                    event_data.get("ProcessId"),
                    event_data.get("NewProcessId"),
                )
            ),
            "parent_process_id": parse_integer(
                event_data.get("ParentProcessId")
            ),
            "command_line": first_value(
                event_data.get("CommandLine"),
                event_data.get("ScriptBlockText"),
                record.get("command_line"),
            ),
            "src_ip": first_value(
                event_data.get("IpAddress"),
                event_data.get("SourceIp"),
                event_data.get("SourceAddress"),
            ),
            "src_port": parse_integer(
                first_value(
                    event_data.get("IpPort"),
                    event_data.get("SourcePort"),
                )
            ),
            "dst_ip": first_value(
                event_data.get("DestinationIp"),
                event_data.get("DestinationAddress"),
            ),
            "dst_port": parse_integer(
                event_data.get("DestinationPort")
            ),
            "network_protocol": first_value(
                event_data.get("Protocol"),
                event_data.get("ApplicationProtocol"),
            ),
            "rule_id": None,
            "rule_name": None,
            "audit_type": None,
            "audit_group_id": None,
            "channel": record.get("channel"),
            "provider": record.get("provider"),
            "file_path": first_value(
                event_data.get("TargetFilename"),
                event_data.get("Path"),
            ),
            "file_hash": first_value(
                event_data.get("Hashes"),
                event_data.get("Hash"),
            ),
            "tags": [category],
            "raw_message": record.get("raw_message"),
            "details": copy.deepcopy(event_data),
        }
    )

    return normalized


def linux_category(record, parsed_fields):
    existing = parsed_fields.get("event_category")

    if existing:
        return str(existing)

    audit_type = record.get("audit_type")

    if audit_type in AUDIT_CATEGORIES:
        return AUDIT_CATEGORIES[audit_type]

    program = str(record.get("program") or "").lower()
    message = str(record.get("raw_message") or "").lower()

    if program in {
        "sshd",
        "login",
        "su",
        "systemd-logind",
        "polkitd",
    }:
        return "authentication"

    if program == "sudo":
        return "privilege"

    if program == "cron":
        return "scheduled_task"

    if program == "suricata":
        return "alert"

    if "[ufw " in message:
        return "network"

    if program in {"ntpd", "dhclient"}:
        return "network"

    return "system"


def linux_severity(record, parsed_fields, category):
    message = str(record.get("raw_message") or "").lower()
    audit_type = record.get("audit_type")
    result = str(
        first_value(
            parsed_fields.get("res"),
            parsed_fields.get("success"),
            "",
        )
    ).lower()

    if audit_type == "AVC":
        return "medium"

    if "failed" in message or result in {"failed", "no"}:
        return "low"

    if "[ufw block]" in message or "[ufw deny]" in message:
        return "low"

    if category in {"user_creation", "privilege"}:
        return "medium"

    return "informational"


def linux_outcome(record, parsed_fields):
    result = first_value(
        parsed_fields.get("res"),
        parsed_fields.get("success"),
    )

    if result is not None:
        lowered = str(result).lower()

        if lowered in {"success", "yes", "true", "1"}:
            return "success"

        if lowered in {"failed", "failure", "no", "false", "0"}:
            return "failure"

        return str(result)

    message = str(record.get("raw_message") or "").lower()

    if "failed" in message or "failure" in message:
        return "failure"

    if "accepted" in message or "success" in message:
        return "success"

    return None


def linux_action(record, category):
    audit_type = str(record.get("audit_type") or "").lower()

    if audit_type:
        return audit_type

    if category == "authentication":
        return "authenticate"

    if category == "privilege":
        return "privilege_use"

    if category == "scheduled_task":
        return "scheduled_execute"

    if category == "network":
        return "network_activity"

    return None


def normalize_linux(record):
    normalized = empty_normalized_record()
    parsed_fields = record.get("parsed_fields")

    if not isinstance(parsed_fields, dict):
        parsed_fields = {}

    category = linux_category(record, parsed_fields)
    program = record.get("program")

    normalized.update(
        {
            "timestamp": parse_timestamp(
                record.get("timestamp_raw"),
                evidence_year,
            ),
            "hostname": record.get("hostname"),
            "source_type": "linux",
            "source_origin": record.get("source_origin"),
            "event_category": category,
            "severity": linux_severity(
                record,
                parsed_fields,
                category,
            ),
            "event_id": None,
            "event_action": linux_action(record, category),
            "outcome": linux_outcome(record, parsed_fields),
            "user": record.get("user"),
            "process_name": first_value(
                parsed_fields.get("exe"),
                parsed_fields.get("comm"),
                program,
            ),
            "process_id": parse_integer(record.get("pid")),
            "parent_process_id": parse_integer(
                parsed_fields.get("ppid")
            ),
            "command_line": first_value(
                parsed_fields.get("command"),
                parsed_fields.get("COMMAND"),
                parsed_fields.get("proctitle"),
            ),
            "src_ip": first_value(
                parsed_fields.get("addr"),
                parsed_fields.get("SRC"),
            ),
            "src_port": parse_integer(
                parsed_fields.get("SPT")
            ),
            "dst_ip": parsed_fields.get("DST"),
            "dst_port": parse_integer(
                parsed_fields.get("DPT")
            ),
            "network_protocol": parsed_fields.get("PROTO"),
            "rule_id": parsed_fields.get("key"),
            "rule_name": None,
            "audit_type": record.get("audit_type"),
            "audit_group_id": parsed_fields.get(
                "audit_group_id"
            ),
            "channel": parsed_fields.get("source_file"),
            "provider": (
                "auditd"
                if record.get("audit_type") is not None
                else program
            ),
            "file_path": first_value(
                parsed_fields.get("name"),
                parsed_fields.get("path"),
                parsed_fields.get("exe"),
            ),
            "file_hash": parsed_fields.get("hash"),
            "tags": [category],
            "raw_message": record.get("raw_message"),
            "details": copy.deepcopy(parsed_fields),
        }
    )

    return normalized


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


def validate_normalized(record):
    reasons = []

    if record.get("timestamp") is None:
        reasons.append("unparseable timestamp")

    for field in required_fields:
        value = record.get(field)

        if value is None or value == "":
            reasons.append(f"missing required field: {field}")

    for name, definition in field_definitions.items():
        value = record.get(name)

        if not value_matches_type(value, definition["type"]):
            reasons.append(
                "invalid type for field "
                f"{name}: expected {definition['type']}"
            )

    return list(dict.fromkeys(reasons))


def quarantine_record(
    original,
    source_type,
    line_number,
    reasons,
):
    if isinstance(original, dict):
        quarantined = copy.deepcopy(original)
    else:
        quarantined = {"raw_record": original}

    quarantined["quarantine_source_type"] = source_type
    quarantined["quarantine_source_line"] = line_number
    quarantined["quarantine_reason"] = "; ".join(reasons)
    return quarantined


def write_ndjson(stream, record):
    stream.write(
        json.dumps(
            record,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    stream.write("\n")


def process_source(
    input_path,
    source_label,
    normalizer,
    normalized_stream,
    quarantine_stream,
):
    normalized_count = 0
    quarantine_count = 0

    for line_number, original in iter_ndjson(input_path):
        if (
            isinstance(original, dict)
            and original.get("_invalid_json")
        ):
            reasons = [
                "invalid JSON: "
                + str(original.get("_json_error"))
            ]
            write_ndjson(
                quarantine_stream,
                quarantine_record(
                    original.get("_raw_record"),
                    source_label,
                    line_number,
                    reasons,
                ),
            )
            quarantine_count += 1
            continue

        if not isinstance(original, dict):
            write_ndjson(
                quarantine_stream,
                quarantine_record(
                    original,
                    source_label,
                    line_number,
                    ["record is not a JSON object"],
                ),
            )
            quarantine_count += 1
            continue

        try:
            normalized = normalizer(original)
        except (TypeError, ValueError, AttributeError) as error:
            write_ndjson(
                quarantine_stream,
                quarantine_record(
                    original,
                    source_label,
                    line_number,
                    [f"normalization error: {error}"],
                ),
            )
            quarantine_count += 1
            continue

        reasons = validate_normalized(normalized)

        if reasons:
            write_ndjson(
                quarantine_stream,
                quarantine_record(
                    original,
                    source_label,
                    line_number,
                    reasons,
                ),
            )
            quarantine_count += 1
        else:
            write_ndjson(normalized_stream, normalized)
            normalized_count += 1

    return normalized_count, quarantine_count


normalized_file.parent.mkdir(parents=True, exist_ok=True)
quarantine_file.parent.mkdir(parents=True, exist_ok=True)

normalized_temp = None
quarantine_temp = None

try:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=normalized_file.parent,
        prefix=".normalized_events.",
        suffix=".tmp",
        delete=False,
    ) as normalized_stream, tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=quarantine_file.parent,
        prefix=".quarantine.",
        suffix=".tmp",
        delete=False,
    ) as quarantine_stream:
        normalized_temp = Path(normalized_stream.name)
        quarantine_temp = Path(quarantine_stream.name)

        windows_counts = process_source(
            windows_file,
            "windows_json",
            normalize_windows,
            normalized_stream,
            quarantine_stream,
        )
        linux_counts = process_source(
            linux_file,
            "linux_text",
            normalize_linux,
            normalized_stream,
            quarantine_stream,
        )

    os.replace(normalized_temp, normalized_file)
    os.replace(quarantine_temp, quarantine_file)

except Exception:
    for temporary_path in (
        normalized_temp,
        quarantine_temp,
    ):
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    raise

total_normalized = windows_counts[0] + linux_counts[0]
total_quarantined = windows_counts[1] + linux_counts[1]

print(
    "windows_json     : normalized "
    f"{windows_counts[0]:7d} "
    f"{windows_counts[1]:7d} quarantined"
)
print(
    "linux_text       : normalized "
    f"{linux_counts[0]:7d} "
    f"{linux_counts[1]:7d} quarantined"
)
print(
    "total            : normalized "
    f"{total_normalized:7d} "
    f"{total_quarantined:7d} quarantined"
)
print(f"{normalized_file.name} written")
print(f"{quarantine_file.name} written")
PYTHON