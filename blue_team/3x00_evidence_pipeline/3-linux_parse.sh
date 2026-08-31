#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_ROOT="${1:-${EVIDENCE_ROOT:-$HOME/evidence_pack_primary}}"
OUTPUT_FILE="${2:-${OUTPUT_FILE:-$SCRIPT_DIR/linux_events.json}}"

AUTH_LOG="$EVIDENCE_ROOT/linux/auth.log"
AUDIT_LOG="$EVIDENCE_ROOT/linux/audit.log"
SYSLOG_FILE="$EVIDENCE_ROOT/linux/syslog"
TELEMETRY_FILE="$EVIDENCE_ROOT/student_telemetry/linux_events.json"

declare -a REQUIRED_FILES=(
    "$AUTH_LOG"
    "$AUDIT_LOG"
    "$SYSLOG_FILE"
    "$TELEMETRY_FILE"
)

for input_file in "${REQUIRED_FILES[@]}"; do
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

OUTPUT_DIR="$(dirname -- "$OUTPUT_FILE")"
mkdir -p -- "$OUTPUT_DIR"

python3 -W error - \
    "$AUTH_LOG" \
    "$AUDIT_LOG" \
    "$SYSLOG_FILE" \
    "$TELEMETRY_FILE" \
    "$OUTPUT_FILE" <<'PYTHON'
import json
import os
import re
import sys
import tempfile
from pathlib import Path


auth_log = Path(sys.argv[1])
audit_log = Path(sys.argv[2])
syslog_file = Path(sys.argv[3])
telemetry_file = Path(sys.argv[4])
output_file = Path(sys.argv[5]).resolve()

SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+"
    r"\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>[^\s:\[]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

ISO_PREFIXED_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+"
    r"\d{2}:\d{2}:\d{2})\s+"
    r"(?:(?:[A-Z][a-z]{2}\s+)?"
    r"\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)?"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>[^\s:\[]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

AUDIT_TYPE_PATTERN = re.compile(r"\btype=([A-Z0-9_]+)")
AUDIT_ID_PATTERN = re.compile(
    r"\bmsg=audit\((\d+(?:\.\d+)?):(\d+)\)"
)
KEY_VALUE_PATTERN = re.compile(
    r"""([A-Za-z_][A-Za-z0-9_]*)="""
    r"""(?:"([^"]*)"|'([^']*)'|([^\s]+))"""
)

USER_PATTERNS = (
    re.compile(
        r"\bfor\s+(?:invalid\s+user\s+)?"
        r"([A-Za-z0-9._-]+)"
    ),
    re.compile(r"\buser\s+([A-Za-z0-9._-]+)"),
    re.compile(r"^\s*([A-Za-z0-9._-]+)\s*:\s+TTY="),
)


def emit(output_stream, record):
    output_stream.write(
        json.dumps(
            record,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    output_stream.write("\n")


def extract_key_values(text):
    fields = {}

    for match in KEY_VALUE_PATTERN.finditer(text):
        key = match.group(1)
        value = next(
            item
            for item in match.groups()[1:]
            if item is not None
        )
        fields[key] = value

    nested_message = fields.get("msg")

    if nested_message and "=" in nested_message:
        for key, value in extract_key_values(
            nested_message
        ).items():
            fields.setdefault(key, value)

    return fields


def parse_pid(value):
    if value is None:
        return None

    try:
        return int(value)
    except ValueError:
        return None


def extract_syslog_user(message, fields):
    for pattern in USER_PATTERNS:
        match = pattern.search(message)

        if match:
            return match.group(1)

    for key in ("acct", "user"):
        value = fields.get(key)

        if value:
            return value

    return None


def parse_syslog_line(line, source_file):
    raw_line = line.rstrip("\r\n")
    match = SYSLOG_PATTERN.match(raw_line)

    if match is None:
        match = ISO_PREFIXED_PATTERN.match(raw_line)

    if match is None:
        return {
            "timestamp_raw": None,
            "hostname": None,
            "program": None,
            "audit_type": None,
            "pid": None,
            "user": None,
            "raw_message": raw_line,
            "parsed_fields": {
                "source_file": source_file,
                "parse_status": "unparsed",
            },
            "source_origin": "evidence_pack",
        }

    values = match.groupdict()
    message = values["message"]
    fields = extract_key_values(message)
    fields["message"] = message
    fields["source_file"] = source_file
    fields["parse_status"] = "parsed"

    return {
        "timestamp_raw": values["timestamp"],
        "hostname": values["hostname"],
        "program": values["program"],
        "audit_type": None,
        "pid": parse_pid(values.get("pid")),
        "user": extract_syslog_user(message, fields),
        "raw_message": raw_line,
        "parsed_fields": fields,
        "source_origin": "evidence_pack",
    }


def parse_audit_line(line, source_file):
    raw_line = line.rstrip("\r\n")
    audit_type_match = AUDIT_TYPE_PATTERN.search(raw_line)
    audit_id_match = AUDIT_ID_PATTERN.search(raw_line)
    fields = extract_key_values(raw_line)

    if audit_id_match:
        audit_group_id = (
            f"{audit_id_match.group(1)}:"
            f"{audit_id_match.group(2)}"
        )
        timestamp_raw = f"audit({audit_group_id})"
    else:
        audit_group_id = None
        timestamp_raw = None

    fields["audit_group_id"] = audit_group_id
    fields["source_file"] = source_file
    fields["parse_status"] = (
        "parsed"
        if audit_type_match and audit_id_match
        else "partial"
    )

    hostname = (
        fields.get("hostname")
        or fields.get("node")
    )

    user = (
        fields.get("acct")
        or fields.get("user")
        or fields.get("auid")
        or fields.get("uid")
    )

    return {
        "timestamp_raw": timestamp_raw,
        "hostname": hostname,
        "program": None,
        "audit_type": (
            audit_type_match.group(1)
            if audit_type_match
            else None
        ),
        "pid": parse_pid(fields.get("pid")),
        "user": user,
        "raw_message": raw_line,
        "parsed_fields": fields,
        "source_origin": "evidence_pack",
    }


def parse_telemetry_record(record, line_number):
    if not isinstance(record, dict):
        raise ValueError(
            "student telemetry line "
            f"{line_number} is not a JSON object"
        )

    required = {
        "timestamp",
        "hostname",
        "source_type",
        "event_category",
        "user",
        "command",
        "raw_message",
    }

    missing = sorted(required - record.keys())

    if missing:
        raise ValueError(
            "student telemetry line "
            f"{line_number} is missing: "
            + ", ".join(missing)
        )

    source_type = str(record["source_type"])
    source_type_lower = source_type.lower()

    if source_type_lower == "auditd":
        program = None
        audit_type = str(
            record["event_category"]
        ).upper()
    else:
        program = source_type
        audit_type = None

    parsed_fields = {
        "event_category": record["event_category"],
        "command": record["command"],
        "original_source_type": source_type,
        "source_file": "student_telemetry/"
        "linux_events.json",
        "parse_status": "mapped",
    }

    return {
        "timestamp_raw": record["timestamp"],
        "hostname": record["hostname"],
        "program": program,
        "audit_type": audit_type,
        "pid": record.get("pid"),
        "user": record.get("user"),
        "raw_message": record["raw_message"],
        "parsed_fields": parsed_fields,
        "source_origin": (
            record.get("source_origin")
            or "student_telemetry"
        ),
    }


def process_text_file(
    input_path,
    output_stream,
    parser,
    source_file,
):
    line_count = 0
    record_count = 0

    with input_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as input_stream:
        for line in input_stream:
            line_count += 1
            emit(
                output_stream,
                parser(line, source_file),
            )
            record_count += 1

    return line_count, record_count


def process_telemetry(input_path, output_stream):
    record_count = 0

    with input_path.open(
        "r",
        encoding="utf-8",
    ) as input_stream:
        for line_number, line in enumerate(
            input_stream,
            start=1,
        ):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    "invalid student telemetry JSON at "
                    f"line {line_number}: {error}"
                ) from error

            emit(
                output_stream,
                parse_telemetry_record(
                    record,
                    line_number,
                ),
            )
            record_count += 1

    return record_count


output_file.parent.mkdir(
    parents=True,
    exist_ok=True,
)

temporary_path = None

try:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output_file.parent,
        prefix=".linux_events.",
        suffix=".tmp",
        delete=False,
    ) as output_stream:
        temporary_path = Path(output_stream.name)

        auth_lines, auth_records = process_text_file(
            auth_log,
            output_stream,
            parse_syslog_line,
            "linux/auth.log",
        )

        audit_lines, audit_records = process_text_file(
            audit_log,
            output_stream,
            parse_audit_line,
            "linux/audit.log",
        )

        syslog_lines, syslog_records = (
            process_text_file(
                syslog_file,
                output_stream,
                parse_syslog_line,
                "linux/syslog",
            )
        )

        telemetry_records = process_telemetry(
            telemetry_file,
            output_stream,
        )

    os.replace(temporary_path, output_file)

except Exception:
    if (
        temporary_path is not None
        and temporary_path.exists()
    ):
        temporary_path.unlink()

    raise

total_records = (
    auth_records
    + audit_records
    + syslog_records
    + telemetry_records
)

print(
    f"parsing auth.log      ... "
    f"{auth_lines} lines -> {auth_records} records"
)
print(
    f"parsing audit.log     ... "
    f"{audit_lines} lines -> {audit_records} records"
)
print(
    f"parsing syslog        ... "
    f"{syslog_lines} lines -> {syslog_records} records"
)
print(
    "appending student telemetry ... "
    f"{telemetry_records} records"
)
print(
    f"linux_events.json: {total_records} records written"
)
PYTHON
