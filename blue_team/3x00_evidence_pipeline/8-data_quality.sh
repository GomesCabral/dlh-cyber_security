#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${1:-${WORK_DIR:-$SCRIPT_DIR}}"
INPUT_FILE="${INPUT_FILE:-$WORK_DIR/normalized_events.json}"
CLEANED_FILE="${CLEANED_FILE:-$WORK_DIR/cleaned_events.json}"
CLEANING_LOG="${CLEANING_LOG:-$WORK_DIR/cleaning_log.json}"
EXPECTED_START="${EXPECTED_START:-}"
EXPECTED_END="${EXPECTED_END:-}"

if [[ ! -f "$INPUT_FILE" ]]; then
    printf 'ERROR: normalized input not found: %s\n' \
        "$INPUT_FILE" >&2
    exit 1
fi

if [[ ! -r "$INPUT_FILE" ]]; then
    printf 'ERROR: normalized input is not readable: %s\n' \
        "$INPUT_FILE" >&2
    exit 1
fi

mkdir -p -- "$(dirname -- "$CLEANED_FILE")"
mkdir -p -- "$(dirname -- "$CLEANING_LOG")"

python3 -W error - \
    "$INPUT_FILE" \
    "$CLEANED_FILE" \
    "$CLEANING_LOG" \
    "$EXPECTED_START" \
    "$EXPECTED_END" <<'PYTHON'
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime, time, timedelta, timezone
from pathlib import Path


input_file = Path(sys.argv[1])
cleaned_file = Path(sys.argv[2]).resolve()
cleaning_log = Path(sys.argv[3]).resolve()
expected_start_override = sys.argv[4].strip()
expected_end_override = sys.argv[5].strip()

ISO_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})$"
)

AUDIT_PATTERN = re.compile(
    r"^audit\((\d+(?:\.\d+)?):\d+\)$"
)

MOJIBAKE_MARKERS = (
    "Ã",
    "Â",
    "â€",
    "â€™",
    "â€œ",
    "â€\u009d",
    "â€“",
    "â€”",
    "ðŸ",
)


def iter_ndjson(path):
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"invalid JSON at line {line_number}: {error}"
                ) from error

            if not isinstance(record, dict):
                raise ValueError(
                    f"line {line_number} is not a JSON object"
                )

            yield line_number, record


def format_timestamp(value):
    value = value.astimezone(timezone.utc)

    if value.microsecond:
        rendered = value.isoformat(timespec="microseconds")
    else:
        rendered = value.isoformat(timespec="seconds")

    return rendered.replace("+00:00", "Z")


def parse_iso(value):
    if not isinstance(value, str) or not ISO_PATTERN.fullmatch(value):
        return None

    text = value

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    if re.search(r"[+-]\d{4}$", text):
        text = text[:-5] + text[-5:-2] + ":" + text[-2:]

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return None

    return parsed.astimezone(timezone.utc)


def parse_override(value, name):
    parsed = parse_iso(value)

    if parsed is None:
        raise ValueError(
            f"{name} must be an ISO 8601 timestamp with timezone"
        )

    return parsed


def fallback_timestamp(value, inferred_year):
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    audit_match = AUDIT_PATTERN.fullmatch(text)

    if audit_match:
        try:
            return datetime.fromtimestamp(
                float(audit_match.group(1)),
                tz=timezone.utc,
            )
        except (ValueError, OverflowError):
            return None

    if re.fullmatch(r"\d{10}(?:\.\d+)?", text):
        try:
            return datetime.fromtimestamp(
                float(text),
                tz=timezone.utc,
            )
        except (ValueError, OverflowError):
            return None

    if re.fullmatch(r"\d{13}", text):
        try:
            return datetime.fromtimestamp(
                int(text) / 1000,
                tz=timezone.utc,
            )
        except (ValueError, OverflowError):
            return None

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    )

    for pattern in formats:
        try:
            parsed = datetime.strptime(text, pattern)
        except ValueError:
            continue

        return parsed.replace(tzinfo=timezone.utc)

    for pattern in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, pattern)
        except ValueError:
            continue

        return parsed.replace(
            year=inferred_year,
            tzinfo=timezone.utc,
        )

    return None


def infer_year(day_counts):
    if not day_counts:
        return datetime.now(timezone.utc).year

    year_counts = Counter()

    for day, count in day_counts.items():
        year_counts[day.year] += count

    return year_counts.most_common(1)[0][0]


def infer_expected_range(day_counts):
    if not day_counts:
        raise ValueError(
            "cannot infer expected range because no valid timestamps exist"
        )

    maximum = max(day_counts.values())
    threshold = max(1, int(maximum * 0.20))
    core_days = sorted(
        day
        for day, count in day_counts.items()
        if count >= threshold
    )

    if not core_days:
        core_days = sorted(day_counts)

    start = datetime.combine(
        core_days[0],
        time.min,
        tzinfo=timezone.utc,
    )
    end = datetime.combine(
        core_days[-1],
        time.max,
        tzinfo=timezone.utc,
    )
    return start, end


def scan_timestamp_distribution(path):
    day_counts = Counter()

    for _, record in iter_ndjson(path):
        parsed = parse_iso(record.get("timestamp"))

        if parsed is not None:
            day_counts[parsed.date()] += 1

    return day_counts


day_counts = scan_timestamp_distribution(input_file)
inferred_year = infer_year(day_counts)

if expected_start_override:
    expected_start = parse_override(
        expected_start_override,
        "EXPECTED_START",
    )
else:
    expected_start, _ = infer_expected_range(day_counts)

if expected_end_override:
    expected_end = parse_override(
        expected_end_override,
        "EXPECTED_END",
    )
else:
    _, expected_end = infer_expected_range(day_counts)

if expected_start > expected_end:
    raise ValueError("EXPECTED_START is later than EXPECTED_END")

timezone_lower_limit = expected_start - timedelta(hours=12)
timezone_upper_limit = expected_end + timedelta(hours=12)


def record_id(record, line_number):
    canonical = json.dumps(
        record,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()[:20]
    return f"{digest}:{line_number}"


def duplicate_fingerprint(record):
    values = [
        record.get("timestamp"),
        record.get("hostname"),
        record.get("source_type"),
        record.get("raw_message"),
    ]
    canonical = json.dumps(
        values,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).digest()


def mojibake_score(value):
    score = value.count("\ufffd") * 20

    for marker in MOJIBAKE_MARKERS:
        score += value.count(marker)

    return score


def has_encoding_error(value):
    return isinstance(value, str) and mojibake_score(value) > 0


def repair_encoding(value):
    best = value
    best_score = mojibake_score(value)

    for encoding in ("latin-1", "cp1252"):
        candidate = value

        for _ in range(2):
            try:
                candidate = candidate.encode(encoding).decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                break

            candidate_score = mojibake_score(candidate)

            if candidate_score < best_score:
                best = candidate
                best_score = candidate_score

    if best != value and best_score < mojibake_score(value):
        return best

    return None


def write_ndjson(stream, record):
    stream.write(
        json.dumps(
            record,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    stream.write("\n")


def log_entry(
    stream,
    defect_type,
    original_value,
    corrected_value,
    current_record_id,
    reason,
):
    write_ndjson(
        stream,
        {
            "defect_type": defect_type,
            "original_value": original_value,
            "corrected_value": corrected_value,
            "record_id": current_record_id,
            "reason": reason,
        },
    )


def assemble_log(
    output_path,
    corrections_path,
    unrepairable_path,
):
    temporary = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=".cleaning_log.",
            suffix=".tmp",
            delete=False,
        ) as output_stream:
            temporary = Path(output_stream.name)
            output_stream.write("{\n")
            output_stream.write(
                '  "expected_range": '
                + json.dumps(
                    {
                        "start": format_timestamp(expected_start),
                        "end": format_timestamp(expected_end),
                        "timezone_tolerance_hours": 12,
                        "method": (
                            "explicit environment override"
                            if expected_start_override
                            or expected_end_override
                            else "dominant UTC date range"
                        ),
                    },
                    ensure_ascii=False,
                )
                + ",\n"
            )

            for section, path in (
                ("corrections", corrections_path),
                ("unrepairable", unrepairable_path),
            ):
                output_stream.write(f'  "{section}": [')
                first = True

                with path.open("r", encoding="utf-8") as stream:
                    for line in stream:
                        if not line.strip():
                            continue

                        if first:
                            output_stream.write("\n")
                            first = False
                        else:
                            output_stream.write(",\n")

                        output_stream.write("    " + line.strip())

                if not first:
                    output_stream.write("\n  ")

                output_stream.write("]")

                if section == "corrections":
                    output_stream.write(",\n")
                else:
                    output_stream.write("\n")

            output_stream.write("}\n")

        os.replace(temporary, output_path)

    except Exception:
        if temporary is not None and temporary.exists():
            temporary.unlink()

        raise


cleaned_file.parent.mkdir(parents=True, exist_ok=True)
cleaning_log.parent.mkdir(parents=True, exist_ok=True)

cleaned_temp = None
corrections_temp = None
unrepairable_temp = None
seen_duplicates = set()

malformed_detected = 0
malformed_repaired = 0
malformed_dropped = 0
duplicates_detected = 0
hostname_normalized = 0
encoding_detected = 0
encoding_repaired = 0
wrong_timezone_flagged = 0
cleaned_count = 0

try:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=cleaned_file.parent,
        prefix=".cleaned_events.",
        suffix=".tmp",
        delete=False,
    ) as cleaned_stream, tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=cleaning_log.parent,
        prefix=".corrections.",
        suffix=".ndjson",
        delete=False,
    ) as corrections_stream, tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=cleaning_log.parent,
        prefix=".unrepairable.",
        suffix=".ndjson",
        delete=False,
    ) as unrepairable_stream:
        cleaned_temp = Path(cleaned_stream.name)
        corrections_temp = Path(corrections_stream.name)
        unrepairable_temp = Path(unrepairable_stream.name)

        for line_number, record in iter_ndjson(input_file):
            current_id = record_id(record, line_number)
            original_timestamp = record.get("timestamp")
            parsed_timestamp = parse_iso(original_timestamp)

            if parsed_timestamp is None:
                malformed_detected += 1
                parsed_timestamp = fallback_timestamp(
                    original_timestamp,
                    inferred_year,
                )

                if parsed_timestamp is None:
                    malformed_dropped += 1
                    log_entry(
                        unrepairable_stream,
                        "malformed_timestamp",
                        original_timestamp,
                        None,
                        current_id,
                        "Timestamp did not match ISO 8601 or any supported fallback format, so the record was dropped.",
                    )
                    continue

                repaired_timestamp = format_timestamp(parsed_timestamp)
                record["timestamp"] = repaired_timestamp
                malformed_repaired += 1
                log_entry(
                    corrections_stream,
                    "malformed_timestamp",
                    original_timestamp,
                    repaired_timestamp,
                    current_id,
                    "Timestamp was repaired with a supported fallback parser and converted to UTC ISO 8601.",
                )
            else:
                canonical_timestamp = format_timestamp(parsed_timestamp)
                record["timestamp"] = canonical_timestamp

            fingerprint = duplicate_fingerprint(record)

            if fingerprint in seen_duplicates:
                duplicates_detected += 1
                log_entry(
                    corrections_stream,
                    "duplicate",
                    {
                        "timestamp": record.get("timestamp"),
                        "hostname": record.get("hostname"),
                        "source_type": record.get("source_type"),
                        "raw_message": record.get("raw_message"),
                    },
                    None,
                    current_id,
                    "A prior record had the same timestamp, hostname, source_type, and raw_message, so this occurrence was removed.",
                )
                continue

            seen_duplicates.add(fingerprint)

            hostname = record.get("hostname")

            if isinstance(hostname, str):
                lowered_hostname = hostname.lower()

                if lowered_hostname != hostname:
                    record["hostname"] = lowered_hostname
                    hostname_normalized += 1
                    log_entry(
                        corrections_stream,
                        "hostname_case",
                        hostname,
                        lowered_hostname,
                        current_id,
                        "Hostnames are normalized to lowercase for reliable correlation.",
                    )

            raw_message = record.get("raw_message")

            if has_encoding_error(raw_message):
                encoding_detected += 1
                repaired_message = repair_encoding(raw_message)

                if repaired_message is not None:
                    record["raw_message"] = repaired_message
                    encoding_repaired += 1
                    log_entry(
                        corrections_stream,
                        "encoding_error",
                        raw_message,
                        repaired_message,
                        current_id,
                        "Mojibake was reversed by re-encoding the text as latin-1 or Windows-1252 and decoding it as UTF-8.",
                    )
                else:
                    log_entry(
                        corrections_stream,
                        "encoding_error",
                        raw_message,
                        raw_message,
                        current_id,
                        "An encoding defect was detected, but the original bytes could not be reconstructed safely, so the message was retained.",
                    )

            if (
                parsed_timestamp < timezone_lower_limit
                or parsed_timestamp > timezone_upper_limit
            ):
                tags = record.get("tags")

                if not isinstance(tags, list):
                    tags = []

                if "suspected_wrong_tz" not in tags:
                    tags.append("suspected_wrong_tz")

                record["tags"] = tags
                wrong_timezone_flagged += 1
                log_entry(
                    corrections_stream,
                    "suspected_wrong_tz",
                    record.get("timestamp"),
                    record.get("timestamp"),
                    current_id,
                    "Timestamp is more than 12 hours outside the inferred evidence date range and was flagged without altering its value.",
                )

            write_ndjson(cleaned_stream, record)
            cleaned_count += 1

    os.replace(cleaned_temp, cleaned_file)
    assemble_log(
        cleaning_log,
        corrections_temp,
        unrepairable_temp,
    )

except Exception:
    if cleaned_temp is not None and cleaned_temp.exists():
        cleaned_temp.unlink()

    raise

finally:
    for temporary_path in (
        corrections_temp,
        unrepairable_temp,
    ):
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

print(
    "malformed timestamps   : "
    f"{malformed_detected:7d} detected "
    f"{malformed_repaired:7d} repaired "
    f"{malformed_dropped:7d} dropped"
)
print(
    "duplicates             : "
    f"{duplicates_detected:7d} detected "
    f"{duplicates_detected:7d} removed"
)
print(
    "hostname case          : "
    f"{hostname_normalized:7d} normalized"
)
print(
    "encoding errors        : "
    f"{encoding_detected:7d} detected "
    f"{encoding_repaired:7d} repaired"
)
print(
    "suspected wrong tz     : "
    f"{wrong_timezone_flagged:7d} flagged"
)
print(
    "expected UTC range     : "
    f"{format_timestamp(expected_start)} to "
    f"{format_timestamp(expected_end)}"
)
print(
    f"{cleaned_file.name}    written "
    f"({cleaned_count} records)"
)
print(f"{cleaning_log.name}      written")
PYTHON
