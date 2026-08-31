#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_ROOT="${1:-${EVIDENCE_ROOT:-$HOME/evidence_pack_primary}}"
OUTPUT_FILE="${2:-${OUTPUT_FILE:-$SCRIPT_DIR/windows_events.json}}"

WINDOWS_DIR="$EVIDENCE_ROOT/windows"
TELEMETRY_FILE="$EVIDENCE_ROOT/student_telemetry/windows_events.json"

declare -a WINDOWS_FILES=(
    "$WINDOWS_DIR/security.json"
    "$WINDOWS_DIR/sysmon.json"
    "$WINDOWS_DIR/powershell.json"
)

for input_file in "${WINDOWS_FILES[@]}" "$TELEMETRY_FILE"; do
    if [[ ! -f "$input_file" ]]; then
        printf 'ERROR: required input file not found: %s\n' \
            "$input_file" >&2
        exit 1
    fi

    if [[ ! -r "$input_file" ]]; then
        printf 'ERROR: input file is not readable: %s\n' \
            "$input_file" >&2
        exit 1
    fi
done

OUTPUT_DIR="$(dirname -- "$OUTPUT_FILE")"
mkdir -p -- "$OUTPUT_DIR"

TMP_DIR="$(mktemp -d)"
TMP_OUTPUT="$TMP_DIR/windows_events.json"
trap 'rm -rf -- "$TMP_DIR"' EXIT

: > "$TMP_OUTPUT"

process_file() {
    local input_file="$1"
    local mode="$2"
    local segment_file="$3"

    jq -c \
        --arg mode "$mode" \
        --arg filename "$(basename -- "$input_file")" \
        '
        def fail($message):
            error(
                $filename
                + " line "
                + (input_line_number | tostring)
                + ": "
                + $message
            );

        def required_fields:
            [
                "timestamp_raw",
                "hostname",
                "event_id",
                "channel",
                "provider",
                "raw_message",
                "event_data",
                "source_origin"
            ];

        if type != "object" then
            fail("record is not a JSON object")
        else
            .
        end

        | if $mode == "student_telemetry" then
      .timestamp_raw = (
          .timestamp_raw // .timestamp
      )

      | .channel = (
          .channel //
          if (
              .event_id == 4104
              or (
                  (.event_category // "")
                  | ascii_downcase
                  | contains("powershell")
              )
          ) then
              "Microsoft-Windows-PowerShell/Operational"
          elif .source_type == "Security" then
              "Security"
          elif .source_type == "Sysmon" then
              "Microsoft-Windows-Sysmon/Operational"
          elif .source_type == "PowerShell" then
              "Microsoft-Windows-PowerShell/Operational"
          else
              .source_type
          end
      )

      | .provider = (
          .provider //
          if .channel == "Security" then
              "Microsoft-Windows-Security-Auditing"
          elif (
              .channel
              == "Microsoft-Windows-Sysmon/Operational"
          ) then
              "Microsoft-Windows-Sysmon"
          elif (
              .channel
              == "Microsoft-Windows-PowerShell/Operational"
          ) then
              "Microsoft-Windows-PowerShell"
          else
              "MedDefense-Student-Telemetry"
          end
      )

      | .event_data = (
          .event_data // {
              event_category: .event_category,
              user: .user,
              command_line: .command_line,
              original_source_type: .source_type
          }
      )

      | .source_origin = (
          .source_origin // "student_telemetry"
      )
  else
      .
  end

        | (required_fields - keys) as $missing

        | if ($missing | length) > 0 then
              fail(
                  "missing required fields: "
                  + ($missing | join(", "))
              )
          else
              .
          end

        | if (
              $mode == "evidence_pack"
              and .source_origin != "evidence_pack"
          ) then
              fail(
                  "expected source_origin evidence_pack, received "
                  + (.source_origin | tostring)
              )
          else
              .
          end
        ' "$input_file" > "$segment_file"
}

total_records=0

for input_file in "${WINDOWS_FILES[@]}"; do
    filename="$(basename -- "$input_file")"
    segment_file="$TMP_DIR/$filename"

    process_file "$input_file" "evidence_pack" "$segment_file"

    record_count="$(awk 'END {print NR + 0}' "$segment_file")"
    cat -- "$segment_file" >> "$TMP_OUTPUT"

    printf 'reading %-18s ... %6d records\n' \
        "$filename" \
        "$record_count"

    total_records=$((total_records + record_count))
done

telemetry_segment="$TMP_DIR/student_windows_events.json"

process_file \
    "$TELEMETRY_FILE" \
    "student_telemetry" \
    "$telemetry_segment"

telemetry_count="$(awk 'END {print NR + 0}' "$telemetry_segment")"
cat -- "$telemetry_segment" >> "$TMP_OUTPUT"

printf 'appending student telemetry ... %6d records\n' \
    "$telemetry_count"

total_records=$((total_records + telemetry_count))

mv -- "$TMP_OUTPUT" "$OUTPUT_FILE"

printf 'windows_events.json: %d records\n' "$total_records"
