#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == "--version" ]]; then
    echo "3x00-capstone-1.0"
    exit 0
fi

EVIDENCE_ROOT="${1:-${CAPSTONE_PACK:-$HOME/evidence_pack_secondary}}"
OUTPUT_DIR="${2:-${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}/enriched}"

fail() {
    printf '[pipeline] ERROR: %s\n' "$*" >&2
    exit 1
}

run_stage() {
    local number="$1"
    local name="$2"
    shift 2

    printf '[pipeline] stage %s %-20s ... ' "$number" "$name"

    if "$@"; then
        printf 'ok\n'
    else
        printf 'failed\n' >&2
        exit 1
    fi
}

[[ -d "$EVIDENCE_ROOT" ]] ||
    fail "evidence pack not found: $EVIDENCE_ROOT"

mkdir -p "$OUTPUT_DIR"

run_stage 0 source_inventory \
    "$SCRIPT_DIR/0-source_inventory.sh" \
    "$EVIDENCE_ROOT" \
    "$OUTPUT_DIR/source_inventory.json"

run_stage 2 windows_parse \
    "$SCRIPT_DIR/2-windows_parse.sh" \
    "$EVIDENCE_ROOT" \
    "$OUTPUT_DIR/windows_events.json"

run_stage 3 linux_parse \
    "$SCRIPT_DIR/3-linux_parse.sh" \
    "$EVIDENCE_ROOT" \
    "$OUTPUT_DIR/linux_events.json"

cp "$SCRIPT_DIR/event_schema.json" "$OUTPUT_DIR/event_schema.json"

run_stage 5 normalize \
    "$SCRIPT_DIR/5-normalize.sh" "$OUTPUT_DIR"

run_stage 6 network_normalize \
    "$SCRIPT_DIR/6-network_normalize.sh" \
    "$EVIDENCE_ROOT" \
    "$OUTPUT_DIR"

run_stage 8 data_quality \
    "$SCRIPT_DIR/8-data_quality.sh" "$OUTPUT_DIR"

run_stage 9 enrich \
    "$SCRIPT_DIR/9-enrich.sh" \
    "$OUTPUT_DIR" \
    "$EVIDENCE_ROOT"

[[ -s "$OUTPUT_DIR/enriched_events.json" ]] ||
    fail "enriched_events.json was not produced"

printf '[pipeline] stage 10 timeline             ... '

cp "$OUTPUT_DIR/enriched_events.json" \
   "$OUTPUT_DIR/enriched_events.jsonl"

if jq -rc '"\(.timestamp // .["@timestamp"] // .event_time // "")\t\(tojson)"' \
    "$OUTPUT_DIR/enriched_events.jsonl" |
    LC_ALL=C sort -T "$OUTPUT_DIR" -k1,1 |
    cut -f2- > "$OUTPUT_DIR/timeline.jsonl"
then
    printf 'ok\n'
else
    printf 'failed\n' >&2
    exit 1
fi

run_stage 11 source_stats python3 - "$OUTPUT_DIR" <<'PYTHON'
import json
import sys
from collections import Counter
from pathlib import Path

directory = Path(sys.argv[1])
events_file = directory / "enriched_events.jsonl"
cleaning_file = directory / "cleaning_log.json"
stats_file = directory / "source_stats.json"

counts = Counter({
    "windows_json": 0,
    "linux_text": 0,
    "firewall": 0,
    "suricata_alert": 0,
    "pcap_flow": 0,
})

events_out = 0

with events_file.open("r", encoding="utf-8") as stream:
    for line in stream:
        if not line.strip():
            continue

        event = json.loads(line)
        events_out += 1

        searchable = " ".join(
            str(event.get(field, "")).lower()
            for field in (
                "source_type",
                "source",
                "source_file",
                "event_source",
                "event_category",
                "dataset",
                "log_type",
            )
        )

        if "windows" in searchable or "sysmon" in searchable:
            counts["windows_json"] += 1
        elif "linux" in searchable or "auth.log" in searchable or "syslog" in searchable:
            counts["linux_text"] += 1
        elif "suricata" in searchable or "eve.json" in searchable:
            counts["suricata_alert"] += 1
        elif "firewall" in searchable:
            counts["firewall"] += 1
        elif "pcap" in searchable or "flow" in searchable:
            counts["pcap_flow"] += 1

dirty = []
events_dropped = 0

if cleaning_file.exists() and cleaning_file.stat().st_size:
    try:
        cleaning = json.loads(
            cleaning_file.read_text(encoding="utf-8-sig")
        )

        for key, value in cleaning.items():
            lowered = key.lower()

            if isinstance(value, int) and value > 0:
                if any(word in lowered for word in (
                    "drop", "duplicate", "malformed",
                    "skew", "invalid", "gap", "correct"
                )):
                    dirty.append(f"{key}:{value}")

                if "drop" in lowered or "quarantine" in lowered:
                    events_dropped += value
    except (json.JSONDecodeError, OSError):
        dirty.append("cleaning_log_unreadable")

result = {
    "events_in": events_out + events_dropped,
    "events_out": events_out,
    "events_dropped": events_dropped,
    "source_counts": dict(counts),
    "dirty_data_detected": sorted(set(dirty)),
}

stats_file.write_text(
    json.dumps(result, indent=2) + "\n",
    encoding="utf-8",
)
PYTHON

printf '[pipeline] completed: %s\n' "$OUTPUT_DIR"

