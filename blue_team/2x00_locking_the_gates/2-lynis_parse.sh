#!/bin/bash

# MedDefense Health Systems - Lynis Audit Parser
#
# Converts a Lynis .dat report into structured JSON.
#
# Threat context:
# Lynis findings provide measurable evidence of weaknesses such as
# insufficient kernel hardening, weak authentication, unnecessary services,
# unsafe permissions and missing audit controls.
#
# This script performs analysis only and does not modify the target system.

set -euo pipefail

export LC_ALL=C

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <lynis-report.dat>" >&2
    exit 1
fi

REPORT_FILE="$1"

if [[ ! -f "$REPORT_FILE" ]]; then
    echo "Error: report file not found: $REPORT_FILE" >&2
    exit 1
fi

if [[ ! -r "$REPORT_FILE" ]]; then
    echo "Error: report file is not readable: $REPORT_FILE" >&2
    exit 1
fi

if [[ "$REPORT_FILE" != *.dat ]]; then
    echo "Error: expected a .dat Lynis report file." >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required." >&2
    exit 1
fi

HARDENING_INDEX="$(
    awk -F= '
        /^hardening_index=/ {
            print $2
            exit
        }
    ' "$REPORT_FILE"
)"

if [[ -z "$HARDENING_INDEX" ]]; then
    HARDENING_INDEX=0
fi

if [[ ! "$HARDENING_INDEX" =~ ^[0-9]+$ ]]; then
    echo "Error: invalid hardening index in Lynis report." >&2
    exit 1
fi

parse_findings() {
    local severity="$1"
    local report="$2"

    awk -v severity="$severity" '
        BEGIN {
            prefix = severity "[]="
        }

        index($0, prefix) == 1 {
            value = substr($0, length(prefix) + 1)

            split(value, fields, "|")

            test_id = fields[1]
            message = fields[2]

            if (test_id == "") {
                test_id = "LYNIS"
            }

            if (message == "") {
                message = value
            }

            print severity "\t" test_id "\t" message
        }
    ' "$report"
}

{
    parse_findings "warning" "$REPORT_FILE"
    parse_findings "suggestion" "$REPORT_FILE"
    parse_findings "manual_check" "$REPORT_FILE"
} | jq -R -s \
    --argjson hardening_index "$HARDENING_INDEX" '
    split("\n")
    | map(select(length > 0))
    | map(
        split("\t")
        | {
            severity: .[0],
            test_id: .[1],
            message: .[2]
        }
    )
    | {
        hardening_index: $hardening_index,
        findings: .
    }
'
