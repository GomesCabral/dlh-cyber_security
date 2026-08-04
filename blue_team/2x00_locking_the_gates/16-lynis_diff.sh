#!/bin/bash

# MedDefense Health Systems - Lynis Improvement Diff
#
# Compares the pre-hardening and post-hardening Lynis findings and produces
# structured evidence of security improvement.
#
# The report identifies:
# - resolved findings
# - remaining findings
# - newly introduced findings
# - hardening-index improvement
# - residual risk
#
# This script does not modify security configuration. If a post-hardening
# Lynis report does not exist, it may run a new Lynis assessment and parse it.

set -euo pipefail

export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BEFORE_FILE="${SCRIPT_DIR}/lynis_findings.json"
POST_FILE="${SCRIPT_DIR}/lynis_post_findings.json"

ALTERNATE_BEFORE="${SCRIPT_DIR}/lynis_before.json"
ALTERNATE_POST="${SCRIPT_DIR}/lynis_after.json"

LYNIS_REPORT="/var/log/lynis-report.dat"
PARSER="${SCRIPT_DIR}/2-lynis_parse.sh"

OUTPUT_FILE="${SCRIPT_DIR}/hardening_improvement.json"

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: run this script with sudo." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Resolve pre-hardening evidence
# ---------------------------------------------------------------------------

if [[ ! -f "$BEFORE_FILE" ]]; then
    if [[ -f "$ALTERNATE_BEFORE" ]]; then
        BEFORE_FILE="$ALTERNATE_BEFORE"
    else
        echo "Error: no pre-hardening Lynis JSON report found." >&2
        echo "Expected one of:" >&2
        echo "  lynis_findings.json" >&2
        echo "  lynis_before.json" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Resolve or generate post-hardening evidence
# ---------------------------------------------------------------------------

if [[ ! -f "$POST_FILE" ]]; then

    if [[ -f "$ALTERNATE_POST" ]]; then
        POST_FILE="$ALTERNATE_POST"

    else
        echo "[*] Post-hardening Lynis report not found."
        echo "[*] Running Lynis assessment..."

        if ! command -v lynis >/dev/null 2>&1; then
            echo "Error: Lynis is not installed." >&2
            exit 1
        fi

        if [[ ! -x "$PARSER" ]]; then
            echo "Error: 2-lynis_parse.sh is missing or not executable." >&2
            exit 1
        fi

        lynis audit system --quick >/dev/null

        if [[ ! -r "$LYNIS_REPORT" ]]; then
            echo "Error: Lynis report not found: ${LYNIS_REPORT}" >&2
            exit 1
        fi

        "$PARSER" "$LYNIS_REPORT" > "$POST_FILE"

        echo "[*] Post-hardening report generated: $(basename "$POST_FILE")"
    fi
fi

# ---------------------------------------------------------------------------
# Validate JSON inputs
# ---------------------------------------------------------------------------

python3 - "$BEFORE_FILE" "$POST_FILE" "$OUTPUT_FILE" <<'PYTHON'
import json
import sys
from pathlib import Path

before_path = Path(sys.argv[1])
after_path = Path(sys.argv[2])
output_path = Path(sys.argv[3])


def load_report(path):
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(
            f"Unable to read valid JSON from {path}: {error}"
        )

    if "hardening_index" not in data:
        raise SystemExit(
            f"{path} does not contain hardening_index"
        )

    if "findings" not in data or not isinstance(data["findings"], list):
        raise SystemExit(
            f"{path} does not contain a valid findings array"
        )

    return data


before = load_report(before_path)
after = load_report(after_path)


def normalize_finding(finding):
    return {
        "severity": str(finding.get("severity", "")).strip(),
        "test_id": str(finding.get("test_id", "")).strip(),
        "message": str(finding.get("message", "")).strip(),
    }


def finding_key(finding):
    normalized = normalize_finding(finding)

    # Lynis messages occasionally vary slightly between releases.
    # Test ID + severity + message gives a deterministic comparison.
    return (
        normalized["severity"].lower(),
        normalized["test_id"].lower(),
        normalized["message"].lower(),
    )


before_findings = [
    normalize_finding(finding)
    for finding in before["findings"]
]

after_findings = [
    normalize_finding(finding)
    for finding in after["findings"]
]

before_map = {
    finding_key(finding): finding
    for finding in before_findings
}

after_map = {
    finding_key(finding): finding
    for finding in after_findings
}

before_keys = set(before_map)
after_keys = set(after_map)

resolved_keys = before_keys - after_keys
remaining_keys = before_keys & after_keys
new_keys = after_keys - before_keys

resolved_findings = sorted(
    [before_map[key] for key in resolved_keys],
    key=lambda item: (
        item["severity"],
        item["test_id"],
        item["message"],
    ),
)

remaining_findings = sorted(
    [after_map[key] for key in remaining_keys],
    key=lambda item: (
        item["severity"],
        item["test_id"],
        item["message"],
    ),
)

new_findings = sorted(
    [after_map[key] for key in new_keys],
    key=lambda item: (
        item["severity"],
        item["test_id"],
        item["message"],
    ),
)

before_score = int(before["hardening_index"])
after_score = int(after["hardening_index"])
delta = after_score - before_score

remaining_warnings = sum(
    finding["severity"].lower() == "warning"
    for finding in remaining_findings
)

remaining_suggestions = sum(
    finding["severity"].lower() == "suggestion"
    for finding in remaining_findings
)

remaining_manual = sum(
    finding["severity"].lower() == "manual_check"
    for finding in remaining_findings
)

new_warnings = sum(
    finding["severity"].lower() == "warning"
    for finding in new_findings
)

if not remaining_findings and not new_findings:
    residual_summary = (
        "No Lynis findings remain after hardening and no new findings "
        "were introduced."
    )

elif remaining_warnings > 0 or new_warnings > 0:
    residual_summary = (
        f"Residual risk remains because {remaining_warnings} warning(s) "
        f"remain and {new_warnings} new warning(s) were introduced. "
        f"{remaining_suggestions} suggestion(s) and "
        f"{remaining_manual} manual check(s) also remain and should be "
        "reviewed according to operational risk and business requirements."
    )

else:
    residual_summary = (
        f"No warning-level residual findings were identified, but "
        f"{remaining_suggestions} suggestion(s) and "
        f"{remaining_manual} manual check(s) remain. "
        f"{len(new_findings)} new non-warning finding(s) should also be "
        "reviewed."
    )

report = {
    "before_score": before_score,
    "after_score": after_score,
    "delta": delta,
    "resolved_findings": resolved_findings,
    "remaining_findings": remaining_findings,
    "new_findings": new_findings,
    "resolved_count": len(resolved_findings),
    "remaining_count": len(remaining_findings),
    "new_count": len(new_findings),
    "residual_risk_summary": residual_summary,
}

output_path.write_text(
    json.dumps(report, indent=2) + "\n",
    encoding="utf-8",
)
PYTHON

BEFORE_SCORE="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["before_score"])
' "$OUTPUT_FILE"
)"

AFTER_SCORE="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["after_score"])
' "$OUTPUT_FILE"
)"

DELTA="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["delta"])
' "$OUTPUT_FILE"
)"

RESOLVED="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["resolved_count"])
' "$OUTPUT_FILE"
)"

REMAINING="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["remaining_count"])
' "$OUTPUT_FILE"
)"

NEW="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["new_count"])
' "$OUTPUT_FILE"
)"

echo "Before: ${BEFORE_SCORE}"
echo "After: ${AFTER_SCORE}"

if (( DELTA >= 0 )); then
    echo "Delta: +${DELTA}"
else
    echo "Delta: ${DELTA}"
fi

echo "Findings resolved: ${RESOLVED}"
echo "Findings remaining: ${REMAINING}"
echo "New findings: ${NEW}"
echo "Report saved to: $(basename "$OUTPUT_FILE")"
