#!/bin/bash

# MedDefense Health Systems - Compliance Evidence Bundle
#
# Produces a machine-readable auditor-ready compliance artifact from the
# structured evidence generated throughout the Linux hardening project.
#
# Inputs:
# - cis_profile.json
# - gap_analysis.json
# - remediation_queue.json
# - audit_validation.json
# - validation_results.json
# - hardening_improvement.json
#
# Output:
# - compliance_report.json
#
# This script is read-only with respect to the hardened system. It consumes
# existing evidence and produces a new compliance artifact.

set -euo pipefail

export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CIS_PROFILE="${SCRIPT_DIR}/cis_profile.json"
GAP_ANALYSIS="${SCRIPT_DIR}/gap_analysis.json"
REMEDIATION_QUEUE="${SCRIPT_DIR}/remediation_queue.json"
AUDIT_VALIDATION="${SCRIPT_DIR}/audit_validation.json"
VALIDATION_RESULTS="${SCRIPT_DIR}/validation_results.json"
IMPROVEMENT_REPORT="${SCRIPT_DIR}/hardening_improvement.json"

OUTPUT_FILE="${SCRIPT_DIR}/compliance_report.json"

EVIDENCE_FILES=(
    "$CIS_PROFILE"
    "$GAP_ANALYSIS"
    "$REMEDIATION_QUEUE"
    "$AUDIT_VALIDATION"
    "$VALIDATION_RESULTS"
    "$IMPROVEMENT_REPORT"
)

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required." >&2
    exit 1
fi

echo "[*] Loading compliance evidence..."

MISSING=0

for file in "${EVIDENCE_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "Error: missing evidence file: $(basename "$file")" >&2
        MISSING=$((MISSING + 1))
    fi
done

if (( MISSING > 0 )); then
    echo "Compliance bundle not generated." >&2
    exit 1
fi

# Validate all evidence before processing it.
for file in "${EVIDENCE_FILES[@]}"; do
    if ! python3 -m json.tool "$file" >/dev/null 2>&1; then
        echo "Error: invalid JSON evidence: $(basename "$file")" >&2
        exit 1
    fi
done

HOSTNAME_VALUE="$(hostname 2>/dev/null || echo unknown)"
KERNEL_VALUE="$(uname -r 2>/dev/null || echo unknown)"
ARCH_VALUE="$(uname -m 2>/dev/null || echo unknown)"

if [[ -r /etc/os-release ]]; then
    OS_VALUE="$(
        . /etc/os-release
        printf '%s' "${PRETTY_NAME:-unknown}"
    )"
else
    OS_VALUE="unknown"
fi

HARDENING_DATE="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

export HOSTNAME_VALUE
export KERNEL_VALUE
export ARCH_VALUE
export OS_VALUE
export HARDENING_DATE

python3 - \
    "$CIS_PROFILE" \
    "$GAP_ANALYSIS" \
    "$REMEDIATION_QUEUE" \
    "$AUDIT_VALIDATION" \
    "$VALIDATION_RESULTS" \
    "$IMPROVEMENT_REPORT" \
    "$OUTPUT_FILE" <<'PYTHON'
import json
import os
import sys
from pathlib import Path


(
    cis_path,
    gap_path,
    queue_path,
    audit_path,
    validation_path,
    improvement_path,
    output_path,
) = map(Path, sys.argv[1:])


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


cis = load_json(cis_path)
gap = load_json(gap_path)
queue = load_json(queue_path)
audit_validation = load_json(audit_path)
validation = load_json(validation_path)
improvement = load_json(improvement_path)

controls = cis.get("controls", [])
gap_controls = gap.get("controls", [])

if len(controls) != 15:
    raise SystemExit(
        f"Expected 15 selected controls, found {len(controls)}."
    )


# ----------------------------------------------------------------------
# Index evidence by control ID
# ----------------------------------------------------------------------

gap_by_id = {
    control.get("control_id"): control
    for control in gap_controls
    if control.get("control_id")
}


# ----------------------------------------------------------------------
# Selected controls
# ----------------------------------------------------------------------

selected_controls = []

for control in controls:
    selected_controls.append({
        "control_id": control["control_id"],
        "title": control["title"],
        "severity": control["severity"],
        "asset_scope": control["asset_scope"],
        "implementation_task": control["implementation_task"],
        "verification_method": control["verification_method"],
    })


# ----------------------------------------------------------------------
# Remediated controls
#
# A control is considered remediated when it was identified as requiring
# remediation and has a mapped implementation script in the evidence queue.
# This is evidence of planned/executed remediation workflow, not a substitute
# for validation.
# ----------------------------------------------------------------------

queued_control_ids = set()

for item in queue.get("remediation_queue", []):
    control_id = item.get("control_id")

    if control_id:
        queued_control_ids.add(control_id)


remediated_controls = []

for control in controls:
    if control["control_id"] in queued_control_ids:
        remediated_controls.append({
            "control_id": control["control_id"],
            "title": control["title"],
            "remediation_script": control["implementation_task"],
        })


# ----------------------------------------------------------------------
# Verification evidence
#
# Task 15 currently validates many low-level checks rather than emitting one
# control ID per result. We therefore include the independent validation
# evidence and use the gap state to determine control-level compliance.
# ----------------------------------------------------------------------

verified_controls = []
unresolved_controls = []
deviations = []


def deviation_details(control, gap_control):
    control_id = control["control_id"]

    reason = (
        "Control could not be fully validated or remediated in the current "
        "laboratory environment."
    )

    risk = (
        "Residual exposure associated with this control remains until the "
        "production Ubuntu 22.04 implementation is completed and validated."
    )

    compensating = (
        "Audit-only validation, continuous monitoring, restricted laboratory "
        "access and independent post-hardening validation."
    )

    # More specific deviations for the known non-target lab environment.
    implementation = control.get("implementation_task", "")

    if implementation in {
        "6-filesystem_hardening.sh",
        "7-service_minimization.sh",
        "8-pam_hardening.sh",
        "9-apparmor_config.sh",
    }:
        reason = (
            "The current laboratory host runs Kali Linux rather than the "
            "MedDefense Ubuntu 22.04 target. Automatic remediation was "
            "intentionally withheld to avoid disrupting legitimate "
            "platform-specific services or authentication controls."
        )

        risk = (
            "The equivalent production control remains unproven on the "
            "current non-target operating system."
        )

        compensating = (
            "The control was assessed in AUDIT_ONLY mode and the expected "
            "Ubuntu 22.04 configuration is documented for deployment on the "
            "target server."
        )

    return {
        "control_id": control_id,
        "reason": reason,
        "risk_accepted": risk,
        "compensating_control": compensating,
        "owner": "James Chen - Infrastructure Security",
    }


for control in controls:
    control_id = control["control_id"]
    gap_control = gap_by_id.get(control_id, {})
    status = gap_control.get("status", "not_assessed")

    control_record = {
        "control_id": control_id,
        "title": control["title"],
        "status": status,
    }

    if status == "compliant":
        verified_controls.append(control_record)

    elif status in {"non_compliant", "partially_compliant", "not_assessed"}:
        unresolved_controls.append(control_record)

        if status in {"partially_compliant", "not_assessed"}:
            deviations.append(
                deviation_details(control, gap_control)
            )


# ----------------------------------------------------------------------
# Task 15 validation evidence
# ----------------------------------------------------------------------

validation_summary = {
    "checks_executed": validation.get("checks_executed", 0),
    "pass_count": validation.get("pass_count", 0),
    "fail_count": validation.get("fail_count", 0),
    "overall_status": validation.get(
        "overall_status",
        "UNKNOWN"
    ),
}


# ----------------------------------------------------------------------
# Audit coverage evidence
# ----------------------------------------------------------------------

audit_summary = {
    "tests_executed": audit_validation.get("tests_executed", 0),
    "captured": audit_validation.get("captured", 0),
    "missed": audit_validation.get("missed", 0),
    "all_tests_passed": audit_validation.get(
        "all_tests_passed",
        False
    ),
}


# ----------------------------------------------------------------------
# Lynis residual risk
# ----------------------------------------------------------------------

remaining_findings = improvement.get(
    "remaining_findings",
    []
)

residual_count = improvement.get(
    "remaining_count",
    len(remaining_findings)
)


# ----------------------------------------------------------------------
# Compliance percentage
#
# Control-level compliance is based on controls whose final gap state is
# compliant. Partially compliant and not assessed controls are not counted
# as fully compliant.
# ----------------------------------------------------------------------

selected_count = len(controls)
verified_count = len(verified_controls)

compliance_percentage = (
    round((verified_count / selected_count) * 100, 1)
    if selected_count
    else 0.0
)


# ----------------------------------------------------------------------
# Evidence manifest
# ----------------------------------------------------------------------

evidence_files = [
    {
        "file": cis_path.name,
        "purpose": "Selected threat-driven CIS control baseline",
    },
    {
        "file": gap_path.name,
        "purpose": "Control compliance gap analysis",
    },
    {
        "file": queue_path.name,
        "purpose": "Risk-prioritized remediation evidence",
    },
    {
        "file": audit_path.name,
        "purpose": "Audit telemetry validation evidence",
    },
    {
        "file": validation_path.name,
        "purpose": "Independent post-hardening validation",
    },
    {
        "file": improvement_path.name,
        "purpose": "Pre/post Lynis improvement and residual findings",
    },
]


report = {
    "report_metadata": {
        "organization": "MedDefense Health Systems",
        "report_type": "Machine-Readable Compliance Evidence Bundle",
        "hardening_date_utc": os.environ["HARDENING_DATE"],
    },
    "system_identity": {
        "hostname": os.environ["HOSTNAME_VALUE"],
        "operating_system": os.environ["OS_VALUE"],
        "kernel": os.environ["KERNEL_VALUE"],
        "architecture": os.environ["ARCH_VALUE"],
    },
    "summary": {
        "evidence_files_loaded": len(evidence_files),
        "controls_selected": selected_count,
        "controls_remediated": len(remediated_controls),
        "controls_verified": verified_count,
        "unresolved_controls": len(unresolved_controls),
        "deviations_documented": len(deviations),
        "overall_compliance_percentage": compliance_percentage,
        "residual_lynis_findings": residual_count,
    },
    "selected_controls": selected_controls,
    "remediated_controls": remediated_controls,
    "verified_controls": verified_controls,
    "unresolved_controls": unresolved_controls,
    "deviations": deviations,
    "compensating_controls": [
        {
            "control_id": deviation["control_id"],
            "compensating_control": deviation["compensating_control"],
        }
        for deviation in deviations
    ],
    "validation_summary": validation_summary,
    "audit_telemetry_validation": audit_summary,
    "lynis_improvement": {
        "before_score": improvement.get("before_score"),
        "after_score": improvement.get("after_score"),
        "delta": improvement.get("delta"),
        "resolved_count": improvement.get("resolved_count", 0),
        "remaining_count": residual_count,
        "new_count": improvement.get("new_count", 0),
        "residual_risk_summary": improvement.get(
            "residual_risk_summary",
            ""
        ),
    },
    "residual_lynis_findings": remaining_findings,
    "evidence_files_used": evidence_files,
}

output_path.write_text(
    json.dumps(report, indent=2) + "\n",
    encoding="utf-8",
)
PYTHON

EVIDENCE_COUNT="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["summary"]["evidence_files_loaded"])
' "$OUTPUT_FILE"
)"

SELECTED_COUNT="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["summary"]["controls_selected"])
' "$OUTPUT_FILE"
)"

REMEDIATED_COUNT="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["summary"]["controls_remediated"])
' "$OUTPUT_FILE"
)"

VERIFIED_COUNT="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["summary"]["controls_verified"])
' "$OUTPUT_FILE"
)"

DEVIATION_COUNT="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["summary"]["deviations_documented"])
' "$OUTPUT_FILE"
)"

COMPLIANCE="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["summary"]["overall_compliance_percentage"])
' "$OUTPUT_FILE"
)"

RESIDUAL="$(
    python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["summary"]["residual_lynis_findings"])
' "$OUTPUT_FILE"
)"

echo "Evidence files loaded: ${EVIDENCE_COUNT}"
echo "Controls selected: ${SELECTED_COUNT}"
echo "Controls remediated: ${REMEDIATED_COUNT}"
echo "Controls verified: ${VERIFIED_COUNT}"
echo "Deviations documented: ${DEVIATION_COUNT}"
echo "Overall compliance: ${COMPLIANCE}%"
echo "Residual findings: ${RESIDUAL}"
echo "Report saved to: $(basename "$OUTPUT_FILE")"
