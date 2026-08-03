#!/bin/bash

# MedDefense Health Systems - Evidence-Based Remediation Queue
#
# Reads the threat-driven CIS profile and Lynis findings, determines the
# compliance status of each control, then creates:
#
# - gap_analysis.json
# - remediation_queue.json
#
# The remediation queue is sorted by risk priority and maps each identified
# gap to the later hardening script responsible for remediation.

set -euo pipefail

export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CIS_PROFILE="${SCRIPT_DIR}/cis_profile.json"
LYNIS_FINDINGS="${SCRIPT_DIR}/lynis_findings.json"

GAP_OUTPUT="${SCRIPT_DIR}/gap_analysis.json"
QUEUE_OUTPUT="${SCRIPT_DIR}/remediation_queue.json"

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required." >&2
    exit 1
fi

if [[ ! -f "$CIS_PROFILE" ]]; then
    echo "Error: cis_profile.json not found." >&2
    exit 1
fi

if [[ ! -f "$LYNIS_FINDINGS" ]]; then
    echo "Error: lynis_findings.json not found." >&2
    exit 1
fi

jq empty "$CIS_PROFILE"
jq empty "$LYNIS_FINDINGS"

TEMP_GAP="$(mktemp)"
TEMP_QUEUE="$(mktemp)"

cleanup() {
    rm -f "$TEMP_GAP" "$TEMP_QUEUE"
}

trap cleanup EXIT

python3 - \
    "$CIS_PROFILE" \
    "$LYNIS_FINDINGS" \
    "$TEMP_GAP" \
    "$TEMP_QUEUE" <<'PYTHON'

import json
import sys
from pathlib import Path


cis_path = Path(sys.argv[1])
lynis_path = Path(sys.argv[2])
gap_path = Path(sys.argv[3])
queue_path = Path(sys.argv[4])


with cis_path.open("r", encoding="utf-8") as f:
    cis_data = json.load(f)

with lynis_path.open("r", encoding="utf-8") as f:
    lynis_data = json.load(f)


controls = cis_data.get("controls", [])
findings = lynis_data.get("findings", [])


# ----------------------------------------------------------------------
# Mapping logic
#
# Each CIS control is associated with words that may appear in Lynis
# findings. This is not blind compliance matching; it is a threat-driven
# evidence correlation layer for the MedDefense environment.
# ----------------------------------------------------------------------

CONTROL_RULES = {
    "MD-CIS-001": {
        "keywords": [
            "ssh",
            "password authentication",
            "passwordauthentication",
        ],
        "default_status": "non_compliant",
        "operational_risk": (
            "Attackers may brute-force or reuse credentials to obtain "
            "remote access and perform SSH lateral movement."
        ),
    },
    "MD-CIS-002": {
        "keywords": [
            "root login",
            "permitrootlogin",
            "ssh",
        ],
        "default_status": "non_compliant",
        "operational_risk": (
            "Direct root access increases the impact of compromised "
            "credentials and reduces administrative accountability."
        ),
    },
    "MD-CIS-003": {
        "keywords": [
            "ssh",
            "idle",
            "timeout",
            "maxauthtries",
        ],
        "default_status": "partially_compliant",
        "operational_risk": (
            "Long-lived SSH sessions or excessive authentication attempts "
            "increase exposure to session abuse and brute-force attacks."
        ),
    },
    "MD-CIS-004": {
        "keywords": [
            "sysctl",
            "tcp syncookies",
            "icmp",
            "redirect",
            "source route",
            "rp_filter",
        ],
        "default_status": "non_compliant",
        "operational_risk": (
            "Weak kernel network settings can expose the system to spoofing, "
            "malicious redirects, source-routing abuse and denial-of-service."
        ),
    },
    "MD-CIS-005": {
        "keywords": [
            "aslr",
            "core dump",
            "suid_dumpable",
            "randomize_va_space",
        ],
        "default_status": "partially_compliant",
        "operational_risk": (
            "Insufficient memory protections can assist exploitation and may "
            "allow credentials or sensitive process data to leak through "
            "core dumps."
        ),
    },
    "MD-CIS-006": {
        "keywords": [
            "pam",
            "lockout",
            "faillock",
            "authentication",
        ],
        "default_status": "non_compliant",
        "operational_risk": (
            "Without failed-login controls, attackers can repeatedly guess "
            "local credentials."
        ),
    },
    "MD-CIS-007": {
        "keywords": [
            "password quality",
            "pam_pwquality",
            "password policy",
            "pwquality",
        ],
        "default_status": "non_compliant",
        "operational_risk": (
            "Weak password requirements increase the likelihood of password "
            "guessing, credential reuse and offline cracking."
        ),
    },
    "MD-CIS-008": {
        "keywords": [
            "service",
            "services",
            "daemon",
            "unnecessary",
        ],
        "default_status": "non_compliant",
        "operational_risk": (
            "Unnecessary services increase the attack surface and may expose "
            "vulnerable or misconfigured network daemons."
        ),
    },
    "MD-CIS-009": {
        "keywords": [
            "mysql",
            "database",
            "3306",
        ],
        "default_status": "not_assessed",
        "operational_risk": (
            "An exposed database service could allow unauthorized access to "
            "billing and patient information."
        ),
    },
    "MD-CIS-010": {
        "keywords": [
            "firewall",
            "ufw",
            "iptables",
            "nftables",
        ],
        "default_status": "non_compliant",
        "operational_risk": (
            "Without a default-deny firewall, unauthorized systems may reach "
            "administrative or application services."
        ),
    },
    "MD-CIS-011": {
        "keywords": [
            "firewall",
            "port",
            "ssh",
            "database",
        ],
        "default_status": "non_compliant",
        "operational_risk": (
            "Administrative and database ports may be reachable from networks "
            "that do not require access."
        ),
    },
    "MD-CIS-012": {
        "keywords": [
            "suid",
            "sgid",
            "privileged binary",
        ],
        "default_status": "non_compliant",
        "operational_risk": (
            "Unnecessary SUID or SGID binaries may be abused for local "
            "privilege escalation."
        ),
    },
    "MD-CIS-013": {
        "keywords": [
            "world writable",
            "world-writable",
            "permissions",
        ],
        "default_status": "non_compliant",
        "operational_risk": (
            "Unsafe file permissions may allow unauthorized modification, "
            "persistence or application tampering."
        ),
    },
    "MD-CIS-014": {
        "keywords": [
            "auditd",
            "audit",
            "logging",
        ],
        "default_status": "non_compliant",
        "operational_risk": (
            "Missing audit visibility may prevent detection of privilege "
            "escalation and obstruct incident investigation."
        ),
    },
    "MD-CIS-015": {
        "keywords": [
            "logrotate",
            "log rotation",
            "retention",
            "rsyslog",
            "journald",
        ],
        "default_status": "compliant",
        "operational_risk": (
            "Insufficient log retention can destroy forensic evidence or "
            "allow excessive log growth to exhaust disk space."
        ),
    },
}


SEVERITY_BASE = {
    "critical": 90,
    "high": 75,
    "medium": 55,
}

STATUS_ADJUSTMENT = {
    "non_compliant": 5,
    "partially_compliant": 0,
    "not_assessed": -10,
    "compliant": -50,
}


def normalize(value):
    return str(value).lower().strip()


def find_matches(keywords):
    matches = []

    for finding in findings:
        test_id = normalize(finding.get("test_id", ""))
        message = normalize(finding.get("message", ""))

        searchable = f"{test_id} {message}"

        if any(keyword.lower() in searchable for keyword in keywords):
            matches.append(finding)

    return matches


gap_results = []
queue = []


for control in controls:
    control_id = control["control_id"]
    rule = CONTROL_RULES.get(control_id, {})

    keywords = rule.get("keywords", [])
    matches = find_matches(keywords)

    status = rule.get("default_status", "not_assessed")

    # If supporting Lynis evidence exists, promote assumed gaps into evidence-
    # backed non-compliance unless the control was defined as partially compliant.
    if matches:
        if status == "partially_compliant":
            status = "partially_compliant"
        elif status == "compliant":
            status = "partially_compliant"
        else:
            status = "non_compliant"

    evidence = []

    for finding in matches:
        evidence.append(
            {
                "test_id": finding.get("test_id", "LYNIS"),
                "severity": finding.get("severity", "unknown"),
                "message": finding.get("message", ""),
            }
        )

    gap_entry = {
        "control_id": control_id,
        "title": control["title"],
        "status": status,
        "severity": control["severity"],
        "asset_scope": control["asset_scope"],
        "matching_lynis_findings": evidence,
        "implementation_task": control["implementation_task"],
        "verification_method": control["verification_method"],
        "justification": control["justification"],
    }

    gap_results.append(gap_entry)

    if status in ("non_compliant", "partially_compliant"):
        base = SEVERITY_BASE.get(control["severity"], 50)
        score = base + STATUS_ADJUSTMENT.get(status, 0)

        if matches:
            score += min(len(matches) * 2, 5)

        score = max(1, min(score, 100))

        for asset in control["asset_scope"]:
            queue.append(
                {
                    "control_id": control_id,
                    "title": control["title"],
                    "status": status,
                    "affected_asset": asset,
                    "severity": control["severity"],
                    "priority_score": score,
                    "matching_lynis_findings": evidence,
                    "remediation_script": control["implementation_task"],
                    "operational_risk_if_left_unresolved": rule.get(
                        "operational_risk",
                        "Security exposure remains unresolved."
                    ),
                    "expected_validation_check": control[
                        "verification_method"
                    ],
                }
            )


queue.sort(
    key=lambda item: (
        -item["priority_score"],
        item["control_id"],
        item["affected_asset"],
    )
)


summary = {
    "controls_assessed": len(gap_results),
    "compliant": sum(
        1 for item in gap_results if item["status"] == "compliant"
    ),
    "non_compliant": sum(
        1 for item in gap_results if item["status"] == "non_compliant"
    ),
    "partially_compliant": sum(
        1
        for item in gap_results
        if item["status"] == "partially_compliant"
    ),
    "not_assessed": sum(
        1 for item in gap_results if item["status"] == "not_assessed"
    ),
}


gap_output = {
    "summary": summary,
    "controls": gap_results,
}


queue_output = {
    "queue_summary": {
        "remediation_actions_queued": len(
            [
                item
                for item in gap_results
                if item["status"]
                in ("non_compliant", "partially_compliant")
            ]
        )
    },
    "remediation_queue": queue,
}


with gap_path.open("w", encoding="utf-8") as f:
    json.dump(gap_output, f, indent=2)
    f.write("\n")


with queue_path.open("w", encoding="utf-8") as f:
    json.dump(queue_output, f, indent=2)
    f.write("\n")
PYTHON

mv "$TEMP_GAP" "$GAP_OUTPUT"
mv "$TEMP_QUEUE" "$QUEUE_OUTPUT"

trap - EXIT

CONTROLS_ASSESSED="$(jq '.summary.controls_assessed' "$GAP_OUTPUT")"
COMPLIANT="$(jq '.summary.compliant' "$GAP_OUTPUT")"
NON_COMPLIANT="$(jq '.summary.non_compliant' "$GAP_OUTPUT")"
PARTIALLY_COMPLIANT="$(jq '.summary.partially_compliant' "$GAP_OUTPUT")"
NOT_ASSESSED="$(jq '.summary.not_assessed' "$GAP_OUTPUT")"

REMEDIATION_ACTIONS="$(
    jq '.queue_summary.remediation_actions_queued' "$QUEUE_OUTPUT"
)"

echo "Controls assessed: ${CONTROLS_ASSESSED}"
echo "Compliant: ${COMPLIANT}"
echo "Non-compliant: ${NON_COMPLIANT}"
echo "Partially compliant: ${PARTIALLY_COMPLIANT}"
echo "Not assessed: ${NOT_ASSESSED}"
echo "Remediation actions queued: ${REMEDIATION_ACTIONS}"
echo "Report saved to: $(basename "$GAP_OUTPUT")"
echo "Queue saved to: $(basename "$QUEUE_OUTPUT")"
