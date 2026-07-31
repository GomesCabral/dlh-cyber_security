#!/bin/bash

# MedDefense Health Systems - Threat-Driven CIS Control Profile
#
# Generates a structured CIS hardening profile for:
# - billing-srv-01
# - web-srv-01
# - log-srv-01
#
# The profile prioritizes controls that address the MedDefense threat model:
# SSH lateral movement, weak authentication, unnecessary services, exposed
# database services, missing audit visibility and insufficient kernel security.
#
# This script is idempotent. Repeated executions generate the same control
# profile and atomically replace the previous JSON output.

set -euo pipefail

export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/cis_profile.json"
TEMP_FILE="$(mktemp "${SCRIPT_DIR}/cis_profile.json.tmp.XXXXXX")"

cleanup() {
    rm -f "$TEMP_FILE"
}

trap cleanup EXIT

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required to validate the CIS control profile." >&2
    exit 1
fi

cat > "$TEMP_FILE" <<'JSON'
{
  "profile": {
    "organization": "MedDefense Health Systems",
    "profile_name": "Threat-Driven Linux CIS Hardening Profile",
    "profile_version": "1.0",
    "target_assets": [
      "billing-srv-01",
      "web-srv-01",
      "log-srv-01"
    ],
    "control_selection_method": "Controls were selected according to the MedDefense threat model rather than through blind implementation of the complete CIS Benchmark."
  },
  "controls": [
    {
      "control_id": "MD-CIS-001",
      "title": "Disable SSH password authentication",
      "cis_section": "4 - Access, Authentication and Authorization",
      "severity": "critical",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "SSH credential attacks",
        "Crimson Tide Phase 3 lateral movement",
        "MedDefense Finding 009"
      ],
      "implementation_task": "2-ssh_hardening.sh",
      "verification_method": "Run sshd -T and confirm passwordauthentication no.",
      "justification": "Password-based SSH authentication exposes the servers to brute-force attacks, password spraying and credential reuse."
    },
    {
      "control_id": "MD-CIS-002",
      "title": "Prohibit direct SSH root login",
      "cis_section": "4 - Access, Authentication and Authorization",
      "severity": "critical",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "Direct privileged access",
        "Credential compromise",
        "SSH lateral movement"
      ],
      "implementation_task": "2-ssh_hardening.sh",
      "verification_method": "Run sshd -T and confirm permitrootlogin no.",
      "justification": "Disabling direct root login requires administrators to authenticate through an attributable account before using sudo."
    },
    {
      "control_id": "MD-CIS-003",
      "title": "Configure SSH session timeout and authentication limits",
      "cis_section": "4 - Access, Authentication and Authorization",
      "severity": "medium",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "Abandoned privileged sessions",
        "Brute-force authentication",
        "Session hijacking"
      ],
      "implementation_task": "2-ssh_hardening.sh",
      "verification_method": "Use sshd -T to verify clientaliveinterval, clientalivecountmax and maxauthtries.",
      "justification": "Idle session termination and authentication limits reduce the opportunity to abuse unattended sessions or repeatedly guess credentials."
    },
    {
      "control_id": "MD-CIS-004",
      "title": "Enable kernel network-stack protections",
      "cis_section": "3 - Network Configuration",
      "severity": "high",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "IP spoofing",
        "ICMP redirect abuse",
        "Source-routed traffic",
        "SYN flood attacks"
      ],
      "implementation_task": "3-kernel_network_hardening.sh",
      "verification_method": "Query the required net.ipv4 and net.ipv6 parameters using sysctl.",
      "justification": "Secure sysctl network settings reduce exposure to spoofing, malicious redirects, source routing and denial-of-service activity."
    },
    {
      "control_id": "MD-CIS-005",
      "title": "Enable kernel memory protections and restrict core dumps",
      "cis_section": "1 - Initial Setup",
      "severity": "high",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "Memory exploitation",
        "Credential leakage through core dumps",
        "Local privilege escalation"
      ],
      "implementation_task": "4-kernel_memory_hardening.sh",
      "verification_method": "Verify kernel.randomize_va_space, fs.suid_dumpable and core dump limits.",
      "justification": "ASLR and core dump restrictions make memory exploitation more difficult and reduce the risk of sensitive information being written to disk."
    },
    {
      "control_id": "MD-CIS-006",
      "title": "Enforce PAM login attempt limiting",
      "cis_section": "4 - Access, Authentication and Authorization",
      "severity": "critical",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "Password brute force",
        "Credential stuffing",
        "Compromised local accounts"
      ],
      "implementation_task": "5-pam_lockout.sh",
      "verification_method": "Inspect PAM configuration and test repeated failed authentication attempts with a non-production account.",
      "justification": "Account lockout or delay controls reduce the number of password guesses available to an attacker."
    },
    {
      "control_id": "MD-CIS-007",
      "title": "Enforce PAM password quality requirements",
      "cis_section": "4 - Access, Authentication and Authorization",
      "severity": "medium",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "Weak passwords",
        "Password guessing",
        "Credential reuse"
      ],
      "implementation_task": "6-pam_password_quality.sh",
      "verification_method": "Inspect pam_pwquality configuration and attempt to set a password that violates the defined policy.",
      "justification": "Password length and quality requirements reduce the likelihood that local credentials can be guessed or cracked."
    },
    {
      "control_id": "MD-CIS-008",
      "title": "Disable unnecessary services",
      "cis_section": "2 - Services",
      "severity": "high",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "Exposed attack surface",
        "Misconfigured reachable services",
        "Crimson Tide initial access"
      ],
      "implementation_task": "7-service_minimization.sh",
      "verification_method": "Compare systemctl running-service output and listening sockets against the approved service allowlist.",
      "justification": "Every unnecessary daemon creates additional code, network exposure and configuration that an attacker may exploit."
    },
    {
      "control_id": "MD-CIS-009",
      "title": "Restrict database network exposure",
      "cis_section": "2 - Services",
      "severity": "critical",
      "asset_scope": [
        "billing-srv-01"
      ],
      "threat_mapping": [
        "Exposed MySQL service",
        "Unauthorized database access",
        "Patient and billing data theft"
      ],
      "implementation_task": "7-service_minimization.sh",
      "verification_method": "Use ss -lntup and the database bind-address configuration to confirm that MySQL is not publicly exposed.",
      "justification": "The billing database contains sensitive financial and patient information and must only accept connections from explicitly authorized systems."
    },
    {
      "control_id": "MD-CIS-010",
      "title": "Apply a default-deny host firewall policy",
      "cis_section": "3 - Network Configuration",
      "severity": "critical",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "Unauthorized inbound access",
        "Exposed administrative services",
        "Lateral movement"
      ],
      "implementation_task": "8-firewall_hardening.sh",
      "verification_method": "Inspect firewall status and confirm that only role-approved ports are permitted.",
      "justification": "A default-deny firewall restricts connectivity to explicitly approved services and limits both external exposure and lateral movement."
    },
    {
      "control_id": "MD-CIS-011",
      "title": "Restrict access to administrative and database ports",
      "cis_section": "3 - Network Configuration",
      "severity": "high",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "SSH lateral movement",
        "Database scanning",
        "Unauthorized management access"
      ],
      "implementation_task": "8-firewall_hardening.sh",
      "verification_method": "Review firewall rules and test connectivity from authorized and unauthorized network locations.",
      "justification": "Source-based firewall restrictions ensure that SSH, database and logging services are accessible only from trusted systems."
    },
    {
      "control_id": "MD-CIS-012",
      "title": "Audit and minimize SUID and SGID binaries",
      "cis_section": "1 - Initial Setup",
      "severity": "high",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "Local privilege escalation",
        "Abuse of privileged binaries",
        "Post-compromise persistence"
      ],
      "implementation_task": "9-filesystem_permissions.sh",
      "verification_method": "Use find with -perm -4000 and -perm -2000, then compare results with the approved privileged-binary allowlist.",
      "justification": "Unnecessary SUID and SGID permissions can allow a compromised low-privilege account to execute code with elevated privileges."
    },
    {
      "control_id": "MD-CIS-013",
      "title": "Remediate unsafe world-writable file permissions",
      "cis_section": "1 - Initial Setup",
      "severity": "high",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "Unauthorized file modification",
        "Malicious persistence",
        "Application tampering"
      ],
      "implementation_task": "9-filesystem_permissions.sh",
      "verification_method": "Search for world-writable files while excluding virtual filesystems and compare the result with approved exceptions.",
      "justification": "World-writable files may permit unauthorized users to alter scripts, application content or security-relevant configuration."
    },
    {
      "control_id": "MD-CIS-014",
      "title": "Enable audit logging for privileged and security-relevant activity",
      "cis_section": "5 - Logging and Auditing",
      "severity": "high",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "Missing audit visibility",
        "Privilege escalation",
        "Evidence destruction",
        "Crimson Tide post-compromise activity"
      ],
      "implementation_task": "10-auditd_hardening.sh",
      "verification_method": "Use auditctl -l and ausearch to confirm that privilege use, identity changes and security configuration modifications are recorded.",
      "justification": "Security-relevant audit events are required to detect attacker activity, investigate incidents and preserve evidence."
    },
    {
      "control_id": "MD-CIS-015",
      "title": "Configure secure log retention and rotation",
      "cis_section": "5 - Logging and Auditing",
      "severity": "medium",
      "asset_scope": [
        "billing-srv-01",
        "web-srv-01",
        "log-srv-01"
      ],
      "threat_mapping": [
        "Log deletion",
        "Disk exhaustion",
        "Insufficient incident evidence"
      ],
      "implementation_task": "11-log_retention.sh",
      "verification_method": "Inspect journald, rsyslog and logrotate configuration and verify that retained logs remain available for the approved period.",
      "justification": "Defined retention and rotation preserve forensic evidence while preventing uncontrolled log growth from exhausting disk capacity."
    }
  ]
}
JSON

# Validate the generated profile before replacing the existing output.
#
# This protects later hardening tasks from consuming an incomplete or malformed
# profile and verifies the exact project requirements.
VALIDATION_RESULT="$(
    python3 - "$TEMP_FILE" <<'PYTHON'
import json
import sys
from pathlib import Path

profile_path = Path(sys.argv[1])

required_fields = {
    "control_id",
    "title",
    "cis_section",
    "severity",
    "asset_scope",
    "threat_mapping",
    "implementation_task",
    "verification_method",
    "justification",
}

allowed_severities = {"critical", "high", "medium"}

try:
    with profile_path.open("r", encoding="utf-8") as profile_file:
        data = json.load(profile_file)
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"Invalid JSON profile: {error}")

controls = data.get("controls")

if not isinstance(controls, list):
    raise SystemExit("The JSON profile must contain a controls array.")

if len(controls) != 15:
    raise SystemExit(
        f"Expected exactly 15 controls, but found {len(controls)}."
    )

control_ids = []

for position, control in enumerate(controls, start=1):
    if not isinstance(control, dict):
        raise SystemExit(
            f"Control at position {position} is not a JSON object."
        )

    missing_fields = required_fields - set(control)

    if missing_fields:
        missing = ", ".join(sorted(missing_fields))
        raise SystemExit(
            f"Control {position} is missing required fields: {missing}"
        )

    empty_fields = [
        field
        for field in required_fields
        if control[field] in ("", None, [], {})
    ]

    if empty_fields:
        empty = ", ".join(sorted(empty_fields))
        raise SystemExit(
            f"Control {control['control_id']} has empty fields: {empty}"
        )

    if control["severity"] not in allowed_severities:
        raise SystemExit(
            f"Invalid severity in {control['control_id']}: "
            f"{control['severity']}"
        )

    control_ids.append(control["control_id"])

if len(control_ids) != len(set(control_ids)):
    raise SystemExit("Duplicate control_id values were detected.")

severity_counts = {
    severity: sum(
        control["severity"] == severity
        for control in controls
    )
    for severity in ("critical", "high", "medium")
}

expected_severity_counts = {
    "critical": 5,
    "high": 7,
    "medium": 3,
}

if severity_counts != expected_severity_counts:
    raise SystemExit(
        "Incorrect severity distribution: "
        f"{severity_counts}; expected {expected_severity_counts}."
    )

cis_sections = {
    control["cis_section"]
    for control in controls
}

implementation_tasks = {
    control["implementation_task"]
    for control in controls
}

if len(cis_sections) != 5:
    raise SystemExit(
        f"Expected 5 CIS sections, but found {len(cis_sections)}."
    )

if len(implementation_tasks) != 10:
    raise SystemExit(
        "Expected 10 mapped implementation tasks, "
        f"but found {len(implementation_tasks)}."
    )

print(
    "|".join(
        [
            str(len(controls)),
            str(severity_counts["critical"]),
            str(severity_counts["high"]),
            str(severity_counts["medium"]),
            str(len(cis_sections)),
            str(len(implementation_tasks)),
        ]
    )
)
PYTHON
)"

IFS='|' read -r \
    CONTROL_COUNT \
    CRITICAL_COUNT \
    HIGH_COUNT \
    MEDIUM_COUNT \
    CIS_SECTION_COUNT \
    IMPLEMENTATION_TASK_COUNT \
    <<< "$VALIDATION_RESULT"

# Atomically replace the output only after successful validation.
mv "$TEMP_FILE" "$OUTPUT_FILE"

# The temporary file was moved successfully, so no cleanup is required.
trap - EXIT

echo "Controls selected: ${CONTROL_COUNT}"
echo "Critical: ${CRITICAL_COUNT}"
echo "High: ${HIGH_COUNT}"
echo "Medium: ${MEDIUM_COUNT}"
echo "CIS sections covered: ${CIS_SECTION_COUNT}"
echo "Mapped implementation tasks: ${IMPLEMENTATION_TASK_COUNT}"
echo "Report saved to: $(basename "$OUTPUT_FILE")"
