#!/bin/bash
# name: 3-patch_plan.sh
# purpose: Join vulnerability_inventory.json (Task 0) with
#          service_dependency_map.json (Task 1) into a prioritized,
#          ordered patch plan.
# Project: 2x03 - Patch Equation
# Task:    3 - The Patch Plan
#
# Note: this is a pure, deterministic join over two already-computed JSON
# files. It does NOT query live system state (no `ss`, no re-running T0/T1),
# specifically so that the same two input files always produce the same
# plan, as required by the task.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
VULN_FILE="${SCRIPT_DIR}/vulnerability_inventory.json"
DEPS_FILE="${SCRIPT_DIR}/service_dependency_map.json"
OUTPUT_FILE="${SCRIPT_DIR}/patch_plan.json"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq date awk; do need "$c"; done

# ---------------------------------------------------------------------------
# Weights (constants). Tune here only -- nowhere else in the script.
#   score = CVSS_WEIGHT      * max_cvss
#         + KEV_WEIGHT       * (1 if in_cisa_kev else 0)
#         + CRITICALITY_WEIGHT * max(criticality of affected services)
#         + EXPOSURE_WEIGHT  * exposure_rank
#
# criticality is mapped to a number: critical=4 high=3 medium=2 low=1 none=0
# exposure_rank is derived purely from the breadth of impact recorded in
# the two input files (see the jq program below) -- never from live
# network state, to keep the plan deterministic for a given pair of inputs.
# ---------------------------------------------------------------------------
CVSS_WEIGHT=0.6
KEV_WEIGHT=1.5
CRITICALITY_WEIGHT=0.3
EXPOSURE_WEIGHT=0.4

[[ -f "${VULN_FILE}" ]] || fail "vulnerability_inventory.json not found in ${SCRIPT_DIR} (run 0-vuln_inventory.sh first)"
[[ -f "${DEPS_FILE}" ]] || fail "service_dependency_map.json not found in ${SCRIPT_DIR} (run 1-service_deps.sh first)"

jq empty "${VULN_FILE}" >/dev/null 2>&1 || fail "vulnerability_inventory.json is invalid JSON"

# service_dependency_map.json is NDJSON (one object per line, per Task 1's
# spec) -- `jq -s` slurps every top-level document in the file into a
# single array so we can cross-reference it as normal data.
if ! DEPS_ARRAY="$(jq -s '.' "${DEPS_FILE}" 2>/dev/null)"; then
    fail "service_dependency_map.json contains invalid JSON (one or more lines failed to parse)"
fi

VULN_PACKAGES="$(jq -c '.packages // []' "${VULN_FILE}")"
GENERATED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ---------------------------------------------------------------------------
# The join + scoring + ranking, entirely in jq for determinism and to avoid
# floating point drift from shell arithmetic.
# ---------------------------------------------------------------------------
read -r -d '' JQ_PROGRAM << 'JQEOF'
def crit_num(c):
  if c == "critical" then 4
  elif c == "high" then 3
  elif c == "medium" then 2
  elif c == "low" then 1
  else 0 end;

# Kernel packages: linux-image-*, linux-modules-*, linux-generic,
# linux-virtual, linux-kvm and their -hwe / flavour variants. Deliberately
# excludes linux-headers-* and linux-libc-dev, which do not require a
# running-kernel reboot.
def is_kernel(pkg):
  pkg | test("^linux-(image|modules|generic|virtual|kvm)(-|$)");

def is_systemd(pkg):
  pkg == "systemd";

def round2(x):
  ((x * 100) | round) / 100;

($deps) as $deps_all
| ($vuln) as $vuln_all
| [
    $vuln_all[] as $v
    | ($v.package) as $pkg
    | (
        if is_kernel($pkg) then
          { affected: ["(kernel-wide)"], crit: 4, exposure: 3, reboot: true }
        elif is_systemd($pkg) then
          { affected: ["(system-wide)"],  crit: 4, exposure: 3, reboot: true }
        else
          ( [ $deps_all[]
              | select(.owning_package == $pkg
                        or ((.linked_packages // []) | index($pkg) != null)) ]
          ) as $matched
          | ($matched | map(.service) | unique | sort) as $svc
          | ($matched | map(crit_num(.criticality // "low"))
                       | if length > 0 then max else 0 end) as $maxcrit
          | ( $svc | length ) as $n
          | ( if $n == 0 then 0
              elif $n <= 2 then 1
              else 2 end ) as $exp
          | { affected: $svc, crit: $maxcrit, exposure: $exp, reboot: false }
        end
      ) as $impact
    | ( if ($v.in_cisa_kev // false) then 1 else 0 end ) as $kevnum
    | ( $cvss_w * ($v.max_cvss // 0)
        + $kev_w * $kevnum
        + $crit_w * $impact.crit
        + $exp_w * $impact.exposure
      ) as $raw_score
    | round2($raw_score) as $score
    | {
        package: $pkg,
        score: $score,
        bucket: (if $score >= 7 then "emergency"
                 elif $score >= 4 then "urgent"
                 else "scheduled" end),
        affected_services: $impact.affected,
        requires_restart: (($impact.affected | length) > 0),
        requires_reboot: $impact.reboot,
        rollback_target_version: $v.installed_version,
        candidate_version: $v.candidate_version,
        max_cvss: ($v.max_cvss // 0),
        in_cisa_kev: ($v.in_cisa_kev // false),
        cves: ($v.cves // [])
      }
  ]
  # Deterministic order: score descending, package name ascending as a
  # stable tie-breaker so identical inputs always yield identical order.
  | sort_by([-.score, .package])
  | to_entries
  | map({rank: (.key + 1)} + .value) as $plan
  | {
      generated_at: $gen_at,
      weights: {
        cvss_weight: $cvss_w,
        kev_weight: $kev_w,
        criticality_weight: $crit_w,
        exposure_weight: $exp_w
      },
      plan: $plan,
      summary: {
        total_patches: ($plan | length),
        emergency: ($plan | map(select(.bucket == "emergency")) | length),
        urgent: ($plan | map(select(.bucket == "urgent")) | length),
        scheduled: ($plan | map(select(.bucket == "scheduled")) | length),
        reboot_required: (($plan | map(select(.requires_reboot == true)) | length) > 0),
        kernel_update_present: ($plan | any(.affected_services[]? == "(kernel-wide)")),
        systemd_update_present: ($plan | any(.affected_services[]? == "(system-wide)"))
      }
    }
JQEOF

jq -n \
  --argjson vuln "${VULN_PACKAGES}" \
  --argjson deps "${DEPS_ARRAY}" \
  --argjson cvss_w "${CVSS_WEIGHT}" \
  --argjson kev_w "${KEV_WEIGHT}" \
  --argjson crit_w "${CRITICALITY_WEIGHT}" \
  --argjson exp_w "${EXPOSURE_WEIGHT}" \
  --arg gen_at "${GENERATED_AT}" \
  "${JQ_PROGRAM}" > "${OUTPUT_FILE}" || fail "jq transform failed"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "patch_plan.json is invalid JSON"

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------
EMERGENCY="$(jq -r '.summary.emergency' "${OUTPUT_FILE}")"
URGENT="$(jq -r '.summary.urgent' "${OUTPUT_FILE}")"
SCHEDULED="$(jq -r '.summary.scheduled' "${OUTPUT_FILE}")"
REBOOT_REQUIRED="$(jq -r '.summary.reboot_required' "${OUTPUT_FILE}")"
KERNEL_PRESENT="$(jq -r '.summary.kernel_update_present' "${OUTPUT_FILE}")"
SYSTEMD_PRESENT="$(jq -r '.summary.systemd_update_present' "${OUTPUT_FILE}")"

echo "Emergency: ${EMERGENCY}   Urgent: ${URGENT}   Scheduled: ${SCHEDULED}"

if [[ "${REBOOT_REQUIRED}" == "true" ]]; then
    reason=""
    [[ "${KERNEL_PRESENT}" == "true" ]] && reason="kernel update present"
    if [[ "${SYSTEMD_PRESENT}" == "true" ]]; then
        if [[ -n "${reason}" ]]; then
            reason="${reason}, systemd update present"
        else
            reason="systemd update present"
        fi
    fi
    echo "Reboot required by plan: yes (${reason})"
else
    echo "Reboot required by plan: no"
fi

echo "Report saved to: patch_plan.json"