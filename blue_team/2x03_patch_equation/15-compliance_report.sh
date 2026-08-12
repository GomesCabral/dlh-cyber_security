#!/bin/bash
# name: 15-compliance_report.sh
# purpose: Generate the single machine-readable compliance artifact that
#          answers "where are we, right now, with respect to every known
#          CVE on this host" -- resolved, open, deferred with a recorded
#          reason (held package), or deferred pending the next
#          maintenance window.
# Project: 2x03 - Patch Equation
# Task:    15 - The Patch Compliance Artifact
#
# Read-only: aggregates Tasks 0, 10, 12, and 13's artifacts. Changes
# nothing on the system.
#
# --- Documented assumptions (this task's schema is not fully specified
#     by prior tasks, so these choices are made explicit rather than
#     silently guessed) ---
#
# ./history/ -- rotated copies of vulnerability_inventory.json, one per
# prior run, matched by the glob history/vulnerability_inventory*.json.
# Each is expected to carry the same schema as the current file,
# including .metadata.generated_at, used as that snapshot's timestamp.
#
# CVE state:
#   resolved         no longer present in the CURRENT vulnerability_inventory.json
#                     (having been seen in some prior snapshot), OR explicitly
#                     listed in any patch_change_log.json event's cves_resolved
#   deferred_held     still open, AND its owning package is currently held
#                     (hold_management.json .applied[] with hold_applied=true) --
#                     justification is that hold's recorded reason
#   deferred_window   still open, not held, AND its owning package already
#                     appears in the current patch_plan.json -- a fix is
#                     planned, just waiting for the next maintenance window
#   open              still open, not held, not yet planned
#
# Compliance score = resolved CVEs classified critical/high, divided by
# ALL critical/high CVEs ever seen (any state) -- the literal formula
# from the spec, applied consistently.
#
# "Now", for the 7-day overdue clock, is patch_change_log.json's
# period_end when available (per the task's instruction to use the
# change log for the clock), falling back to the current
# vulnerability_inventory.json's generated_at, and only as a last resort
# the real system date.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
VULN_FILE="${SCRIPT_DIR}/vulnerability_inventory.json"
HISTORY_DIR="${SCRIPT_DIR}/history"
CHANGE_LOG_FILE="${SCRIPT_DIR}/patch_change_log.json"
HOLD_FILE="${SCRIPT_DIR}/hold_management.json"
PLAN_FILE="${SCRIPT_DIR}/patch_plan.json"
OUTPUT_FILE="${SCRIPT_DIR}/patch_compliance.json"

TARGET_SCORE="95.00"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq date hostname uname awk; do need "$c"; done

[[ -f "${VULN_FILE}" ]] || fail "vulnerability_inventory.json not found in ${SCRIPT_DIR} (run 0-vuln_inventory.sh first)"
jq empty "${VULN_FILE}" >/dev/null 2>&1 || fail "vulnerability_inventory.json is invalid JSON"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# ---------------------------------------------------------------------------
# 1-2. Collect every CVE ever seen, across the current inventory and any
#      rotated history/ copies, tagging each with the earliest timestamp
#      it was observed at (first_seen) and whether it's in the CURRENT
#      inventory (still open).
# ---------------------------------------------------------------------------
CURRENT_GENERATED_AT="$(jq -r '.metadata.generated_at // empty' "${VULN_FILE}")"
[[ -z "${CURRENT_GENERATED_AT}" ]] && CURRENT_GENERATED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

ALL_SNAPSHOTS=("${VULN_FILE}")
if [[ -d "${HISTORY_DIR}" ]]; then
    while IFS= read -r f; do
        [[ -n "${f}" ]] || continue
        ALL_SNAPSHOTS+=("${f}")
    done < <(compgen -G "${HISTORY_DIR}/vulnerability_inventory*.json" || true)
fi

# CVE_FIRSTSEEN_FILE: one line per (cve, package, severity, timestamp) seen
# in any snapshot; the earliest timestamp per CVE becomes first_seen.
CVE_OBSERVATIONS="${TMP_DIR}/cve_observations.tsv"
: > "${CVE_OBSERVATIONS}"

for snap in "${ALL_SNAPSHOTS[@]}"; do
    [[ -f "${snap}" ]] || continue
    jq empty "${snap}" >/dev/null 2>&1 || continue
    snap_ts="$(jq -r '.metadata.generated_at // empty' "${snap}")"
    [[ -z "${snap_ts}" ]] && snap_ts="$(date -u -r "${snap}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "${CURRENT_GENERATED_AT}")"

    jq -r --arg ts "${snap_ts}" '
      .packages // [] | .[] as $p | ($p.cves // [])[] |
      [., $p.package, ($p.severity // "unknown"), $ts] | @tsv
    ' "${snap}" >> "${CVE_OBSERVATIONS}" 2>/dev/null
done

CURRENT_CVES_FILE="${TMP_DIR}/current_cves.txt"
jq -r '.packages // [] | .[].cves[]?' "${VULN_FILE}" | sort -u > "${CURRENT_CVES_FILE}"

# ---------------------------------------------------------------------------
# Load enrichment sources
# ---------------------------------------------------------------------------
RESOLVED_VIA_LOG="${TMP_DIR}/resolved_via_log.tsv"
: > "${RESOLVED_VIA_LOG}"
CHANGE_LOG_PERIOD_END=""
if [[ -f "${CHANGE_LOG_FILE}" ]]; then
    jq empty "${CHANGE_LOG_FILE}" >/dev/null 2>&1 && {
        CHANGE_LOG_PERIOD_END="$(jq -r '.period_end // empty' "${CHANGE_LOG_FILE}")"
        jq -r '
          .events // [] | .[] as $e | ($e.cves_resolved // [])[] |
          [., ($e.ended // "")] | @tsv
        ' "${CHANGE_LOG_FILE}" >> "${RESOLVED_VIA_LOG}" 2>/dev/null
    }
fi

HELD_PACKAGES="${TMP_DIR}/held_packages.tsv"
: > "${HELD_PACKAGES}"
if [[ -f "${HOLD_FILE}" ]]; then
    jq empty "${HOLD_FILE}" >/dev/null 2>&1 && \
    jq -r '.applied // [] | .[] | select(.hold_applied == true) | [.package, (.reason // "")] | @tsv' \
      "${HOLD_FILE}" >> "${HELD_PACKAGES}" 2>/dev/null
fi

PLANNED_PACKAGES="${TMP_DIR}/planned_packages.txt"
: > "${PLANNED_PACKAGES}"
if [[ -f "${PLAN_FILE}" ]]; then
    jq empty "${PLAN_FILE}" >/dev/null 2>&1 && \
    jq -r '.plan // [] | .[].package' "${PLAN_FILE}" | sort -u > "${PLANNED_PACKAGES}"
fi

# "Now" for the overdue clock: patch_change_log.json's period_end first,
# per the task's instruction to use the change log for the clock.
NOW_FOR_CLOCK="${CHANGE_LOG_PERIOD_END:-${CURRENT_GENERATED_AT}}"
NOW_EPOCH="$(date -d "${NOW_FOR_CLOCK}" +%s 2>/dev/null || date +%s)"

# ---------------------------------------------------------------------------
# Build the per-CVE list
# ---------------------------------------------------------------------------
CVES_FILE="${TMP_DIR}/cves.jsonl"
: > "${CVES_FILE}"

RESOLVED=0; OPEN=0; DEFERRED_HELD=0; DEFERRED_WINDOW=0
RESOLVED_CH=0; TOTAL_CH=0
OVERDUE=0

# Group observations by CVE: package (last seen), severity (last seen),
# first_seen (min timestamp).
while IFS= read -r cve; do
    [[ -n "${cve}" ]] || continue

    pkg="$(awk -F'\t' -v c="${cve}" '$1==c{print $2; exit}' "${CVE_OBSERVATIONS}")"
    severity="$(awk -F'\t' -v c="${cve}" '$1==c{print $3; exit}' "${CVE_OBSERVATIONS}")"
    first_seen="$(awk -F'\t' -v c="${cve}" '$1==c{print $4}' "${CVE_OBSERVATIONS}" | sort | head -1)"

    is_current="false"
    grep -qxF "${cve}" "${CURRENT_CVES_FILE}" && is_current="true"

    resolved_log_ts="$(awk -F'\t' -v c="${cve}" '$1==c{print $2}' "${RESOLVED_VIA_LOG}" | sort | head -1)"

    state=""
    justification="null"
    resolved_at="null"

    if [[ "${is_current}" == "false" || -n "${resolved_log_ts}" ]]; then
        state="resolved"
        RESOLVED=$((RESOLVED + 1))
        if [[ -n "${resolved_log_ts}" ]]; then
            resolved_at="\"${resolved_log_ts}\""
        else
            resolved_at="\"${CURRENT_GENERATED_AT}\""
        fi
    else
        held_reason="$(awk -F'\t' -v p="${pkg}" '$1==p{print $2; exit}' "${HELD_PACKAGES}")"
        if [[ -n "${held_reason}" ]] || grep -qxF "${pkg}" <(awk -F'\t' '{print $1}' "${HELD_PACKAGES}"); then
            state="deferred_held"
            DEFERRED_HELD=$((DEFERRED_HELD + 1))
            justification="$(jq -Rn --arg j "${held_reason:-package is held}" '$j')"
        elif grep -qxF "${pkg}" "${PLANNED_PACKAGES}" 2>/dev/null; then
            state="deferred_window"
            DEFERRED_WINDOW=$((DEFERRED_WINDOW + 1))
            justification="$(jq -Rn '"scheduled in current patch plan, pending next maintenance window"')"
        else
            state="open"
            OPEN=$((OPEN + 1))
        fi
    fi

    is_crit_high="false"
    [[ "${severity}" == "critical" || "${severity}" == "high" ]] && is_crit_high="true"

    if [[ "${is_crit_high}" == "true" ]]; then
        TOTAL_CH=$((TOTAL_CH + 1))
        [[ "${state}" == "resolved" ]] && RESOLVED_CH=$((RESOLVED_CH + 1))
    fi

    if [[ "${state}" == "open" && "${is_crit_high}" == "true" && -n "${first_seen}" ]]; then
        fs_epoch="$(date -d "${first_seen}" +%s 2>/dev/null || echo "")"
        if [[ -n "${fs_epoch}" ]]; then
            age_days=$(( (NOW_EPOCH - fs_epoch) / 86400 ))
            [[ "${age_days}" -gt 7 ]] && OVERDUE=$((OVERDUE + 1))
        fi
    fi

    fs_json="null"
    [[ -n "${first_seen}" ]] && fs_json="\"${first_seen}\""

    jq -cn \
      --arg id "${cve}" --arg package "${pkg}" --arg severity "${severity}" \
      --arg state "${state}" \
      --argjson first_seen "${fs_json}" \
      --argjson resolved_at "${resolved_at}" \
      --argjson justification "${justification}" \
      '{id:$id, package:$package, severity:$severity, state:$state,
        first_seen:$first_seen, resolved_at:$resolved_at, justification:$justification}' \
      >> "${CVES_FILE}"

done < <(awk -F'\t' '{print $1}' "${CVE_OBSERVATIONS}" | sort -u)

# ---------------------------------------------------------------------------
# Score + emit
# ---------------------------------------------------------------------------
SCORE="$(awk -v r="${RESOLVED_CH}" -v t="${TOTAL_CH}" 'BEGIN{
    if (t == 0) { printf "100.00" } else { printf "%.2f", (r/t)*100 }
}')"

CVES_JSON="$(jq -cs 'sort_by(.id)' "${CVES_FILE}" 2>/dev/null || echo '[]')"
HOSTNAME_VAL="$(hostname)"
KERNEL_VAL="$(uname -r)"
GENERATED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

jq -n \
  --arg generated_at "${GENERATED_AT}" \
  --arg hostname "${HOSTNAME_VAL}" \
  --arg kernel "${KERNEL_VAL}" \
  --argjson resolved "${RESOLVED}" --argjson open_count "${OPEN}" \
  --argjson deferred_held "${DEFERRED_HELD}" --argjson deferred_window "${DEFERRED_WINDOW}" \
  --arg score "${SCORE}" --arg target_score "${TARGET_SCORE}" \
  --argjson overdue "${OVERDUE}" \
  --argjson cves "${CVES_JSON}" \
  '{
     generated_at: $generated_at,
     hostname: $hostname,
     kernel: $kernel,
     summary: {
       resolved: $resolved,
       open: $open_count,
       deferred_held: $deferred_held,
       deferred_window: $deferred_window,
       score: ($score | tonumber),
       target_score: ($target_score | tonumber),
       overdue: $overdue
     },
     cves: $cves
   }' > "${OUTPUT_FILE}"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "patch_compliance.json is invalid JSON"

MEETS_TARGET="$(awk -v s="${SCORE}" -v t="${TARGET_SCORE}" 'BEGIN{print (s+0 >= t+0) ? "1" : "0"}')"
[[ "${MEETS_TARGET}" == "1" ]] && exit 0
exit 1