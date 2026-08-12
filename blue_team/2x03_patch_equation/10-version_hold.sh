#!/bin/bash
# name: 10-version_hold.sh
# purpose: Manage apt-mark holds and apt preference pins as declarative
#          data from hold_registry.json -- apply every registered hold,
#          release any hold present on the system but absent from the
#          registry (convergence), and flag any hold whose review date
#          has passed.
# Project: 2x03 - Patch Equation
# Task:    10 - The Version Hold Management
#
# This script is the ONLY writer of package holds and of
# /etc/apt/preferences.d/meddefense-pins. Manual `apt-mark hold` calls or
# hand-edits to the pin file will be silently reverted the next time this
# script runs, since it always converges the system to exactly what
# hold_registry.json declares -- nothing more, nothing less.
#
# Idempotency: the preferences fragment is regenerated in full and written
# atomically (temp file + mv) from the registry on every run, the same
# pattern used in Task 8 -- never appended to, so it cannot accumulate
# duplicate or stale entries.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
REGISTRY_FILE="${SCRIPT_DIR}/hold_registry.json"
OUTPUT_FILE="${SCRIPT_DIR}/hold_management.json"

# Overridable for safe testing -- defaults to the real system path.
PREFERENCES_FILE="${PREFERENCES_FILE_PATH:-/etc/apt/preferences.d/meddefense-pins}"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq apt-mark date awk mktemp; do need "$c"; done

[[ -f "${REGISTRY_FILE}" ]] || fail "hold_registry.json not found in ${SCRIPT_DIR}"
jq empty "${REGISTRY_FILE}" >/dev/null 2>&1 || fail "hold_registry.json is invalid JSON"

# ---------------------------------------------------------------------------
# 1. Read the registry
# ---------------------------------------------------------------------------
REGISTRY_COUNT="$(jq '.holds // [] | length' "${REGISTRY_FILE}")"
echo "[*] Reading hold_registry.json...           (${REGISTRY_COUNT} entries)"

REGISTRY_PACKAGES="$(jq -r '.holds // [] | .[].package' "${REGISTRY_FILE}")"

# ---------------------------------------------------------------------------
# Current apt-mark holds, before this run touches anything
# ---------------------------------------------------------------------------
CURRENT_HOLDS="$(apt-mark showhold 2>/dev/null | sort -u)"
CURRENT_HOLDS_COUNT="$(grep -c . <<< "${CURRENT_HOLDS}" 2>/dev/null || echo 0)"
[[ -z "${CURRENT_HOLDS}" ]] && CURRENT_HOLDS_COUNT=0
entry_word="entries"
[[ "${CURRENT_HOLDS_COUNT}" -eq 1 ]] && entry_word="entry"
echo "[*] Reading current apt-mark showhold...    (${CURRENT_HOLDS_COUNT} ${entry_word})"

# ---------------------------------------------------------------------------
# Today, for days_to_review math
# ---------------------------------------------------------------------------
TODAY_EPOCH="$(date -u +%s)"

days_to_review() {
    local review_date="$1"
    local review_epoch
    review_epoch="$(date -u -d "${review_date}" +%s 2>/dev/null)" || { echo ""; return; }
    awk -v r="${review_epoch}" -v t="${TODAY_EPOCH}" 'BEGIN{printf "%d", (r - t) / 86400}'
}

# ---------------------------------------------------------------------------
# 2. Apply every hold + write the preferences fragment (regenerated in full)
# ---------------------------------------------------------------------------
echo "Applying holds:"

APPLIED_FILE="$(mktemp)"
OVERDUE_FILE="$(mktemp)"
PREFS_BODY_FILE="$(mktemp)"
trap 'rm -f "${APPLIED_FILE}" "${OVERDUE_FILE}" "${PREFS_BODY_FILE}"' EXIT
: > "${APPLIED_FILE}"
: > "${OVERDUE_FILE}"
: > "${PREFS_BODY_FILE}"

{
    echo "// Managed by 10-version_hold.sh -- MedDefense package hold registry."
    echo "// This file is regenerated in full on every run from hold_registry.json."
    echo "// Do not hand-edit -- changes will be overwritten on the next run."
} >> "${PREFS_BODY_FILE}"

while IFS= read -r entry; do
    [[ -n "${entry}" ]] || continue

    pkg="$(jq -r '.package' <<< "${entry}")"
    reason="$(jq -r '.reason // ""' <<< "${entry}")"
    owner="$(jq -r '.owner // ""' <<< "${entry}")"
    review_date="$(jq -r '.review_date // ""' <<< "${entry}")"
    pin_version="$(jq -r '.pin_version // ""' <<< "${entry}")"

    hold_ok=false
    if apt-mark hold "${pkg}" > /dev/null 2>&1; then
        hold_ok=true
    fi

    {
        echo ""
        echo "// package: ${pkg} | reason: ${reason} | owner: ${owner} | review: ${review_date}"
        echo "Package: ${pkg}"
        echo "Pin: version ${pin_version}"
        echo "Pin-Priority: 1001"
    } >> "${PREFS_BODY_FILE}"

    dtr="$(days_to_review "${review_date}")"

    status_label="OK"
    [[ "${hold_ok}" == "false" ]] && status_label="FAILED"
    printf '  %-24s hold + pin %-28s %s\n' "${pkg}" "${pin_version}" "${status_label}"

    jq -cn --arg package "${pkg}" --arg reason "${reason}" --arg owner "${owner}" \
           --arg review_date "${review_date}" --arg pin_version "${pin_version}" \
           --argjson hold_applied "${hold_ok}" \
           --arg days_to_review "${dtr}" \
      '{package:$package, reason:$reason, owner:$owner, review_date:$review_date,
        pin_version:$pin_version, hold_applied:$hold_applied,
        days_to_review: ($days_to_review | if length>0 then tonumber else null end)}' >> "${APPLIED_FILE}"

    if [[ -n "${dtr}" && "${dtr}" -lt 0 ]]; then
        jq -cn --arg package "${pkg}" --arg owner "${owner}" --arg review_date "${review_date}" \
               --arg days_to_review "${dtr}" \
          '{package:$package, owner:$owner, review_date:$review_date,
            days_to_review: ($days_to_review | tonumber)}' >> "${OVERDUE_FILE}"
    fi
done < <(jq -c '.holds // [] | .[]' "${REGISTRY_FILE}")

# Atomic write of the preferences fragment.
dir="$(dirname -- "${PREFERENCES_FILE}")"
[[ -d "${dir}" ]] || mkdir -p "${dir}" 2>/dev/null || true
tmp_prefs="$(mktemp "${dir}/.tmp.XXXXXX" 2>/dev/null || mktemp)"
cat "${PREFS_BODY_FILE}" > "${tmp_prefs}"
chmod 644 "${tmp_prefs}" 2>/dev/null || true
mv -f "${tmp_prefs}" "${PREFERENCES_FILE}"

# ---------------------------------------------------------------------------
# 3. Convergence: release any current hold not in the registry
# ---------------------------------------------------------------------------
echo "Releasing holds no longer in registry:"

RELEASED_FILE="$(mktemp)"
trap 'rm -f "${APPLIED_FILE}" "${OVERDUE_FILE}" "${PREFS_BODY_FILE}" "${RELEASED_FILE}"' EXIT
: > "${RELEASED_FILE}"

TO_RELEASE="$(comm -23 <(echo "${CURRENT_HOLDS}") <(echo "${REGISTRY_PACKAGES}" | sort -u) 2>/dev/null | grep -v '^$' || true)"

if [[ -z "${TO_RELEASE}" ]]; then
    echo "  (none)"
else
    while IFS= read -r pkg; do
        [[ -n "${pkg}" ]] || continue
        release_ok=false
        if apt-mark unhold "${pkg}" > /dev/null 2>&1; then
            release_ok=true
        fi
        status_label="OK"
        [[ "${release_ok}" == "false" ]] && status_label="FAILED"
        printf '  %-24s unhold %s\n' "${pkg}" "${status_label}"
        jq -cn --arg package "${pkg}" --argjson released "${release_ok}" \
          '{package:$package, released:$released}' >> "${RELEASED_FILE}"
    done <<< "${TO_RELEASE}"
fi

# ---------------------------------------------------------------------------
# 4-5. Emit hold_management.json
# ---------------------------------------------------------------------------
APPLIED_JSON="$(jq -cs '.' "${APPLIED_FILE}")"
RELEASED_JSON="$(jq -cs '.' "${RELEASED_FILE}")"
OVERDUE_JSON="$(jq -cs '.' "${OVERDUE_FILE}")"
OVERDUE_COUNT="$(jq 'length' <<< "${OVERDUE_JSON}")"
TOTAL_HELD="$(jq '[.[] | select(.hold_applied == true)] | length' <<< "${APPLIED_JSON}")"

jq -n \
  --argjson applied "${APPLIED_JSON}" \
  --argjson released "${RELEASED_JSON}" \
  --argjson overdue_reviews "${OVERDUE_JSON}" \
  --argjson total_held "${TOTAL_HELD}" \
  '{
     applied: $applied,
     released: $released,
     overdue_reviews: $overdue_reviews,
     total_held: $total_held
   }' > "${OUTPUT_FILE}"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "hold_management.json is invalid JSON"

echo "Overdue reviews: ${OVERDUE_COUNT}"
echo "Report saved to: hold_management.json"

# The task spec doesn't explicitly define exit codes for this script
# (unlike Tasks 4, 5, 6, 7, and 9). For consistency with the rest of the
# project, exit non-zero if any hold or release action actually failed,
# so a caller (or a cron wrapper) can detect a partially-applied registry
# instead of only finding out by reading the report.
ANY_FAILURE="$(jq '([.applied[] | select(.hold_applied == false)] | length)
                  + ([.released[] | select(.released == false)] | length) > 0' "${OUTPUT_FILE}")"
[[ "${ANY_FAILURE}" == "true" ]] && exit 1
exit 0