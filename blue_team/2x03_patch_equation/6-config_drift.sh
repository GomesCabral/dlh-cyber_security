#!/bin/bash
# name: 6-config_drift.sh
# purpose: Compare pre_patch_state.json conffile_hashes (SHA-256) against
#          the current on-disk state, classify every tracked conffile as
#          unchanged, modified, missing, or new, and cross-reference each
#          drifted file against patch_execution_log.json to mark it
#          expected (its owning package was upgraded this run) or
#          unexpected (drifted with no owning upgrade to explain it).
# Project: 2x03 - Patch Equation
# Task:    6 - The Configuration Drift Detector
#
# A note on `diff -u` for modified files: pre_patch_state.json only stores
# a SHA-256 per conffile, not its content, so there is no in-repo "before"
# copy to diff against directly. Instead this script uses the backup files
# dpkg itself leaves behind during a conffile conflict:
#   <path>.dpkg-old   the previous (pre-patch) file, when dpkg overwrote it
#   <path>.dpkg-dist  the new package maintainer's default, when dpkg kept
#                     the local file because it had been modified
# If neither exists, the diff is reported as unavailable rather than
# fabricated -- this is stated explicitly in the output.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
PRE_STATE_FILE="${SCRIPT_DIR}/pre_patch_state.json"
EXEC_LOG_FILE="${SCRIPT_DIR}/patch_execution_log.json"
OUTPUT_FILE="${SCRIPT_DIR}/config_drift.json"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq sha256sum diff dpkg-query awk; do need "$c"; done

[[ -f "${PRE_STATE_FILE}" ]] || fail "pre_patch_state.json not found in ${SCRIPT_DIR} (run the snapshot step first)"
jq empty "${PRE_STATE_FILE}" >/dev/null 2>&1 || fail "pre_patch_state.json is invalid JSON"

[[ -f "${EXEC_LOG_FILE}" ]] || fail "patch_execution_log.json not found in ${SCRIPT_DIR} (run 4-patch_execute.sh first)"
jq empty "${EXEC_LOG_FILE}" >/dev/null 2>&1 || fail "patch_execution_log.json is invalid JSON"

# ---------------------------------------------------------------------------
# 5. Set of packages actually upgraded (status "success") in this run.
#    A drifted conffile is "expected" only if its owning package is in
#    this set -- otherwise the drift has no upgrade to explain it and is
#    "unexpected".
# ---------------------------------------------------------------------------
UPGRADED_PACKAGES="$(jq -r '.entries[]? | select(.status == "success") | .package' "${EXEC_LOG_FILE}")"

is_upgraded_package() {
    local pkg="$1"
    grep -qxF "${pkg}" <<< "${UPGRADED_PACKAGES}"
}

# ---------------------------------------------------------------------------
# Unified diff for a modified conffile, truncated to 40 lines, using
# dpkg's own backup files as the "before" copy (see header note).
# ---------------------------------------------------------------------------
get_diff() {
    local path="$1"
    if [[ -f "${path}.dpkg-old" ]]; then
        diff -u "${path}.dpkg-old" "${path}" 2>/dev/null | head -n 40
    elif [[ -f "${path}.dpkg-dist" ]]; then
        {
            echo "# no pre-patch backup found; diff below is CURRENT vs the package's new default (${path}.dpkg-dist)"
            diff -u "${path}" "${path}.dpkg-dist" 2>/dev/null
        } | head -n 40
    else
        echo "(diff unavailable: neither ${path}.dpkg-old nor ${path}.dpkg-dist exist)"
    fi
}

FILES_JSONL="${TMP_DIR}/files.jsonl"
: > "${FILES_JSONL}"

COUNT_UNCHANGED=0
COUNT_MODIFIED=0
COUNT_MISSING=0
COUNT_NEW=0
UNEXPECTED_DRIFT=false

# ---------------------------------------------------------------------------
# 1-2-3-4. Load conffile_hashes, recompute SHA-256, classify each file
# ---------------------------------------------------------------------------
while IFS= read -r entry; do
    [[ -n "${entry}" ]] || continue

    path="$(jq -r '.path' <<< "${entry}")"
    pre_hash="$(jq -r '.sha256 // .hash // ""' <<< "${entry}")"
    owning_package="$(jq -r '.owning_package // "unknown"' <<< "${entry}")"
    [[ -n "${path}" && "${path}" != "null" ]] || continue

    if [[ ! -f "${path}" ]]; then
        classification="missing"
        current_hash=""
    else
        current_hash="$(sha256sum -- "${path}" 2>/dev/null | awk '{print $1}')"
        if [[ "${current_hash}" == "${pre_hash}" ]]; then
            classification="unchanged"
        else
            classification="modified"
        fi
    fi

    case "${classification}" in
        unchanged)
            COUNT_UNCHANGED=$((COUNT_UNCHANGED + 1))
            jq -cn --arg path "${path}" --arg owning_package "${owning_package}" \
                   --arg classification "${classification}" \
                   --arg pre_sha256 "${pre_hash}" --arg current_sha256 "${current_hash}" \
              '{path:$path, owning_package:$owning_package, classification:$classification,
                pre_sha256:$pre_sha256, current_sha256:$current_sha256,
                expected:true, diff:null}' >> "${FILES_JSONL}"
            ;;
        missing)
            COUNT_MISSING=$((COUNT_MISSING + 1))
            exp=false
            is_upgraded_package "${owning_package}" && exp=true
            [[ "${exp}" == "false" ]] && UNEXPECTED_DRIFT=true
            jq -cn --arg path "${path}" --arg owning_package "${owning_package}" \
                   --arg classification "${classification}" \
                   --arg pre_sha256 "${pre_hash}" \
                   --argjson expected "${exp}" \
              '{path:$path, owning_package:$owning_package, classification:$classification,
                pre_sha256:$pre_sha256, current_sha256:null,
                expected:$expected, diff:null}' >> "${FILES_JSONL}"
            ;;
        modified)
            COUNT_MODIFIED=$((COUNT_MODIFIED + 1))
            exp=false
            is_upgraded_package "${owning_package}" && exp=true
            [[ "${exp}" == "false" ]] && UNEXPECTED_DRIFT=true
            diff_text="$(get_diff "${path}")"
            jq -cn --arg path "${path}" --arg owning_package "${owning_package}" \
                   --arg classification "${classification}" \
                   --arg pre_sha256 "${pre_hash}" --arg current_sha256 "${current_hash}" \
                   --argjson expected "${exp}" --arg diff "${diff_text}" \
              '{path:$path, owning_package:$owning_package, classification:$classification,
                pre_sha256:$pre_sha256, current_sha256:$current_sha256,
                expected:$expected, diff:$diff}' >> "${FILES_JSONL}"
            ;;
    esac
done < <(jq -c '.conffile_hashes // [] | .[]' "${PRE_STATE_FILE}")

# ---------------------------------------------------------------------------
# "new" conffiles: for every package actually upgraded this run, compare
# its current conffile list (dpkg-query) against the set of paths already
# tracked for that package in pre_patch_state.json. Anything present now
# that wasn't tracked before is a conffile the patch itself introduced.
# ---------------------------------------------------------------------------
TRACKED_PATHS_FILE="${TMP_DIR}/tracked_paths.txt"
jq -r '.conffile_hashes // [] | .[] | .path' "${PRE_STATE_FILE}" > "${TRACKED_PATHS_FILE}"

while IFS= read -r pkg; do
    [[ -n "${pkg}" ]] || continue

    while IFS= read -r confline; do
        [[ -n "${confline}" ]] || continue
        cpath="$(awk '{print $1}' <<< "${confline}")"
        [[ -n "${cpath}" ]] || continue

        if ! grep -qxF "${cpath}" "${TRACKED_PATHS_FILE}"; then
            COUNT_NEW=$((COUNT_NEW + 1))
            current_hash_json="null"
            if [[ -f "${cpath}" ]]; then
                current_hash_json="$(sha256sum -- "${cpath}" 2>/dev/null | awk '{printf "\"%s\"", $1}')"
            fi
            jq -cn --arg path "${cpath}" --arg owning_package "${pkg}" \
                   --argjson current_sha256 "${current_hash_json}" \
              '{path:$path, owning_package:$owning_package, classification:"new",
                pre_sha256:null, current_sha256:$current_sha256,
                expected:true, diff:null}' >> "${FILES_JSONL}"
        fi
    done < <(dpkg-query -W -f='${Conffiles}\n' -- "${pkg}" 2>/dev/null | sed 's/^[[:space:]]*//')
done <<< "${UPGRADED_PACKAGES}"

# ---------------------------------------------------------------------------
# 6. Emit config_drift.json
# ---------------------------------------------------------------------------
FILES_ARRAY="$(jq -cs '.' "${FILES_JSONL}")"
TOTAL=$((COUNT_UNCHANGED + COUNT_MODIFIED + COUNT_MISSING + COUNT_NEW))

jq -n \
  --argjson total "${TOTAL}" \
  --argjson unchanged "${COUNT_UNCHANGED}" \
  --argjson modified "${COUNT_MODIFIED}" \
  --argjson missing "${COUNT_MISSING}" \
  --argjson new_count "${COUNT_NEW}" \
  --argjson unexpected_drift "${UNEXPECTED_DRIFT}" \
  --argjson files "${FILES_ARRAY}" \
  '{
     summary: {
       total:$total, unchanged:$unchanged, modified:$modified,
       missing:$missing, new:$new_count, unexpected_drift:$unexpected_drift
     },
     files:$files
   }' > "${OUTPUT_FILE}"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "config_drift.json is invalid JSON"

# 7. Exit code -- 0 only if there is no unexpected drift.
if [[ "${UNEXPECTED_DRIFT}" == "true" ]]; then
    exit 1
fi
exit 0