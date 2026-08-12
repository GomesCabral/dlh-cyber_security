#!/bin/bash
# name: 7-apt_recovery.sh
# purpose: Diagnose a broken dpkg/apt state left behind by an interrupted
#          upgrade, repair it in a strict, non-destructive order, restart
#          any service whose package was in the broken set, and emit a
#          structured recovery report.
# Project: 2x03 - Patch Equation
# Task:    7 - The Broken Upgrade Recovery
#
# Repair order (never reordered, never repeated):
#   1. remove ONLY stale lock files (confirmed unheld by any live process)
#   2. dpkg --configure -a
#   3. apt-get --fix-broken install -y   (DEBIAN_FRONTEND=noninteractive)
#   4. dpkg --audit (re-run) -- must be empty to call the system recovered
#
# A note on "stale" locks: dpkg's lock files use flock(), which the kernel
# releases automatically the instant the holding process dies -- so a lock
# file that still exists but is held by no one is not itself blocking
# anything. This script still identifies and can remove such files (per
# the task's instructions), but the actual repair is done by
# `dpkg --configure -a` and `apt-get --fix-broken install`, which fix the
# real problem: packages left half-configured/half-installed/unpacked by
# the interrupted upgrade.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
DEPS_FILE="${SCRIPT_DIR}/service_dependency_map.json"
OUTPUT_FILE="${SCRIPT_DIR}/apt_recovery.json"
OWN_PID="$$"
START_TIME="$(date +%s)"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq pgrep fuser dpkg apt-get systemctl df date awk grep; do need "$c"; done

LOCK_FILES=(
    "${LOCK_FRONTEND_PATH:-/var/lib/dpkg/lock-frontend}"
    "${LOCK_DPKG_PATH:-/var/lib/dpkg/lock}"
    "${LOCK_APT_ARCHIVES_PATH:-/var/cache/apt/archives/lock}"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Matches real dpkg/apt tooling by binary name (anchored to path/word
# boundaries), never a bare substring "apt" -- otherwise this very script,
# 7-apt_recovery.sh, would match its own command line and refuse to run.
get_live_procs() {
    pgrep -fa -- '(^|/)dpkg([[:space:]]|$)|(^|/)apt-get([[:space:]]|$)|(^|/)apt-cache([[:space:]]|$)|(^|/)apt([[:space:]]|$)|unattended-upgr' 2>/dev/null \
      | grep -vE "^${OWN_PID}[[:space:]]" \
      | grep -v "7-apt_recovery.sh" \
      || true
}

lock_status() {
    local f="$1"
    [[ -e "${f}" ]] || { echo "absent"; return; }
    if fuser "${f}" >/dev/null 2>&1; then
        echo "held"
    else
        echo "stale"
    fi
}

broken_packages() {
    # More robust than scraping dpkg --audit's prose: read the actual
    # dpkg status field for every installed package and match the states
    # the task cares about directly.
    dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null \
      | awk '/half-configured|half-installed|unpacked|triggers-pending/ {print $1}' \
      | sort -u
}

# ---------------------------------------------------------------------------
# 1. Diagnose (read-only, nothing is changed by this section)
# ---------------------------------------------------------------------------
echo "[*] Diagnosing..."

LIVE_PROCS="$(get_live_procs)"
if [[ -n "${LIVE_PROCS}" ]]; then
    echo "    live dpkg/apt processes: DETECTED"
    echo "${LIVE_PROCS}" | sed 's/^/      /'
else
    echo "    live dpkg/apt processes: none"
fi

STALE_LOCKS=()
HELD_LOCKS=()
for lf in "${LOCK_FILES[@]}"; do
    st="$(lock_status "${lf}")"
    [[ "${st}" == "stale" ]] && STALE_LOCKS+=("${lf}")
    [[ "${st}" == "held" ]] && HELD_LOCKS+=("${lf}")
done
if [[ "${#STALE_LOCKS[@]}" -gt 0 ]]; then
    echo "    stale locks: $(IFS=,; echo "${STALE_LOCKS[*]}")"
else
    echo "    stale locks: none"
fi

AUDIT_RAW_BEFORE="$(dpkg --audit 2>/dev/null || true)"
BROKEN_LIST_BEFORE="$(broken_packages)"
BROKEN_COUNT_BEFORE="$(grep -c . <<< "${BROKEN_LIST_BEFORE}" || true)"
[[ -z "${BROKEN_LIST_BEFORE}" ]] && BROKEN_COUNT_BEFORE=0

if [[ "${BROKEN_COUNT_BEFORE}" -gt 0 ]]; then
    echo "    dpkg --audit: $(tr '\n' ',' <<< "${BROKEN_LIST_BEFORE}" | sed 's/,$//; s/,/, /g')"
else
    echo "    dpkg --audit: clean"
fi
echo "    broken packages: ${BROKEN_COUNT_BEFORE}"

ROOT_AVAIL_KB="$(df -Pk / 2>/dev/null | awk 'NR==2{print $4}')"
VAR_AVAIL_KB="$(df -Pk /var 2>/dev/null | awk 'NR==2{print $4}')"

INITIAL_DIAGNOSIS="$(jq -cn \
    --arg live_procs "${LIVE_PROCS}" \
    --argjson stale_locks "$(printf '%s\n' "${STALE_LOCKS[@]:-}" | jq -Rsc 'split("\n")|map(select(length>0))')" \
    --argjson held_locks "$(printf '%s\n' "${HELD_LOCKS[@]:-}" | jq -Rsc 'split("\n")|map(select(length>0))')" \
    --arg audit_raw "${AUDIT_RAW_BEFORE}" \
    --argjson broken_packages "$(printf '%s\n' "${BROKEN_LIST_BEFORE}" | jq -Rsc 'split("\n")|map(select(length>0))')" \
    --argjson broken_count "${BROKEN_COUNT_BEFORE}" \
    --argjson root_avail_kb "${ROOT_AVAIL_KB:-0}" \
    --argjson var_avail_kb "${VAR_AVAIL_KB:-0}" \
    '{
       live_processes_detected: ($live_procs != ""),
       live_processes: $live_procs,
       stale_locks: $stale_locks,
       held_locks: $held_locks,
       dpkg_audit_raw: $audit_raw,
       broken_packages: $broken_packages,
       broken_package_count: $broken_count,
       disk_free_kb: { root: $root_avail_kb, var: $var_avail_kb }
     }')"

ACTIONS_FILE="$(mktemp)"
trap 'rm -f "${ACTIONS_FILE}"' EXIT
: > "${ACTIONS_FILE}"

add_action() {
    jq -cn --arg step "$1" --arg status "$2" --arg detail "$3" \
      '{step:$step, status:$status, detail:$detail}' >> "${ACTIONS_FILE}"
}

write_report_and_exit() {
    local recovered="$1" final_state="$2" exit_code="$3"
    local end_time duration actions_json
    end_time="$(date +%s)"
    duration=$((end_time - START_TIME))
    actions_json="$(jq -cs '.' "${ACTIONS_FILE}")"

    jq -n \
      --argjson initial_diagnosis "${INITIAL_DIAGNOSIS}" \
      --argjson actions_taken "${actions_json}" \
      --arg final_state "${final_state}" \
      --argjson recovered "${recovered}" \
      --argjson duration_seconds "${duration}" \
      '{
         initial_diagnosis: $initial_diagnosis,
         actions_taken: $actions_taken,
         final_state: $final_state,
         recovered: $recovered,
         duration_seconds: $duration_seconds
       }' > "${OUTPUT_FILE}"

    jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "apt_recovery.json is invalid JSON"

    if [[ "${recovered}" == "true" ]]; then
        echo "RECOVERED: yes"
    else
        echo "RECOVERED: no"
    fi
    echo "Duration: ${duration}s"
    echo "Report saved to: apt_recovery.json"
    exit "${exit_code}"
}

# ---------------------------------------------------------------------------
# 2. Refuse to proceed if a live dpkg/apt process is detected
# ---------------------------------------------------------------------------
if [[ -n "${LIVE_PROCS}" ]]; then
    add_action "abort" "refused" "live dpkg/apt process detected, refusing to touch locks or package state"
    write_report_and_exit "false" "aborted: live dpkg/apt process detected" 2
fi

if [[ "${BROKEN_COUNT_BEFORE}" -eq 0 && "${#STALE_LOCKS[@]}" -eq 0 ]]; then
    add_action "diagnose" "noop" "no broken packages and no stale locks found; nothing to repair"
    write_report_and_exit "true" "clean (nothing to repair)" 0
fi

# ---------------------------------------------------------------------------
# 3. Repair, in strict order
# ---------------------------------------------------------------------------
echo "[*] Repairing..."

# 3a. Remove only stale locks (already confirmed unheld above; a live
#     process would have caused an early exit already).
if [[ "${#STALE_LOCKS[@]}" -gt 0 ]]; then
    removed=()
    failed_rm=()
    for lf in "${STALE_LOCKS[@]}"; do
        if rm -f -- "${lf}" 2>/dev/null; then
            removed+=("${lf}")
        else
            failed_rm+=("${lf}")
        fi
    done
    if [[ "${#failed_rm[@]}" -eq 0 ]]; then
        printf '    %-38s %s\n' "remove stale locks" "OK"
        add_action "remove_stale_locks" "ok" "removed: $(IFS=,; echo "${removed[*]}")"
    else
        printf '    %-38s %s\n' "remove stale locks" "PARTIAL"
        add_action "remove_stale_locks" "partial" "removed: $(IFS=,; echo "${removed[*]:-none}"); failed: $(IFS=,; echo "${failed_rm[*]}")"
    fi
else
    printf '    %-38s %s\n' "remove stale locks" "SKIPPED (none)"
    add_action "remove_stale_locks" "skipped" "no stale locks present"
fi

# 3b. dpkg --configure -a
configure_out="$(dpkg --configure -a 2>&1)"
configure_rc=$?
if [[ ${configure_rc} -eq 0 ]]; then
    printf '    %-38s %s\n' "dpkg --configure -a" "OK"
    add_action "dpkg_configure_a" "ok" "$(tail -n 20 <<< "${configure_out}")"
else
    printf '    %-38s %s\n' "dpkg --configure -a" "FAILED (rc=${configure_rc})"
    add_action "dpkg_configure_a" "failed" "$(tail -n 20 <<< "${configure_out}")"
fi

# 3c. apt-get --fix-broken install -y
fix_out="$(DEBIAN_FRONTEND=noninteractive apt-get --fix-broken install -y 2>&1)"
fix_rc=$?
if [[ ${fix_rc} -eq 0 ]]; then
    printf '    %-38s %s\n' "apt-get --fix-broken install" "OK"
    add_action "apt_fix_broken_install" "ok" "$(tail -n 20 <<< "${fix_out}")"
else
    printf '    %-38s %s\n' "apt-get --fix-broken install" "FAILED (rc=${fix_rc})"
    add_action "apt_fix_broken_install" "failed" "$(tail -n 20 <<< "${fix_out}")"
fi

# 3d. Re-run dpkg --audit and confirm the output is empty
AUDIT_RAW_AFTER="$(dpkg --audit 2>/dev/null || true)"
BROKEN_LIST_AFTER="$(broken_packages)"

if [[ -z "${AUDIT_RAW_AFTER}" && -z "${BROKEN_LIST_AFTER}" ]]; then
    printf '    %-38s %s\n' "dpkg --audit (re-run)" "clean"
    add_action "dpkg_audit_recheck" "ok" "dpkg --audit is empty; no broken packages remain"
    AUDIT_CLEAN=true
else
    printf '    %-38s %s\n' "dpkg --audit (re-run)" "STILL BROKEN"
    add_action "dpkg_audit_recheck" "failed" "residual broken packages: $(tr '\n' ',' <<< "${BROKEN_LIST_AFTER}" | sed 's/,$//')"
    AUDIT_CLEAN=false
fi

# ---------------------------------------------------------------------------
# 4. Restart any service whose package was in the (pre-repair) broken set
# ---------------------------------------------------------------------------
echo "[*] Restarting affected services..."

RESTARTED_ANY=false
if [[ -f "${DEPS_FILE}" && -n "${BROKEN_LIST_BEFORE}" ]]; then
    if DEPS_ARRAY="$(jq -s '.' "${DEPS_FILE}" 2>/dev/null)"; then
        BROKEN_JSON="$(printf '%s\n' "${BROKEN_LIST_BEFORE}" | jq -Rsc 'split("\n")|map(select(length>0))')"
        AFFECTED_SERVICES="$(jq -r --argjson broken "${BROKEN_JSON}" \
            '.[] | select(.owning_package as $p | $broken | index($p)) 
                 // select((.linked_packages // []) as $lp | $broken | any(. as $b | $lp | index($b)))
             | .service' <<< "${DEPS_ARRAY}" 2>/dev/null | sort -u)"

        if [[ -n "${AFFECTED_SERVICES}" ]]; then
            while IFS= read -r svc; do
                [[ -n "${svc}" ]] || continue
                RESTARTED_ANY=true
                if systemctl restart "${svc}" >/dev/null 2>&1; then
                    state="$(systemctl is-active "${svc}" 2>/dev/null || echo "unknown")"
                    printf '    %-38s %s\n' "${svc}" "${state}"
                    add_action "restart_service:${svc}" "ok" "post-restart state: ${state}"
                else
                    state="$(systemctl is-active "${svc}" 2>/dev/null || echo "unknown")"
                    printf '    %-38s %s\n' "${svc}" "FAILED (${state})"
                    add_action "restart_service:${svc}" "failed" "post-restart state: ${state}"
                fi
            done <<< "${AFFECTED_SERVICES}"
        fi
    fi
fi
if [[ "${RESTARTED_ANY}" == "false" ]]; then
    echo "    (no services mapped to the broken packages)"
    add_action "restart_services" "skipped" "no service in service_dependency_map.json maps to the broken package set"
fi

# ---------------------------------------------------------------------------
# 5-6. Emit report and exit
# ---------------------------------------------------------------------------
if [[ "${AUDIT_CLEAN}" == "true" ]]; then
    write_report_and_exit "true" "clean" 0
else
    write_report_and_exit "false" "broken: residual packages after repair" 1
fi