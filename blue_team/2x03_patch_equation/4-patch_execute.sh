#!/bin/bash
# name: 4-patch_execute.sh
# purpose: Execute the ordered patch plan from Task 3 safely: one advisory
#          lock, per-package pre/post state capture (installed version and
#          service states for every linked service), controlled apt-get
#          upgrade, dpkg-lock backoff, service restarts, and a structured
#          execution log -- consistent even if the run is interrupted.
# Project: 2x03 - Patch Equation
# Task:    4 - The Safe Patch Execution

set -uo pipefail
# No `set -e`: an apt-get failure or a systemctl try-restart failure must be
# caught and recorded, never allowed to kill the whole script.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
PLAN_FILE="${SCRIPT_DIR}/patch_plan.json"
OUTPUT_FILE="${SCRIPT_DIR}/patch_execution_log.json"
LOCK_FILE="/var/lock/meddefense-patch.lock"
TMP_DIR="$(mktemp -d)"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq apt-get dpkg-query systemctl flock sha256sum date awk grep sed hostname; do
    need "$c"
done

[[ -f "${PLAN_FILE}" ]] || fail "patch_plan.json not found in ${SCRIPT_DIR} (run 3-patch_plan.sh first)"
jq empty "${PLAN_FILE}" >/dev/null 2>&1 || fail "patch_plan.json is invalid JSON"

# ---------------------------------------------------------------------------
# 1. Advisory lock -- flock releases automatically when fd 200 closes (i.e.
#    on any process exit, including kill -9 to the process group's parent),
#    but we also register an explicit trap per the task's hint, so cleanup
#    is visible and intentional rather than implicit.
# ---------------------------------------------------------------------------
echo -n "[*] Acquiring lock ${LOCK_FILE}...  "

exec 200>"${LOCK_FILE}" 2>/dev/null || { echo "FAILED (cannot open lock file)"; exit 2; }

if ! flock -n 200; then
    echo "FAILED (another instance is running)"
    exit 2
fi
echo "OK"

cleanup() {
    flock -u 200 2>/dev/null || true
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

on_interrupt() {
    echo "" >&2
    echo "[FAIL] Interrupted -- releasing lock and aborting." >&2
    # This exit triggers the EXIT trap above, which performs the actual
    # cleanup. Without this explicit exit, bash would run the signal's
    # trap handler and then RESUME the script from where it was
    # interrupted, now with TMP_DIR already removed underneath it.
    exit 130
}
trap on_interrupt INT TERM

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

installed_version() {
    local pkg="$1"
    dpkg-query -W -f='${Version}' -- "${pkg}" 2>/dev/null || true
}

# Real systemd unit name, or empty for the kernel/systemd sentinel values
# emitted by Task 3 ("(kernel-wide)" / "(system-wide)") which are not real
# units and must never be handed to systemctl.
is_real_service() {
    local svc="$1"
    [[ "${svc}" != "(kernel-wide)" && "${svc}" != "(system-wide)" && -n "${svc}" ]]
}

service_state_json() {
    local svc="$1"
    local active sub
    active="$(systemctl is-active "${svc}" 2>/dev/null || true)"
    sub="$(systemctl show -p SubState --value "${svc}" 2>/dev/null || true)"
    jq -cn --arg service "${svc}" \
           --arg active_state "${active:-unknown}" \
           --arg sub_state "${sub:-unknown}" \
      '{service:$service, active_state:$active_state, sub_state:$sub_state}'
}

# Builds the pre/post block: installed version plus the service states
# for every linked service. Used for both the `pre` and `post` snapshots.
# $2 is a newline-separated list of real service names.
state_block() {
    local pkg="$1"
    local services="$2"
    local ver svc_json='[]'

    ver="$(installed_version "${pkg}")"

    if [[ -n "${services}" ]]; then
        svc_json="$(
            while IFS= read -r s; do
                [[ -n "${s}" ]] || continue
                service_state_json "${s}"
            done <<< "${services}" | jq -cs '.'
        )"
    fi

    jq -cn --arg v "${ver}" --argjson services "${svc_json}" \
      '{installed_version: (if $v == "" then null else $v end), services: $services}'
}

# Runs `apt-get install --only-upgrade -y <pkg>`, with exponential backoff
# retry SPECIFICALLY when apt reports the dpkg lock is busy (up to a 120s
# total budget). Any other failure is returned immediately, unretried.
# Return codes: 0 = success, 3 = lock timeout, other = apt-get's own exit code.
run_apt_install() {
    local pkg="$1"
    local out_file="$2"
    local err_file="$3"
    local waited=0
    local backoff=1
    local rc

    while true; do
        DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y -- "${pkg}" \
            > "${out_file}" 2> "${err_file}"
        rc=$?

        [[ ${rc} -eq 0 ]] && return 0

        if grep -qE 'Could not get lock|Unable to acquire the dpkg frontend lock' "${err_file}" 2>/dev/null; then
            if (( waited >= 120 )); then
                echo "[patch-execute] dpkg lock still busy after ${waited}s, giving up" >> "${err_file}"
                return 3
            fi
            local sleep_for=$(( backoff < (120 - waited) ? backoff : (120 - waited) ))
            sleep "${sleep_for}"
            waited=$(( waited + sleep_for ))
            backoff=$(( backoff * 2 ))
            continue
        fi

        return "${rc}"
    done
}

# ---------------------------------------------------------------------------
# 2. Load the plan
# ---------------------------------------------------------------------------
TOTAL="$(jq '.plan | length' "${PLAN_FILE}")"
echo "[*] Loading plan: patch_plan.json (${TOTAL} entries)"

PLAN_HASH="$(sha256sum "${PLAN_FILE}" | awk '{print $1}')"
STARTED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
HOSTNAME_VAL="$(hostname)"

ENTRIES_FILE="${TMP_DIR}/entries.jsonl"
: > "${ENTRIES_FILE}"

SUCCEEDED=0
FAILED=0
STOPPED_EARLY=false
INDEX=0

# Read each plan entry as one compact JSON line -- avoids re-parsing the
# whole file per iteration and keeps the loop's exit status controllable
# (a `while read < <(jq ...)` process-substitution loop runs in the current
# shell, so SUCCEEDED/FAILED counters survive across iterations).
while IFS= read -r entry; do
    INDEX=$((INDEX + 1))

    package="$(jq -r '.package' <<< "${entry}")"
    bucket="$(jq -r '.bucket' <<< "${entry}")"
    requires_restart="$(jq -r '.requires_restart' <<< "${entry}")"
    requires_reboot="$(jq -r '.requires_reboot' <<< "${entry}")"
    rollback_target="$(jq -r '.rollback_target_version' <<< "${entry}")"
    affected_services_json="$(jq -c '.affected_services // []' <<< "${entry}")"

    real_services="$(jq -r '.[]' <<< "${affected_services_json}" | while IFS= read -r s; do
        is_real_service "${s}" && echo "${s}"
    done)"

    if [[ "${STOPPED_EARLY}" == "true" ]]; then
        skip_json="$(jq -cn \
            --arg package "${package}" --arg bucket "${bucket}" \
            --arg status "skipped" \
            '{package:$package, bucket:$bucket, status:$status, pre:null, post:null,
              duration_seconds:0, stdout_tail:"", stderr_tail:"",
              note:"skipped after a prior entry failed"}')"
        echo "${skip_json}" >> "${ENTRIES_FILE}"
        printf '[%d/%d] %-20s %-11s SKIPPED (prior entry failed)\n' "${INDEX}" "${TOTAL}" "${package}" "${bucket}"
        continue
    fi

    printf '[%d/%d] %-20s %-11s apt-get ... ' "${INDEX}" "${TOTAL}" "${package}" "${bucket}"

    pre_block="$(state_block "${package}" "${real_services}")"

    out_file="${TMP_DIR}/${INDEX}.stdout"
    err_file="${TMP_DIR}/${INDEX}.stderr"
    : > "${out_file}"; : > "${err_file}"

    t_start="$(date +%s.%N)"
    run_apt_install "${package}" "${out_file}" "${err_file}"
    apt_rc=$?
    t_end="$(date +%s.%N)"
    duration="$(awk -v a="${t_start}" -v b="${t_end}" 'BEGIN{printf "%.1f", (b-a)}')"

    post_block="$(state_block "${package}" "${real_services}")"

    stdout_tail="$(tail -n 20 "${out_file}" 2>/dev/null | jq -Rs '.')"
    stderr_tail="$(tail -n 20 "${err_file}" 2>/dev/null | jq -Rs '.')"

    if [[ "${apt_rc}" -ne 0 ]]; then
        reason="apt-get exited with code ${apt_rc}"
        [[ "${apt_rc}" -eq 3 ]] && reason="dpkg lock busy for over 120s"

        echo "FAILED (${duration}s)"
        echo "      reason: ${reason}"

        entry_json="$(jq -cn \
            --arg package "${package}" --arg bucket "${bucket}" \
            --arg status "failed" --arg reason "${reason}" \
            --argjson pre "${pre_block}" --argjson post "${post_block}" \
            --argjson duration "${duration}" \
            --argjson stdout_tail "${stdout_tail}" --argjson stderr_tail "${stderr_tail}" \
            '{package:$package, bucket:$bucket, status:$status, reason:$reason,
              pre:$pre, post:$post, duration_seconds:$duration,
              stdout_tail:$stdout_tail, stderr_tail:$stderr_tail, restarts:[]}')"
        echo "${entry_json}" >> "${ENTRIES_FILE}"

        FAILED=$((FAILED + 1))
        STOPPED_EARLY=true
        continue
    fi

    echo "OK (${duration}s)"

    restarts_json='[]'
    if [[ "${requires_restart}" == "true" && "${requires_reboot}" != "true" && -n "${real_services}" ]]; then
        restarts_tmp="${TMP_DIR}/${INDEX}.restarts.jsonl"
        : > "${restarts_tmp}"
        while IFS= read -r svc; do
            [[ -n "${svc}" ]] || continue
            if systemctl try-restart "${svc}" >/dev/null 2>&1; then
                printf '      try-restart %-25s OK\n' "${svc}"
                jq -cn --arg service "${svc}" --arg status "ok" '{service:$service,status:$status}' >> "${restarts_tmp}"
            else
                printf '      try-restart %-25s FAILED\n' "${svc}"
                jq -cn --arg service "${svc}" --arg status "failed" '{service:$service,status:$status}' >> "${restarts_tmp}"
            fi
        done <<< "${real_services}"
        restarts_json="$(jq -cs '.' "${restarts_tmp}")"
    fi

    entry_json="$(jq -cn \
        --arg package "${package}" --arg bucket "${bucket}" \
        --arg status "success" \
        --argjson pre "${pre_block}" --argjson post "${post_block}" \
        --argjson duration "${duration}" \
        --argjson stdout_tail "${stdout_tail}" --argjson stderr_tail "${stderr_tail}" \
        --argjson restarts "${restarts_json}" \
        --arg rollback_target_version "${rollback_target}" \
        '{package:$package, bucket:$bucket, status:$status,
          pre:$pre, post:$post, duration_seconds:$duration,
          stdout_tail:$stdout_tail, stderr_tail:$stderr_tail,
          restarts:$restarts, rollback_target_version:$rollback_target_version}')"
    echo "${entry_json}" >> "${ENTRIES_FILE}"

    SUCCEEDED=$((SUCCEEDED + 1))

done < <(jq -c '.plan[]' "${PLAN_FILE}")

FINISHED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ---------------------------------------------------------------------------
# 4. Emit patch_execution_log.json
# ---------------------------------------------------------------------------
ENTRIES_ARRAY="$(jq -cs '.' "${ENTRIES_FILE}")"

jq -n \
  --arg started_at "${STARTED_AT}" \
  --arg finished_at "${FINISHED_AT}" \
  --arg hostname "${HOSTNAME_VAL}" \
  --arg plan_source_hash "${PLAN_HASH}" \
  --argjson entries "${ENTRIES_ARRAY}" \
  --argjson succeeded "${SUCCEEDED}" \
  --argjson failed_count "${FAILED}" \
  '{
     started_at:$started_at,
     finished_at:$finished_at,
     hostname:$hostname,
     plan_source_hash:$plan_source_hash,
     entries:$entries,
     summary:{ succeeded:$succeeded, failed:$failed_count, total:($entries|length) }
   }' > "${OUTPUT_FILE}"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "patch_execution_log.json is invalid JSON"

echo "Succeeded: ${SUCCEEDED}  Failed: ${FAILED}"
echo "Log saved to: patch_execution_log.json"

if [[ "${FAILED}" -gt 0 ]]; then
    exit 1
fi
exit 0