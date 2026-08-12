#!/bin/bash
# name: 13-patch_pipeline.sh
# purpose: Chain every preceding task into one idempotent pipeline: run by
#          hand today, by cron tomorrow, by another analyst next week --
#          identical inputs always produce identical outputs, because
#          every stage this pipeline calls was already built to be
#          idempotent on its own.
# Project: 2x03 - Patch Equation
# Task:    13 - The End-to-End Patch Pipeline
#
# Stage order (fixed, never reordered):
#   0-vuln_inventory.sh, 1-service_deps.sh, 2-pre_patch_snapshot.sh,
#   3-patch_plan.sh, 11-maintenance_window.sh --check, 4-patch_execute.sh,
#   5-post_patch_validate.sh, 6-config_drift.sh, 12-change_log.sh
#
# Maintenance window handling: if 11-maintenance_window.sh --check exits
# 20 (out of window) and MEDDEFENSE_EMERGENCY is not set, stages 4-6 are
# skipped and the pipeline is marked "deferred" (exit 0, not a failure --
# deferring is the correct, intended outcome of an out-of-window run).
# Stage 12 (the change log) still runs regardless, so a deferred run is
# itself recorded.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
OUTPUT_FILE="${SCRIPT_DIR}/pipeline_run.json"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq date hostname; do need "$c"; done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

STARTED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
PIPELINE_START_EPOCH="$(date +%s)"
HOSTNAME_VAL="$(hostname)"

STAGES_FILE="${TMP_DIR}/stages.jsonl"
: > "${STAGES_FILE}"

declare -A ARTIFACTS=()
declare -A SUCCEEDED_STAGES=()
PIPELINE_STATUS="ok"
TOTAL_STAGES=9
STAGE_NUM=0

# ---------------------------------------------------------------------------
# Runs one stage script, capturing stdout/stderr/exit-code/duration.
# Returns the stage's exit code via $?; the caller decides what to do
# with it (this function itself never aborts the pipeline).
# ---------------------------------------------------------------------------
run_stage() {
    local script="$1"; shift
    local out_file="${TMP_DIR}/${script}.stdout"
    local err_file="${TMP_DIR}/${script}.stderr"
    local script_path="${SCRIPT_DIR}/${script}"

    if [[ ! -f "${script_path}" ]]; then
        echo "" > "${out_file}"
        echo "script not found: ${script_path}" > "${err_file}"
        echo "-1"
        return
    fi

    local t_start t_end duration rc
    t_start="$(date +%s.%N)"
    bash "${script_path}" "$@" > "${out_file}" 2> "${err_file}"
    rc=$?
    t_end="$(date +%s.%N)"
    duration="$(awk -v a="${t_start}" -v b="${t_end}" 'BEGIN{printf "%.1f", (b-a)}')"

    echo "${rc} ${duration}"
}

record_stage() {
    local name="$1" script="$2" rc="$3" duration="$4" status="$5"
    local out_file="${TMP_DIR}/${script}.stdout"
    local err_file="${TMP_DIR}/${script}.stderr"
    local stdout_tail stderr_tail

    stdout_tail="$(tail -n 20 "${out_file}" 2>/dev/null | jq -Rs '.')"
    stderr_tail="$(tail -n 20 "${err_file}" 2>/dev/null | jq -Rs '.')"

    jq -cn \
      --arg name "${name}" --arg script "${script}" \
      --argjson exit_code "${rc}" --argjson duration_seconds "${duration}" \
      --arg status "${status}" \
      --argjson stdout_tail "${stdout_tail}" --argjson stderr_tail "${stderr_tail}" \
      '{name:$name, script:$script, status:$status, exit_code:$exit_code,
        duration_seconds:$duration_seconds, stdout_tail:$stdout_tail, stderr_tail:$stderr_tail}' \
      >> "${STAGES_FILE}"
}

detail_for() {
    # Best-effort extra console detail per stage, read from that stage's
    # own JSON artifact when available. Falls back to nothing (just the
    # duration) if the artifact or expected field is missing.
    local script="$1"
    case "${script}" in
        4-patch_execute.sh)
            [[ -f "${SCRIPT_DIR}/patch_execution_log.json" ]] || return
            jq -r '"\(.summary.succeeded + .summary.failed) packages"' "${SCRIPT_DIR}/patch_execution_log.json" 2>/dev/null
            ;;
        5-post_patch_validate.sh)
            [[ -f "${SCRIPT_DIR}/post_patch_validation.json" ]] || return
            jq -r '"\(.passed)/\(.total_checks) checks"' "${SCRIPT_DIR}/post_patch_validation.json" 2>/dev/null
            ;;
        6-config_drift.sh)
            [[ -f "${SCRIPT_DIR}/config_drift.json" ]] || return
            jq -r 'if .summary.unexpected_drift then "unexpected drift detected" else "no unexpected drift" end' \
              "${SCRIPT_DIR}/config_drift.json" 2>/dev/null
            ;;
        12-change_log.sh)
            [[ -f "${SCRIPT_DIR}/patch_change_log.json" ]] || return
            jq -r '"\(.summary.total_events) event" + (if .summary.total_events == 1 then "" else "s" end)' \
              "${SCRIPT_DIR}/patch_change_log.json" 2>/dev/null
            ;;
    esac
}

print_stage_line() {
    local name="$1" status="$2" duration="$3" extra="$4"
    STAGE_NUM=$((STAGE_NUM + 1))
    local suffix
    if [[ -z "${duration}" ]]; then
        suffix="(${extra})"
    elif [[ -n "${extra}" ]]; then
        suffix="(${duration}s, ${extra})"
    else
        suffix="(${duration}s)"
    fi
    printf '[%d/%d] %-35s %s  %s\n' "${STAGE_NUM}" "${TOTAL_STAGES}" "${name}" "${status}" "${suffix}"
}

# ---------------------------------------------------------------------------
# Stages 1-4: inventory, dependency map, snapshot, plan
# ---------------------------------------------------------------------------
for entry in "0-vuln_inventory.sh:0-vuln_inventory.sh" \
             "1-service_deps.sh:1-service_deps.sh" \
             "2-pre_patch_snapshot.sh:2-pre_patch_snapshot.sh" \
             "3-patch_plan.sh:3-patch_plan.sh"; do
    script="${entry%%:*}"
    read -r rc duration < <(run_stage "${script}")

    if [[ "${rc}" -eq 0 ]]; then
        extra="$(detail_for "${script}")"
        print_stage_line "${script}" "OK" "${duration}" "${extra}"
        record_stage "${script}" "${script}" "${rc}" "${duration}" "ok"
        SUCCEEDED_STAGES["${script}"]=1
    else
        print_stage_line "${script}" "FAILED" "${duration}" "exit ${rc}"
        record_stage "${script}" "${script}" "${rc}" "${duration}" "failed"
        PIPELINE_STATUS="failed"
        break
    fi
done

# Artifact map for the stages above (only meaningful if we got this far)
ARTIFACTS["0-vuln_inventory.sh"]="vulnerability_inventory.json"
ARTIFACTS["1-service_deps.sh"]="service_dependency_map.json"
ARTIFACTS["2-pre_patch_snapshot.sh"]="pre_patch_state.json"
ARTIFACTS["3-patch_plan.sh"]="patch_plan.json"

# ---------------------------------------------------------------------------
# Stage 5: maintenance window guard (special exit-code handling)
# ---------------------------------------------------------------------------
if [[ "${PIPELINE_STATUS}" == "ok" ]]; then
    script="11-maintenance_window.sh"
    read -r rc duration < <(run_stage "${script}" --check)
    ARTIFACTS["${script}"]="maintenance_window.json"

    window_name=""
    [[ -f "${SCRIPT_DIR}/maintenance_window.json" ]] && \
        window_name="$(jq -r '.active_window // empty' "${SCRIPT_DIR}/maintenance_window.json" 2>/dev/null)"

    case "${rc}" in
        0)
            print_stage_line "${script}" "OK" "" "${window_name:-standard} window active"
            record_stage "${script}" "${script}" "${rc}" "${duration}" "ok"
            SUCCEEDED_STAGES["${script}"]=1
            ;;
        10)
            print_stage_line "${script}" "OK" "" "emergency override"
            record_stage "${script}" "${script}" "${rc}" "${duration}" "ok"
            SUCCEEDED_STAGES["${script}"]=1
            ;;
        20)
            if [[ "${MEDDEFENSE_EMERGENCY:-0}" == "1" ]]; then
                print_stage_line "${script}" "OK" "" "out of window, MEDDEFENSE_EMERGENCY bypass"
                record_stage "${script}" "${script}" "${rc}" "${duration}" "ok"
                SUCCEEDED_STAGES["${script}"]=1
            else
                print_stage_line "${script}" "DEFERRED" "" "out of window"
                record_stage "${script}" "${script}" "${rc}" "${duration}" "deferred"
                PIPELINE_STATUS="deferred"
            fi
            ;;
        *)
            print_stage_line "${script}" "FAILED" "${duration}" "exit ${rc}"
            record_stage "${script}" "${script}" "${rc}" "${duration}" "failed"
            PIPELINE_STATUS="failed"
            ;;
    esac
fi

# ---------------------------------------------------------------------------
# Stages 6-8: execute, validate, drift -- skipped entirely if deferred
# ---------------------------------------------------------------------------
if [[ "${PIPELINE_STATUS}" == "ok" ]]; then
    EXEC_GROUP=("4-patch_execute.sh" "5-post_patch_validate.sh" "6-config_drift.sh")
    EXEC_GROUP_FAILED=false
    for script in "${EXEC_GROUP[@]}"; do
        case "${script}" in
            4-patch_execute.sh) ARTIFACTS["${script}"]="patch_execution_log.json" ;;
            5-post_patch_validate.sh) ARTIFACTS["${script}"]="post_patch_validation.json" ;;
            6-config_drift.sh) ARTIFACTS["${script}"]="config_drift.json" ;;
        esac

        if [[ "${EXEC_GROUP_FAILED}" == "true" ]]; then
            STAGE_NUM=$((STAGE_NUM + 1))
            printf '[%d/%d] %-35s %s  (skipped, prior stage failed)\n' "${STAGE_NUM}" "${TOTAL_STAGES}" "${script}" "SKIPPED"
            jq -cn --arg name "${script}" --arg script "${script}" \
              '{name:$name, script:$script, status:"skipped", exit_code:null,
                duration_seconds:0, stdout_tail:"", stderr_tail:"",
                note:"skipped: an earlier stage in this pipeline run failed"}' >> "${STAGES_FILE}"
            continue
        fi

        read -r rc duration < <(run_stage "${script}")

        if [[ "${rc}" -eq 0 ]]; then
            extra="$(detail_for "${script}")"
            print_stage_line "${script}" "OK" "${duration}" "${extra}"
            record_stage "${script}" "${script}" "${rc}" "${duration}" "ok"
            SUCCEEDED_STAGES["${script}"]=1
        else
            print_stage_line "${script}" "FAILED" "${duration}" "exit ${rc}"
            record_stage "${script}" "${script}" "${rc}" "${duration}" "failed"
            PIPELINE_STATUS="failed"
            EXEC_GROUP_FAILED=true
        fi
    done
elif [[ "${PIPELINE_STATUS}" == "deferred" ]]; then
    for script in "4-patch_execute.sh" "5-post_patch_validate.sh" "6-config_drift.sh"; do
        STAGE_NUM=$((STAGE_NUM + 1))
        printf '[%d/%d] %-35s %s  (skipped, out of window)\n' "${STAGE_NUM}" "${TOTAL_STAGES}" "${script}" "SKIPPED"
        jq -cn --arg name "${script}" --arg script "${script}" \
          '{name:$name, script:$script, status:"skipped", exit_code:null,
            duration_seconds:0, stdout_tail:"", stderr_tail:"",
            note:"skipped: pipeline deferred (out of maintenance window)"}' >> "${STAGES_FILE}"
    done
fi

# ---------------------------------------------------------------------------
# Stage 9: change log -- always runs (records what happened, even a defer)
# ---------------------------------------------------------------------------
if [[ "${PIPELINE_STATUS}" != "failed" ]]; then
    script="12-change_log.sh"
    read -r rc duration < <(run_stage "${script}")
    ARTIFACTS["${script}"]="patch_change_log.json"

    if [[ "${rc}" -eq 0 ]]; then
        extra="$(detail_for "${script}")"
        print_stage_line "${script}" "OK" "${duration}" "${extra}"
        record_stage "${script}" "${script}" "${rc}" "${duration}" "ok"
        SUCCEEDED_STAGES["${script}"]=1
    else
        print_stage_line "${script}" "FAILED" "${duration}" "exit ${rc}"
        record_stage "${script}" "${script}" "${rc}" "${duration}" "failed"
        PIPELINE_STATUS="failed"
    fi
else
    STAGE_NUM=$((STAGE_NUM + 1))
    printf '[%d/%d] %-35s %s  (skipped, earlier stage failed)\n' "${STAGE_NUM}" "${TOTAL_STAGES}" "12-change_log.sh" "SKIPPED"
    jq -cn '{name:"12-change_log.sh", script:"12-change_log.sh", status:"skipped", exit_code:null,
             duration_seconds:0, stdout_tail:"", stderr_tail:"",
             note:"skipped: earlier stage failed"}' >> "${STAGES_FILE}"
fi

# ---------------------------------------------------------------------------
# Emit pipeline_run.json
# ---------------------------------------------------------------------------
FINISHED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
PIPELINE_END_EPOCH="$(date +%s)"
TOTAL_DURATION="$((PIPELINE_END_EPOCH - PIPELINE_START_EPOCH))"

STAGES_JSON="$(jq -cs '.' "${STAGES_FILE}" 2>/dev/null || echo '[]')"

ARTIFACTS_JSON="{}"
for key in "${!ARTIFACTS[@]}"; do
    if [[ -n "${SUCCEEDED_STAGES[$key]:-}" && -f "${SCRIPT_DIR}/${ARTIFACTS[$key]}" ]]; then
        ARTIFACTS_JSON="$(jq -c --arg k "${key}" --arg v "${ARTIFACTS[$key]}" '. + {($k): $v}' <<< "${ARTIFACTS_JSON}")"
    fi
done

jq -n \
  --arg started_at "${STARTED_AT}" \
  --arg finished_at "${FINISHED_AT}" \
  --arg hostname "${HOSTNAME_VAL}" \
  --arg pipeline_status "${PIPELINE_STATUS}" \
  --argjson stages "${STAGES_JSON}" \
  --argjson artifacts "${ARTIFACTS_JSON}" \
  --argjson duration_seconds "${TOTAL_DURATION}" \
  '{
     started_at: $started_at,
     finished_at: $finished_at,
     hostname: $hostname,
     pipeline_status: $pipeline_status,
     duration_seconds: $duration_seconds,
     stages: $stages,
     artifacts: $artifacts
   }' > "${OUTPUT_FILE}"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "pipeline_run.json is invalid JSON"

echo "PIPELINE: ${PIPELINE_STATUS}"
echo "Duration: ${TOTAL_DURATION}.0s"
echo "Report saved to: pipeline_run.json"

if [[ "${PIPELINE_STATUS}" == "failed" ]]; then
    exit 1
fi
exit 0