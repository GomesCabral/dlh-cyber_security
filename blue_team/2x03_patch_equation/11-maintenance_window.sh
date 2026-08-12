#!/bin/bash
# name: 11-maintenance_window.sh
# purpose: Pure decision logic -- given maintenance_windows.json and the
#          current time (in the configured timezone), decide whether patch
#          operations are allowed to proceed right now, and if not, when
#          the next window opens. This script NEVER touches package state;
#          it only ever reads the clock and the config, and writes its
#          own report.
# Project: 2x03 - Patch Equation
# Task:    11 - The Maintenance Window Enforcement
#
# Usage:
#   11-maintenance_window.sh --check            exit code communicates the decision
#   11-maintenance_window.sh --wait <seconds>   poll until a window opens or timeout
#   11-maintenance_window.sh --report           print JSON only
#
# Exit codes (--check and --wait):
#   exit 0    inside a standard/extended window -> proceed
#   exit 10   only the "emergency" (always:true) window applies, and
#             MEDDEFENSE_EMERGENCY=1 was set -> proceed via emergency override
#   exit 20   outside every window (or emergency applies but no override) -> defer

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
CONFIG_FILE="${SCRIPT_DIR}/maintenance_windows.json"
OUTPUT_FILE="${SCRIPT_DIR}/maintenance_window.json"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq date awk; do need "$c"; done

[[ -f "${CONFIG_FILE}" ]] || fail "maintenance_windows.json not found in ${SCRIPT_DIR}"
jq empty "${CONFIG_FILE}" >/dev/null 2>&1 || fail "maintenance_windows.json is invalid JSON"

# ---------------------------------------------------------------------------
# Mode parsing
# ---------------------------------------------------------------------------
MODE=""
WAIT_SECONDS=0
case "${1:-}" in
    --check)  MODE="check" ;;
    --report) MODE="report" ;;
    --wait)
        MODE="wait"
        WAIT_SECONDS="${2:-}"
        [[ "${WAIT_SECONDS}" =~ ^[0-9]+$ ]] || fail "--wait requires a numeric seconds argument"
        ;;
    *) fail "Usage: $0 --check | --report | --wait <seconds>" ;;
esac

TIMEZONE="$(jq -r '.timezone // "UTC"' "${CONFIG_FILE}")"

# For testing only: MEDDEFENSE_NOW_OVERRIDE lets the "current time" be
# fixed to a specific epoch, so the date/week-of-month logic below can be
# validated deterministically without waiting for the real calendar. When
# unset (normal use), the script uses the real current time.
now_epoch() {
    if [[ -n "${MEDDEFENSE_NOW_OVERRIDE:-}" ]]; then
        printf '%s' "${MEDDEFENSE_NOW_OVERRIDE}"
    else
        date +%s
    fi
}

# ---------------------------------------------------------------------------
# Window matching helpers
# ---------------------------------------------------------------------------

# Ordinal week-of-month for a given day-of-month (1-indexed): days 1-7 are
# week 1, 8-14 are week 2, etc. This is the conventional definition used
# for "1st/2nd/3rd Saturday of the month" style scheduling.
week_of_month() {
    local dom="$1"
    echo $(( (dom - 1) / 7 + 1 ))
}

# Does a given calendar day (weekday abbrev + day-of-month) satisfy one
# specific window definition?
day_matches_window() {
    local win_json="$1" dow="$2" dom="$3"
    local days_match wom_required wom_actual

    days_match="$(jq -r --arg d "${dow}" '(.days // []) | index($d) != null' <<< "${win_json}")"
    [[ "${days_match}" == "true" ]] || return 1

    wom_required="$(jq -r '.week_of_month // empty' <<< "${win_json}")"
    if [[ -n "${wom_required}" ]]; then
        wom_actual="$(week_of_month "${dom}")"
        [[ "${wom_actual}" == "${wom_required}" ]] || return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Core: compute the full status (active window, next window, decision) as
# of a given epoch. Used identically by --check, --report, and every poll
# iteration of --wait, so all three modes share one source of truth.
# ---------------------------------------------------------------------------
compute_status() {
    local epoch="$1"
    local now_str now_date now_time now_dow now_dom
    now_str="$(TZ="${TIMEZONE}" date -d "@${epoch}" +'%Y-%m-%d %H:%M %a %-d')"
    now_date="$(awk '{print $1}' <<< "${now_str}")"
    now_time="$(awk '{print $2}' <<< "${now_str}")"
    now_dow="$(awk '{print $3}' <<< "${now_str}")"
    now_dom="$(awk '{print $4}' <<< "${now_str}")"

    local windows_json
    windows_json="$(jq -c '.windows // []' "${CONFIG_FILE}")"

    # --- is "now" inside any non-emergency (non-always) window? ---
    local active_name=""
    local n
    n="$(jq 'length' <<< "${windows_json}")"
    for ((i = 0; i < n; i++)); do
        local w
        w="$(jq -c ".[${i}]" <<< "${windows_json}")"
        local is_always
        is_always="$(jq -r '.always // false' <<< "${w}")"
        [[ "${is_always}" == "true" ]] && continue

        if day_matches_window "${w}" "${now_dow}" "${now_dom}"; then
            local start end
            start="$(jq -r '.start' <<< "${w}")"
            end="$(jq -r '.end' <<< "${w}")"
            # String comparison is safe here: both are "HH:MM" 24h, fixed
            # width, so lexicographic order matches chronological order.
            if [[ "${now_time}" > "${start}" || "${now_time}" == "${start}" ]] && [[ "${now_time}" < "${end}" ]]; then
                active_name="$(jq -r '.name' <<< "${w}")"
                break
            fi
        fi
    done

    # --- does an "emergency" (always:true) window exist? ---
    local emergency_name=""
    for ((i = 0; i < n; i++)); do
        local w is_always
        w="$(jq -c ".[${i}]" <<< "${windows_json}")"
        is_always="$(jq -r '.always // false' <<< "${w}")"
        if [[ "${is_always}" == "true" ]]; then
            emergency_name="$(jq -r '.name' <<< "${w}")"
            break
        fi
    done

    # --- next window (only meaningful when nothing is active right now) ---
    local next_name="" next_epoch=""
    if [[ -z "${active_name}" ]]; then
        local best_epoch="" best_name=""
        for ((i = 0; i < n; i++)); do
            local w is_always
            w="$(jq -c ".[${i}]" <<< "${windows_json}")"
            is_always="$(jq -r '.always // false' <<< "${w}")"
            [[ "${is_always}" == "true" ]] && continue

            local wname wstart
            wname="$(jq -r '.name' <<< "${w}")"
            wstart="$(jq -r '.start' <<< "${w}")"

            local offset
            for ((offset = 0; offset <= 60; offset++)); do
                local cand_str cand_date cand_dow cand_dom
                cand_str="$(TZ="${TIMEZONE}" date -d "${now_date} +${offset} days" +'%Y-%m-%d %a %-d')"
                cand_date="$(awk '{print $1}' <<< "${cand_str}")"
                cand_dow="$(awk '{print $2}' <<< "${cand_str}")"
                cand_dom="$(awk '{print $3}' <<< "${cand_str}")"

                day_matches_window "${w}" "${cand_dow}" "${cand_dom}" || continue

                local cand_epoch
                cand_epoch="$(TZ="${TIMEZONE}" date -d "${cand_date} ${wstart}" +%s 2>/dev/null)" || continue
                [[ "${cand_epoch}" -ge "${epoch}" ]] || continue

                if [[ -z "${best_epoch}" || "${cand_epoch}" -lt "${best_epoch}" ]]; then
                    best_epoch="${cand_epoch}"
                    best_name="${wname}"
                fi
                break  # first matching day for this window is its soonest occurrence
            done
        done
        next_name="${best_name}"
        next_epoch="${best_epoch}"
    fi

    # --- decision + exit code ---
    local decision exit_code seconds_until=""
    if [[ -n "${active_name}" ]]; then
        decision="proceed"
        exit_code=0
    elif [[ -n "${emergency_name}" && "${MEDDEFENSE_EMERGENCY:-0}" == "1" ]]; then
        decision="proceed (emergency override)"
        active_name="${emergency_name}"
        exit_code=10
    else
        decision="defer"
        exit_code=20
    fi

    if [[ -z "${active_name}" && -n "${next_epoch}" ]]; then
        seconds_until=$(( next_epoch - epoch ))
    fi

    # Emit as a single pipe-delimited line -- avoids nested-JSON-in-bash
    # fragility; the caller parses these fixed fields directly.
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "${now_date}_T_${now_time}" "${now_dow}" "${active_name}" \
        "${next_name}" "${next_epoch}" "${seconds_until}" \
        "${decision}" "${exit_code}" "${TIMEZONE}"
}

format_report_and_print() {
    local status_line="$1" mode="$2"
    IFS='|' read -r now_raw now_dow active_name next_name next_epoch seconds_until decision exit_code tz <<< "${status_line}"
    local now_display="${now_raw//_T_/ }"

    local next_iso=""
    [[ -n "${next_epoch}" ]] && next_iso="$(TZ="${tz}" date -d "@${next_epoch}" +'%Y-%m-%dT%H:%M:%S%:z' 2>/dev/null)"

    jq -n \
      --arg now "${now_display} ${tz} (${now_dow})" \
      --arg timezone "${tz}" \
      --arg active_window "${active_name}" \
      --arg next_window_name "${next_name}" \
      --arg next_window_time "${next_iso}" \
      --arg seconds_until_next "${seconds_until}" \
      --arg decision "${decision}" \
      --argjson exit_code "${exit_code}" \
      '{
         now: $now,
         timezone: $timezone,
         active_window: (if $active_window == "" then null else $active_window end),
         next_window: (if $next_window_name == "" then null else
           {name: $next_window_name, at: $next_window_time} end),
         seconds_until_next: (if $seconds_until_next == "" then null else ($seconds_until_next | tonumber) end),
         decision: $decision,
         exit_code: $exit_code
       }' > "${OUTPUT_FILE}"

    jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "maintenance_window.json is invalid JSON"

    if [[ "${mode}" == "report" ]]; then
        cat "${OUTPUT_FILE}"
    else
        echo "now:            ${now_display} ${tz} (${now_dow})"
        if [[ -n "${active_name}" ]]; then
            echo "active window:  ${active_name}"
        else
            echo "active window:  (none)"
            if [[ -n "${next_name}" ]]; then
                local next_disp
                next_disp="$(TZ="${tz}" date -d "@${next_epoch}" +'%Y-%m-%d %H:%M' 2>/dev/null)"
                echo "next window:    ${next_name}  at ${next_disp}"
                echo "seconds until:  ${seconds_until}"
            fi
        fi
        echo "decision:       ${decision}"
        echo "Report saved to: maintenance_window.json"
    fi
}

# ---------------------------------------------------------------------------
# Mode dispatch
# ---------------------------------------------------------------------------
case "${MODE}" in
    check|report)
        STATUS_LINE="$(compute_status "$(now_epoch)")"
        format_report_and_print "${STATUS_LINE}" "${MODE}"
        EXIT_CODE="$(cut -d'|' -f8 <<< "${STATUS_LINE}")"
        exit "${EXIT_CODE}"
        ;;
    wait)
        DEADLINE=$(( $(now_epoch) + WAIT_SECONDS ))
        POLL_INTERVAL=10
        FINAL_STATUS=""
        while true; do
            NOW="$(now_epoch)"
            STATUS_LINE="$(compute_status "${NOW}")"
            EXIT_CODE="$(cut -d'|' -f8 <<< "${STATUS_LINE}")"
            FINAL_STATUS="${STATUS_LINE}"

            if [[ "${EXIT_CODE}" -eq 0 || "${EXIT_CODE}" -eq 10 ]]; then
                break
            fi
            if [[ "${NOW}" -ge "${DEADLINE}" ]]; then
                break
            fi

            REMAINING=$(( DEADLINE - NOW ))
            SLEEP_FOR=$(( REMAINING < POLL_INTERVAL ? REMAINING : POLL_INTERVAL ))
            [[ "${SLEEP_FOR}" -le 0 ]] && break
            echo "[*] Outside window, waiting (${REMAINING}s remaining in --wait budget)..."
            sleep "${SLEEP_FOR}"
        done
        format_report_and_print "${FINAL_STATUS}" "check"
        EXIT_CODE="$(cut -d'|' -f8 <<< "${FINAL_STATUS}")"
        exit "${EXIT_CODE}"
        ;;
esac