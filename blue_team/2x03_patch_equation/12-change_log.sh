#!/bin/bash
# name: 12-change_log.sh
# purpose: Parse /var/log/apt/history.log* (including rotated/.gz files),
#          group individual apt transactions into "change events" by
#          15-minute proximity, and enrich each event with the requesting
#          user, whether it happened inside the maintenance window (via
#          Task 11), a link to Task 4's execution log if the timestamps
#          overlap, and which CVEs from Task 0's vulnerability inventory
#          the event's package upgrades resolved.
# Project: 2x03 - Patch Equation
# Task:    12 - The Change Tracking Log
#
# This script is read-only: it parses logs and other tasks' JSON
# artifacts, and writes only its own report.
#
# Idempotency: every input this script reads is static (log files already
# on disk, other tasks' already-generated JSON, and Task 11's guard
# invoked with a fixed historical timestamp override, never "now") -- so
# running this script twice against the same inputs always produces byte-
# identical events (order and content), differing only in nothing at all.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
OUTPUT_FILE="${SCRIPT_DIR}/patch_change_log.json"
EXEC_LOG_FILE="${SCRIPT_DIR}/patch_execution_log.json"
VULN_FILE="${SCRIPT_DIR}/vulnerability_inventory.json"
WINDOW_SCRIPT="${SCRIPT_DIR}/11-maintenance_window.sh"

# Overridable for testing -- defaults to the real apt history log location.
HISTORY_LOG_GLOB_DIR="${HISTORY_LOG_DIR:-/var/log/apt}"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq awk sed date dpkg; do need "$c"; done

GROUP_WINDOW_SECONDS=900  # 15 minutes, per spec

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# ---------------------------------------------------------------------------
# 1. Enumerate history log files, including rotated and gzipped ones, and
#    emit one summary line per apt transaction, SOH (\x01)-delimited:
#      start_raw \x01 end_raw \x01 commandline \x01 requested_by \x01
#      install \x01 upgrade \x01 remove \x01 purge \x01 reinstall
# ---------------------------------------------------------------------------
RAW_TRANSACTIONS="${TMP_DIR}/transactions.raw"
: > "${RAW_TRANSACTIONS}"

AWK_PARSER='
BEGIN { RS=""; FS="\n" }
{
    start=""; enddate=""; cmdline=""; reqby="";
    install=""; upgrade=""; remove=""; purge=""; reinstall="";
    for (i=1; i<=NF; i++) {
        line = $i
        if (line ~ /^Start-Date: /)      { start = substr(line, 13) }
        else if (line ~ /^End-Date: /)   { enddate = substr(line, 11) }
        else if (line ~ /^Commandline: /){ cmdline = substr(line, 14) }
        else if (line ~ /^Requested-By: /){ reqby = substr(line, 15) }
        else if (line ~ /^Install: /)    { install = substr(line, 10) }
        else if (line ~ /^Upgrade: /)    { upgrade = substr(line, 10) }
        else if (line ~ /^Remove: /)     { remove = substr(line, 9) }
        else if (line ~ /^Purge: /)      { purge = substr(line, 8) }
        else if (line ~ /^Reinstall: /)  { reinstall = substr(line, 12) }
    }
    if (start != "") {
        printf "%s\x01%s\x01%s\x01%s\x01%s\x01%s\x01%s\x01%s\x01%s\n", \
            start, enddate, cmdline, reqby, install, upgrade, remove, purge, reinstall
    }
}
'

if compgen -G "${HISTORY_LOG_GLOB_DIR}/history.log*" > /dev/null 2>&1; then
    for f in "${HISTORY_LOG_GLOB_DIR}"/history.log*; do
        [[ -f "${f}" ]] || continue
        case "${f}" in
            *.gz) zcat -- "${f}" 2>/dev/null | awk "${AWK_PARSER}" >> "${RAW_TRANSACTIONS}" ;;
            *)    awk "${AWK_PARSER}" "${f}" >> "${RAW_TRANSACTIONS}" ;;
        esac
    done
fi

TXN_COUNT="$(grep -c . "${RAW_TRANSACTIONS}" 2>/dev/null)"
[[ -z "${TXN_COUNT}" ]] && TXN_COUNT=0
if [[ "${TXN_COUNT}" -eq 0 ]]; then
    echo "[WARN] no apt transactions found under ${HISTORY_LOG_GLOB_DIR}" >&2
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

to_epoch() {
    local raw="$1"
    [[ -n "${raw}" ]] || { echo ""; return; }
    date -d "$(tr -s ' ' ' ' <<< "${raw}")" +%s 2>/dev/null
}

to_iso() {
    local epoch="$1"
    [[ -n "${epoch}" ]] || { echo ""; return; }
    date -d "@${epoch}" +'%Y-%m-%dT%H:%M:%S%:z' 2>/dev/null
}

# Extracts "package version" pairs (one per line) from a raw Install:/
# Upgrade:/Remove:/Purge:/Reinstall: field value. Each entry looks like
# "pkg:arch (ver)" or "pkg:arch (oldver, newver)" or "pkg:arch (ver, automatic)".
# The LAST version-looking token inside the parens is taken as the
# package's resulting version in this transaction (for Upgrade, that's the
# new version; for Install, the only version; "automatic" is never
# version-looking, so it's correctly skipped).
extract_packages() {
    local field="$1"
    [[ -n "${field}" ]] || return 0
    sed -E 's/, ([^,()]+:[a-z0-9]+ \()/\n\1/g' <<< "${field}" | while IFS= read -r entry; do
        [[ -n "${entry}" ]] || continue
        local name ver_blob last_ver
        name="$(sed -E 's/^([^:( ]+).*/\1/' <<< "${entry}")"
        ver_blob="$(sed -E 's/^[^(]*\(([^)]*)\).*/\1/' <<< "${entry}")"
        last_ver="$(awk -F', ' '{print $NF}' <<< "${ver_blob}")"
        if [[ "${last_ver}" == "automatic" ]]; then
            last_ver="$(awk -F', ' '{print $1}' <<< "${ver_blob}")"
        fi
        [[ -n "${name}" ]] || continue
        printf '%s %s\n' "${name}" "${last_ver}"
    done
}

# ---------------------------------------------------------------------------
# 2. Group transactions into change events by 15-minute proximity
#    (single-linkage: each transaction must be within GROUP_WINDOW_SECONDS
#    of the PREVIOUS transaction's start to join the same event).
# ---------------------------------------------------------------------------
SORTED_TXNS="${TMP_DIR}/sorted.tsv"
: > "${SORTED_TXNS}"
while IFS=$'\x01' read -r start end cmdline reqby install upgrade remove purge reinstall; do
    [[ -n "${start}" ]] || continue
    epoch="$(to_epoch "${start}")"
    [[ -n "${epoch}" ]] || continue
    printf '%s\x01%s\x01%s\x01%s\x01%s\x01%s\x01%s\x01%s\x01%s\x01%s\n' \
        "${epoch}" "${start}" "${end}" "${cmdline}" "${reqby}" \
        "${install}" "${upgrade}" "${remove}" "${purge}" "${reinstall}" >> "${SORTED_TXNS}"
done < "${RAW_TRANSACTIONS}"

sort -t $'\x01' -k1,1n -o "${SORTED_TXNS}" "${SORTED_TXNS}"

EVENTS_FILE="${TMP_DIR}/events.jsonl"
: > "${EVENTS_FILE}"

CURRENT_EVENT_TMP="${TMP_DIR}/current_event.tsv"
: > "${CURRENT_EVENT_TMP}"
PREV_EPOCH=""
EVENT_INDEX=0

flush_event() {
    [[ -s "${CURRENT_EVENT_TMP}" ]] || return 0
    EVENT_INDEX=$((EVENT_INDEX + 1))
    cp "${CURRENT_EVENT_TMP}" "${TMP_DIR}/event_${EVENT_INDEX}.tsv"
    : > "${CURRENT_EVENT_TMP}"
}

while IFS=$'\x01' read -r epoch start end cmdline reqby install upgrade remove purge reinstall; do
    if [[ -n "${PREV_EPOCH}" ]] && (( epoch - PREV_EPOCH > GROUP_WINDOW_SECONDS )); then
        flush_event
    fi
    printf '%s\x01%s\x01%s\x01%s\x01%s\x01%s\x01%s\x01%s\x01%s\x01%s\n' \
        "${epoch}" "${start}" "${end}" "${cmdline}" "${reqby}" \
        "${install}" "${upgrade}" "${remove}" "${purge}" "${reinstall}" >> "${CURRENT_EVENT_TMP}"
    PREV_EPOCH="${epoch}"
done < "${SORTED_TXNS}"
flush_event

# ---------------------------------------------------------------------------
# Load enrichment sources once
# ---------------------------------------------------------------------------
VULN_PACKAGES='[]'
[[ -f "${VULN_FILE}" ]] && VULN_PACKAGES="$(jq -c '.packages // []' "${VULN_FILE}" 2>/dev/null || echo '[]')"

EXEC_START_EPOCH=""
EXEC_END_EPOCH=""
if [[ -f "${EXEC_LOG_FILE}" ]]; then
    exec_started_at="$(jq -r '.started_at // empty' "${EXEC_LOG_FILE}" 2>/dev/null)"
    exec_finished_at="$(jq -r '.finished_at // empty' "${EXEC_LOG_FILE}" 2>/dev/null)"
    [[ -n "${exec_started_at}" ]] && EXEC_START_EPOCH="$(date -d "${exec_started_at}" +%s 2>/dev/null)"
    [[ -n "${exec_finished_at}" ]] && EXEC_END_EPOCH="$(date -d "${exec_finished_at}" +%s 2>/dev/null)"
fi

# ---------------------------------------------------------------------------
# 3. Enrich each change event
# ---------------------------------------------------------------------------
INSIDE_COUNT=0
OUTSIDE_COUNT=0
TOTAL_CVES_RESOLVED=0

for ((ei = 1; ei <= EVENT_INDEX; ei++)); do
    ef="${TMP_DIR}/event_${ei}.tsv"
    [[ -f "${ef}" ]] || continue

    first_line="$(head -n1 "${ef}")"
    last_line="$(tail -n1 "${ef}")"

    IFS=$'\x01' read -r start_epoch start_raw _ _ first_reqby _ _ _ _ _ <<< "${first_line}"
    IFS=$'\x01' read -r _ _ end_raw _ _ _ _ _ _ <<< "${last_line}"

    event_start_iso="$(to_iso "${start_epoch}")"
    end_epoch="$(to_epoch "${end_raw}")"
    [[ -z "${end_epoch}" ]] && end_epoch="${start_epoch}"
    event_end_iso="$(to_iso "${end_epoch}")"

    # user: first transaction's Requested-By, falling back sensibly
    user=""
    if [[ -n "${first_reqby}" ]]; then
        user="$(awk '{print $1}' <<< "${first_reqby}")"
    fi
    if [[ -z "${user}" ]]; then
        if grep -q "unattended-upgrade" "${ef}"; then
            user="unattended-upgrades"
        else
            user="root"
        fi
    fi

    # within_window: ask Task 11's guard about THIS event's historical
    # start time, via the same testing hook, now used for real: pinning
    # "now" to a specific past epoch instead of the real clock.
    within_window="unknown"
    if [[ -x "${WINDOW_SCRIPT}" || -f "${WINDOW_SCRIPT}" ]]; then
        decision="$(MEDDEFENSE_NOW_OVERRIDE="${start_epoch}" bash "${WINDOW_SCRIPT}" --report 2>/dev/null | jq -r '.decision // empty' 2>/dev/null)"
        case "${decision}" in
            proceed*) within_window="inside" ;;
            defer)    within_window="outside" ;;
            *)        within_window="unknown" ;;
        esac
    fi
    [[ "${within_window}" == "inside" ]] && INSIDE_COUNT=$((INSIDE_COUNT + 1))
    [[ "${within_window}" == "outside" ]] && OUTSIDE_COUNT=$((OUTSIDE_COUNT + 1))

    # linked_execution_log: does this event overlap Task 4's run?
    linked_log="null"
    if [[ -n "${EXEC_START_EPOCH}" && -n "${EXEC_END_EPOCH}" ]]; then
        if [[ "${start_epoch}" -le "${EXEC_END_EPOCH}" && "${end_epoch}" -ge "${EXEC_START_EPOCH}" ]]; then
            linked_log="\"patch_execution_log.json\""
        fi
    fi

    # packages touched (distinct names, across every field/every txn in event)
    PKG_VER_FILE="${TMP_DIR}/pkgver_${ei}.tsv"
    : > "${PKG_VER_FILE}"
    while IFS=$'\x01' read -r _ _ _ _ _ install upgrade remove purge reinstall; do
        for field in "${install}" "${upgrade}" "${remove}" "${purge}" "${reinstall}"; do
            extract_packages "${field}" >> "${PKG_VER_FILE}"
        done
    done < "${ef}"

    PACKAGE_COUNT="$(awk '{print $1}' "${PKG_VER_FILE}" | sort -u | grep -c .)"
    [[ -z "${PACKAGE_COUNT}" ]] && PACKAGE_COUNT=0

    # cves_resolved: for every (package, new_version) touched in this
    # event, if that package appears in vulnerability_inventory.json and
    # the new version is >= its recorded candidate_version (the fix),
    # its CVEs are considered resolved by this event.
    CVES_FILE="${TMP_DIR}/cves_${ei}.txt"
    : > "${CVES_FILE}"
    while IFS=' ' read -r pkgname pkgver; do
        [[ -n "${pkgname}" && -n "${pkgver}" ]] || continue
        vuln_entry="$(jq -c --arg p "${pkgname}" '.[] | select(.package == $p)' <<< "${VULN_PACKAGES}" 2>/dev/null | head -1)"
        [[ -n "${vuln_entry}" ]] || continue
        candidate="$(jq -r '.candidate_version // empty' <<< "${vuln_entry}")"
        [[ -n "${candidate}" ]] || continue
        if dpkg --compare-versions "${pkgver}" ge "${candidate}" 2>/dev/null; then
            jq -r '.cves[]?' <<< "${vuln_entry}" >> "${CVES_FILE}"
        fi
    done < "${PKG_VER_FILE}"
    CVES_JSON="$(sort -u "${CVES_FILE}" | jq -Rsc 'split("\n")|map(select(length>0))')"
    EVENT_CVES_COUNT="$(jq 'length' <<< "${CVES_JSON}")"
    TOTAL_CVES_RESOLVED=$((TOTAL_CVES_RESOLVED + EVENT_CVES_COUNT))

    jq -cn \
      --arg started "${event_start_iso}" \
      --arg ended "${event_end_iso}" \
      --arg user "${user}" \
      --arg within_window "${within_window}" \
      --argjson packages "${PACKAGE_COUNT}" \
      --argjson linked_execution_log "${linked_log}" \
      --argjson cves_resolved "${CVES_JSON}" \
      '{
         started: $started,
         ended: $ended,
         user: $user,
         within_window: $within_window,
         packages: $packages,
         linked_execution_log: $linked_execution_log,
         cves_resolved: $cves_resolved
       }' >> "${EVENTS_FILE}"
done

# ---------------------------------------------------------------------------
# 4. Emit patch_change_log.json
# ---------------------------------------------------------------------------
EVENTS_JSON="$(jq -cs 'sort_by(.started)' "${EVENTS_FILE}" 2>/dev/null || echo '[]')"
TOTAL_EVENTS="$(jq 'length' <<< "${EVENTS_JSON}")"
PERIOD_START="$(jq -r '.[0].started // empty' <<< "${EVENTS_JSON}")"
PERIOD_END="$(jq -r '.[-1].ended // empty' <<< "${EVENTS_JSON}")"

jq -n \
  --arg period_start "${PERIOD_START}" \
  --arg period_end "${PERIOD_END}" \
  --argjson events "${EVENTS_JSON}" \
  --argjson total_events "${TOTAL_EVENTS}" \
  --argjson inside_window "${INSIDE_COUNT}" \
  --argjson outside_window "${OUTSIDE_COUNT}" \
  --argjson cves_resolved "${TOTAL_CVES_RESOLVED}" \
  '{
     period_start: (if $period_start == "" then null else $period_start end),
     period_end: (if $period_end == "" then null else $period_end end),
     events: $events,
     summary: {
       total_events: $total_events,
       inside_window: $inside_window,
       outside_window: $outside_window,
       cves_resolved: $cves_resolved
     }
   }' > "${OUTPUT_FILE}"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "patch_change_log.json is invalid JSON"