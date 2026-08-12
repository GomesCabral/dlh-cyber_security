#!/bin/bash
# name: 2-pre_patch_snapshot.sh
# purpose: Capture the full state of the system before any patch
#          operation, so every subsequent change can be measured against
#          an exact baseline: package versions, active service state
#          (ActiveState, SubState, MainPID), listening sockets, a
#          SHA-256 per tracked conffile, kernel release, and whether a
#          reboot is already pending. Pure read-only capture -- always
#          safe to re-run.
# Project: 2x03 - Patch Equation
# Task:    2 - The Pre-Patch State Snapshot
#
# This is the reference point every later validation task compares
# against (Tasks 5, 6, and 9 all read pre_patch_state.json). Skipping
# this step means flying blind: there is nothing to compare the
# post-patch state to.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
OUTPUT_FILE="${SCRIPT_DIR}/pre_patch_state.json"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq dpkg-query systemctl sha256sum readlink awk sed grep date hostname uname; do need "$c"; done
HAVE_SS=0
command -v ss >/dev/null 2>&1 && HAVE_SS=1
[[ "${HAVE_SS}" -eq 0 ]] && echo "[WARN] 'ss' not found -- listening sockets will be empty" >&2

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
HOSTNAME_VAL="$(hostname)"
KERNEL_VAL="$(uname -r)"

# ---------------------------------------------------------------------------
# reboot_required: presence of /var/run/reboot-required
# ---------------------------------------------------------------------------
REBOOT_REQUIRED="false"
[[ -f /var/run/reboot-required ]] && REBOOT_REQUIRED="true"

# ---------------------------------------------------------------------------
# 1. packages: every installed package -> its currently installed version,
#    via dpkg-query.
# ---------------------------------------------------------------------------
PACKAGES_JSON="$(
    dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' 2>/dev/null \
    | awk '$3=="install" && $4=="ok" && $5=="installed" {print $1, $2}' \
    | jq -Rsc '
        split("\n") | map(select(length > 0) | split(" ")) |
        map(select(length >= 2)) |
        map({(.[0]): .[1]}) | add // {}
      ' 2>/dev/null
)"
jq empty <<< "${PACKAGES_JSON}" >/dev/null 2>&1 || PACKAGES_JSON='{}'
PACKAGE_COUNT="$(jq 'keys | length' <<< "${PACKAGES_JSON}")"
PACKAGES_JSON_FILE="${TMP_DIR}/packages.json"
printf '%s' "${PACKAGES_JSON}" > "${PACKAGES_JSON_FILE}"

# ---------------------------------------------------------------------------
# 2. services: every active systemd service -> ActiveState, SubState,
#    MainPID, queried by their literal systemctl property names.
# ---------------------------------------------------------------------------
SERVICES_FILE="${TMP_DIR}/services.jsonl"
: > "${SERVICES_FILE}"

while IFS= read -r svc; do
    [[ -n "${svc}" ]] || continue

    # A single `systemctl show` call with a comma-separated property list
    # returns all three properties in one shot, each on its own "Key=Value"
    # line -- more efficient than three separate calls per service.
    props="$(systemctl show -p ActiveState -p SubState -p MainPID "${svc}" 2>/dev/null)"
    active_state="$(sed -n 's/^ActiveState=//p' <<< "${props}")"
    sub_state="$(sed -n 's/^SubState=//p' <<< "${props}")"
    main_pid="$(sed -n 's/^MainPID=//p' <<< "${props}")"

    [[ -z "${active_state}" ]] && active_state="unknown"
    [[ -z "${sub_state}" ]] && sub_state="unknown"
    [[ -z "${main_pid}" ]] && main_pid="0"

    jq -cn \
      --arg service "${svc}" \
      --arg active_state "${active_state}" \
      --arg sub_state "${sub_state}" \
      --argjson main_pid "${main_pid}" \
      '{service:$service, active_state:$active_state, sub_state:$sub_state, main_pid:$main_pid}' \
      >> "${SERVICES_FILE}"
done < <(systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | awk '{print $1}')

SERVICES_JSON="$(jq -cs '.' "${SERVICES_FILE}" 2>/dev/null)"
jq empty <<< "${SERVICES_JSON}" >/dev/null 2>&1 || SERVICES_JSON='[]'
SERVICE_COUNT="$(jq 'length' <<< "${SERVICES_JSON}")"
SERVICES_JSON_FILE="${TMP_DIR}/services_out.json"
printf '%s' "${SERVICES_JSON}" > "${SERVICES_JSON_FILE}"

# ---------------------------------------------------------------------------
# 3. listening: every listening TCP/UDP socket via `ss -tulnp`, best-effort
#    mapped to a systemd unit via the owning process's PID -> cgroup.
# ---------------------------------------------------------------------------
LISTENING_FILE="${TMP_DIR}/listening.jsonl"
: > "${LISTENING_FILE}"

pid_to_unit() {
    local pid="$1"
    [[ -n "${pid}" && -r "/proc/${pid}/cgroup" ]] || { echo ""; return; }
    sed -nE 's#.*/([A-Za-z0-9@._-]+\.service)$#\1#p' "/proc/${pid}/cgroup" 2>/dev/null | head -1
}

if [[ "${HAVE_SS}" -eq 1 ]]; then
    while IFS= read -r line; do
        [[ -n "${line}" ]] || continue
        proto="$(awk '{print $1}' <<< "${line}")"
        proto="${proto%6}"  # tcp6 -> tcp, udp6 -> udp

        # Column layout varies across iproute2 versions (Netid column may or
        # may not be present). Find the LISTEN state's local address:port by
        # scanning every field for one matching IP:PORT or *:PORT, rather
        # than trusting a fixed column index (verified necessary: real `ss`
        # output does not reliably keep the local address in a fixed column).
        port=""
        for tok in ${line}; do
            if [[ "${tok}" =~ ^[^[:space:]]*:([0-9]+)$ ]]; then
                port="${BASH_REMATCH[1]}"
                break
            fi
        done
        [[ "${port}" =~ ^[0-9]+$ ]] || continue

        pid="$(grep -oE 'pid=[0-9]+' <<< "${line}" | head -1 | cut -d= -f2)"
        unit=""
        [[ -n "${pid}" ]] && unit="$(pid_to_unit "${pid}")"

        jq -cn --arg port "${port}" --arg proto "${proto}" --arg service "${unit}" \
          '{port: ($port | tonumber), proto: $proto, service: (if $service == "" then null else $service end)}' \
          >> "${LISTENING_FILE}"
    done < <(ss -tulnp 2>/dev/null | tail -n +2)
fi

LISTENING_JSON="$(jq -cs 'unique_by([.port, .proto])' "${LISTENING_FILE}" 2>/dev/null)"
jq empty <<< "${LISTENING_JSON}" >/dev/null 2>&1 || LISTENING_JSON='[]'
LISTENING_JSON_FILE="${TMP_DIR}/listening_out.json"
printf '%s' "${LISTENING_JSON}" > "${LISTENING_JSON_FILE}"

# ---------------------------------------------------------------------------
# 4. conffile_hashes: SHA-256 of every conffile under /etc tracked by a
#    package, per `dpkg-query`.
# ---------------------------------------------------------------------------
CONFFILES_FILE="${TMP_DIR}/conffiles.jsonl"
: > "${CONFFILES_FILE}"

while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    pkg="$(awk '{print $1}' <<< "${line}")"
    dpkg-query -W -f='${Conffiles}\n' -- "${pkg}" 2>/dev/null | sed 's/^[[:space:]]*//' | while IFS= read -r confline; do
        [[ -n "${confline}" ]] || continue
        cpath="$(awk '{print $1}' <<< "${confline}")"
        [[ -n "${cpath}" && -f "${cpath}" ]] || continue
        real="$(readlink -f -- "${cpath}" 2>/dev/null)"
        [[ -n "${real}" ]] || real="${cpath}"
        hash="$(sha256sum -- "${real}" 2>/dev/null | awk '{print $1}')"
        [[ -n "${hash}" ]] || continue
        jq -cn --arg path "${cpath}" --arg sha256 "${hash}" --arg owning_package "${pkg}" \
          '{path:$path, sha256:$sha256, owning_package:$owning_package}' >> "${CONFFILES_FILE}"
    done
done < <(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null)

CONFFILES_JSON="$(jq -cs 'unique_by(.path)' "${CONFFILES_FILE}" 2>/dev/null)"
jq empty <<< "${CONFFILES_JSON}" >/dev/null 2>&1 || CONFFILES_JSON='[]'
CONFFILE_COUNT="$(jq 'length' <<< "${CONFFILES_JSON}")"
CONFFILES_JSON_FILE="${TMP_DIR}/conffiles_out.json"
printf '%s' "${CONFFILES_JSON}" > "${CONFFILES_JSON_FILE}"

# ---------------------------------------------------------------------------
# 5-6. Emit pre_patch_state.json
# ---------------------------------------------------------------------------
JQ_ERR="${TMP_DIR}/jq_final.err"
jq -n \
  --arg timestamp "${TIMESTAMP}" \
  --arg hostname "${HOSTNAME_VAL}" \
  --arg kernel "${KERNEL_VAL}" \
  --argjson reboot_required "${REBOOT_REQUIRED}" \
  --slurpfile packages_arr "${PACKAGES_JSON_FILE}" \
  --slurpfile services_arr "${SERVICES_JSON_FILE}" \
  --slurpfile listening_arr "${LISTENING_JSON_FILE}" \
  --slurpfile conffile_hashes_arr "${CONFFILES_JSON_FILE}" \
  '{
     timestamp: $timestamp,
     hostname: $hostname,
     kernel: $kernel,
     packages: $packages_arr[0],
     services: $services_arr[0],
     listening: $listening_arr[0],
     conffile_hashes: $conffile_hashes_arr[0],
     reboot_required: $reboot_required
   }' > "${OUTPUT_FILE}" 2> "${JQ_ERR}"

if [[ ! -s "${OUTPUT_FILE}" ]]; then
    fail "jq failed to build pre_patch_state.json: $(cat "${JQ_ERR}")"
fi

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "pre_patch_state.json is invalid JSON"

FILE_SIZE_KB="$(( $(stat -c%s "${OUTPUT_FILE}" 2>/dev/null || wc -c < "${OUTPUT_FILE}") / 1024 ))"

echo "Snapshot: pre_patch_state.json"
echo "Size: ${FILE_SIZE_KB} KB"
echo "Kernel: ${KERNEL_VAL}"
echo "Reboot required: ${REBOOT_REQUIRED}"
echo "(${PACKAGE_COUNT} packages, ${SERVICE_COUNT} services, ${CONFFILE_COUNT} conffiles)"