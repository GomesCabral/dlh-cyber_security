#!/bin/bash
# name: 2-pre_patch_snapshot.sh
# purpose: Capture the pre-patch baseline snapshot that Tasks 5, 6, and 9
#          read: every installed package's version, every active
#          service's state, every listening socket, and a SHA-256 per
#          conffile. Pure read-only capture -- always safe to re-run.
# Project: 2x03 - Patch Equation
# Task:    2 - The Pre-Patch State Snapshot
#
# This closes a gap in the numbered task sequence: Tasks 0, 1, 3, 4, 5, 6,
# 7, 8, 9, 10, 11, 12 were already built and all consume
# pre_patch_state.json; Task 2, the script that actually produces it, had
# not been requested yet. It is built now because Task 13's pipeline
# requires it as an explicit stage.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
OUTPUT_FILE="${SCRIPT_DIR}/pre_patch_state.json"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq dpkg-query systemctl sha256sum readlink awk sed grep date; do need "$c"; done
HAVE_SS=0
command -v ss >/dev/null 2>&1 && HAVE_SS=1
[[ "${HAVE_SS}" -eq 0 ]] && echo "[WARN] 'ss' not found -- listening sockets will be empty" >&2

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

CAPTURED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ---------------------------------------------------------------------------
# packages: every installed package -> its currently installed version
# ---------------------------------------------------------------------------
PACKAGES_JSON="$(
    dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' 2>/dev/null \
    | awk '$3=="install" && $4=="ok" && $5=="installed" {print $1, $2}' \
    | jq -Rsc '
        split("\n") | map(select(length > 0) | split(" ")) |
        map({(.[0]): .[1]}) | add // {}
      '
)"

# ---------------------------------------------------------------------------
# services: every active systemd service -> its state
# ---------------------------------------------------------------------------
SERVICES_FILE="${TMP_DIR}/services.jsonl"
: > "${SERVICES_FILE}"

while IFS= read -r svc; do
    [[ -n "${svc}" ]] || continue
    active="$(systemctl is-active "${svc}" 2>/dev/null)"
    [[ -z "${active}" ]] && active="unknown"
    sub="$(systemctl show -p SubState --value "${svc}" 2>/dev/null)"
    [[ -z "${sub}" ]] && sub="unknown"
    jq -cn --arg service "${svc}" --arg active_state "${active}" --arg sub_state "${sub}" \
      '{service:$service, active_state:$active_state, sub_state:$sub_state}' >> "${SERVICES_FILE}"
done < <(systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | awk '{print $1}')

SERVICES_JSON="$(jq -cs '.' "${SERVICES_FILE}" 2>/dev/null || echo '[]')"

# ---------------------------------------------------------------------------
# listening: every listening TCP/UDP socket, best-effort mapped to a
# systemd unit via the owning process's PID -> cgroup.
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
        # scanning every field for one matching IP:PORT or *:PORT, rather than
        # trusting a fixed column index.
        port=""
        for tok in ${line}; do
            if [[ "${tok}" =~ ^[^[:space:]]*:([0-9]+)$ ]]; then
                candidate="${BASH_REMATCH[1]}"
                # Skip the peer address column, which for LISTEN sockets is
                # always the wildcard "*:*" and never matches this pattern
                # anyway -- the first IP:PORT-shaped token is the local one.
                port="${candidate}"
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

LISTENING_JSON="$(jq -cs 'unique_by([.port, .proto])' "${LISTENING_FILE}" 2>/dev/null || echo '[]')"

# ---------------------------------------------------------------------------
# conffile_hashes: every conffile of every installed package, SHA-256'd
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

CONFFILES_JSON="$(jq -cs 'unique_by(.path)' "${CONFFILES_FILE}" 2>/dev/null || echo '[]')"

# ---------------------------------------------------------------------------
# Emit pre_patch_state.json
# ---------------------------------------------------------------------------
jq -n \
  --arg captured_at "${CAPTURED_AT}" \
  --argjson packages "${PACKAGES_JSON}" \
  --argjson services "${SERVICES_JSON}" \
  --argjson listening "${LISTENING_JSON}" \
  --argjson conffile_hashes "${CONFFILES_JSON}" \
  '{
     captured_at: $captured_at,
     packages: $packages,
     services: $services,
     listening: $listening,
     conffile_hashes: $conffile_hashes
   }' > "${OUTPUT_FILE}"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "pre_patch_state.json is invalid JSON"

echo "[*] Snapshot captured: $(jq '.packages | length' "${OUTPUT_FILE}") packages, $(jq '.services | length' "${OUTPUT_FILE}") active services, $(jq '.listening | length' "${OUTPUT_FILE}") listening sockets, $(jq '.conffile_hashes | length' "${OUTPUT_FILE}") conffiles"
echo "Report saved to: pre_patch_state.json"
