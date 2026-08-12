#!/bin/bash
# name: 9-rollback.sh
# purpose: Roll a single package back to the version recorded in
#          pre_patch_state.json, hold it there so unattended-upgrades
#          doesn't immediately re-upgrade it, and re-run Task 5's
#          liveness probes for every affected service to prove the
#          rollback actually restored a working state.
# Project: 2x03 - Patch Equation
# Task:    9 - The Rollback Capability
#
# Usage: sudo ./9-rollback.sh <package>
#
# Exit 0 only if: version was found in the snapshot AND confirmed
# available AND the downgrade succeeded AND the hold succeeded AND every
# affected service that has a defined probe passed it. Exit 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
PRE_STATE_FILE="${SCRIPT_DIR}/pre_patch_state.json"
DEPS_FILE="${SCRIPT_DIR}/service_dependency_map.json"
PROBES_FILE="${SCRIPT_DIR}/service_probes.json"

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq dpkg-query apt-get apt-cache apt-mark systemctl; do need "$c"; done

PACKAGE="${1:-}"
if [[ -z "${PACKAGE}" ]]; then
    echo "Usage: sudo $0 <package>" >&2
    exit 1
fi

[[ -f "${PRE_STATE_FILE}" ]] || fail "pre_patch_state.json not found in ${SCRIPT_DIR} (run the snapshot step first)"
jq empty "${PRE_STATE_FILE}" >/dev/null 2>&1 || fail "pre_patch_state.json is invalid JSON"

# ---------------------------------------------------------------------------
# 2-3. Load the target version; fail clearly if the package isn't tracked
# ---------------------------------------------------------------------------
TARGET_VERSION="$(jq -r --arg p "${PACKAGE}" '.packages[$p] // empty' "${PRE_STATE_FILE}")"

if [[ -z "${TARGET_VERSION}" ]]; then
    echo "[FAIL] '${PACKAGE}' is not present in pre_patch_state.json -- no recorded pre-patch version to roll back to." >&2
    exit 1
fi

echo "[*] Target version from pre_patch_state.json: ${TARGET_VERSION}"

CURRENT_VERSION="$(dpkg-query -W -f='${Version}' -- "${PACKAGE}" 2>/dev/null || true)"

# ---------------------------------------------------------------------------
# 4. Confirm the target version is available -- either already downloaded
#    in the local apt cache, or resolvable via `apt-cache madison`.
# ---------------------------------------------------------------------------
VERSION_AVAILABLE=false

if compgen -G "/var/cache/apt/archives/${PACKAGE}_${TARGET_VERSION//:/%3a}_*.deb" > /dev/null 2>&1; then
    VERSION_AVAILABLE=true
elif apt-cache madison "${PACKAGE}" 2>/dev/null | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}' | grep -qxF "${TARGET_VERSION}"; then
    VERSION_AVAILABLE=true
fi

if [[ "${VERSION_AVAILABLE}" == "true" ]]; then
    echo "[*] Version available in cache or repository: yes"
else
    echo "[*] Version available in cache or repository: no"
    echo "[FAIL] ${TARGET_VERSION} for ${PACKAGE} is not in the local cache and not offered by apt-cache madison -- cannot roll back." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 5. Execute the rollback
# ---------------------------------------------------------------------------
echo -n "[*] Downgrading ${PACKAGE}...                              "

DOWNGRADE_OK=false
if DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
    "${PACKAGE}=${TARGET_VERSION}" > /tmp/.rollback-downgrade-out.$$ 2>&1; then
    DOWNGRADE_OK=true
    echo "OK"
else
    echo "FAILED"
    echo "    $(tail -n 5 /tmp/.rollback-downgrade-out.$$ | tr '\n' ' ')" >&2
fi
rm -f /tmp/.rollback-downgrade-out.$$

# ---------------------------------------------------------------------------
# 6. Hold the package -- only makes sense after an actual successful
#    downgrade; holding a package that's still on the broken version
#    would just lock in the problem.
# ---------------------------------------------------------------------------
HOLD_OK=false
if [[ "${DOWNGRADE_OK}" == "true" ]]; then
    echo -n "[*] apt-mark hold ${PACKAGE}                               "
    if apt-mark hold "${PACKAGE}" > /dev/null 2>&1; then
        HOLD_OK=true
        echo "OK"
    else
        echo "FAILED"
    fi
fi

# ---------------------------------------------------------------------------
# 7. Re-run Task 5's liveness probes for every affected service
# ---------------------------------------------------------------------------
run_http_probe() {
    local url="$1"
    command -v curl >/dev/null 2>&1 || { echo "probe_failed|curl not installed"; return; }
    local code
    code="$(curl -fsS -m 5 -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null)"
    if [[ "${code}" =~ ^2[0-9][0-9]$|^3[0-9][0-9]$ ]]; then
        echo "pass|HTTP ${code} from ${url}"
    else
        echo "probe_failed|HTTP ${code:-no response} from ${url}"
    fi
}

run_mysqladmin_probe() {
    local host="$1" user="$2" password="${3:-}"
    command -v mysqladmin >/dev/null 2>&1 || { echo "probe_failed|mysqladmin not installed"; return; }
    local out
    if [[ -n "${password}" ]]; then
        out="$(mysqladmin ping -h "${host}" -u "${user}" -p"${password}" 2>&1)"
    else
        out="$(mysqladmin ping -h "${host}" -u "${user}" 2>&1)"
    fi
    if grep -qi "mysqld is alive" <<< "${out}"; then
        echo "pass|mysqladmin ping: mysqld is alive"
    else
        echo "probe_failed|mysqladmin ping: ${out}"
    fi
}

run_ssh_probe() {
    local host="$1" port="${2:-22}" user="${3:-probe}"
    command -v ssh >/dev/null 2>&1 || { echo "probe_failed|ssh client not installed"; return; }
    local err
    err="$(ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
              -p "${port}" "${user}@${host}" true 2>&1)"
    local rc=$?
    if [[ ${rc} -eq 0 ]] || grep -qiE "permission denied|host key verification failed" <<< "${err}"; then
        echo "pass|ssh server responded on ${host}:${port}"
    else
        echo "probe_failed|ssh -o BatchMode=yes: ${err}"
    fi
}

run_tcp_probe() {
    local host="$1" port="$2"
    if timeout 5 bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null; then
        echo "pass|tcp connect to ${host}:${port} succeeded"
    else
        echo "probe_failed|tcp connect to ${host}:${port} failed"
    fi
}

echo "[*] Re-running probes for affected services..."

PROBES_ALL_PASS=true
ANY_PROBE_RUN=false

if [[ -f "${DEPS_FILE}" ]]; then
    DEPS_ARRAY="$(jq -s '.' "${DEPS_FILE}" 2>/dev/null || echo '[]')"
    AFFECTED_SERVICES="$(jq -r --arg pkg "${PACKAGE}" \
        '.[] | select((.linked_packages // []) | index($pkg) != null) | .service' \
        <<< "${DEPS_ARRAY}" | sort -u)"
else
    AFFECTED_SERVICES=""
fi

PROBES_JSON='{}'
[[ -f "${PROBES_FILE}" ]] && PROBES_JSON="$(cat "${PROBES_FILE}")"

if [[ -z "${AFFECTED_SERVICES}" ]]; then
    echo "    (no service in service_dependency_map.json links to ${PACKAGE})"
fi

while IFS= read -r svc; do
    [[ -n "${svc}" ]] || continue

    probe_def="$(jq -c --arg s "${svc}" '.[$s] // empty' <<< "${PROBES_JSON}")"
    if [[ -z "${probe_def}" ]]; then
        printf '    %-45s %s\n' "${svc} probe" "NO PROBE DEFINED"
        continue
    fi

    ptype="$(jq -r '.type // ""' <<< "${probe_def}")"
    result=""
    case "${ptype}" in
        http)
            url="$(jq -r '.url // ""' <<< "${probe_def}")"
            result="$(run_http_probe "${url}")"
            ;;
        mysqladmin)
            host="$(jq -r '.host // "127.0.0.1"' <<< "${probe_def}")"
            user="$(jq -r '.user // "root"' <<< "${probe_def}")"
            pass="$(jq -r '.password // ""' <<< "${probe_def}")"
            result="$(run_mysqladmin_probe "${host}" "${user}" "${pass}")"
            ;;
        ssh)
            host="$(jq -r '.host // "127.0.0.1"' <<< "${probe_def}")"
            port="$(jq -r '.port // 22' <<< "${probe_def}")"
            user="$(jq -r '.user // "probe"' <<< "${probe_def}")"
            result="$(run_ssh_probe "${host}" "${port}" "${user}")"
            ;;
        tcp)
            host="$(jq -r '.host // "127.0.0.1"' <<< "${probe_def}")"
            port="$(jq -r '.port // ""' <<< "${probe_def}")"
            result="$(run_tcp_probe "${host}" "${port}")"
            ;;
        *)
            result="probe_failed|unknown probe type '${ptype}'"
            ;;
    esac

    ANY_PROBE_RUN=true
    status="${result%%|*}"
    if [[ "${status}" == "pass" ]]; then
        printf '    %-45s %s\n' "${svc} probe" "PASS"
    else
        printf '    %-45s %s\n' "${svc} probe" "FAIL (${result#*|})"
        PROBES_ALL_PASS=false
    fi
done <<< "${AFFECTED_SERVICES}"

# ---------------------------------------------------------------------------
# 8. Summary + exit code
# ---------------------------------------------------------------------------
OVERALL_OK=false
if [[ "${DOWNGRADE_OK}" == "true" && "${HOLD_OK}" == "true" && "${PROBES_ALL_PASS}" == "true" ]]; then
    OVERALL_OK=true
fi

if [[ "${OVERALL_OK}" == "true" ]]; then
    echo "ROLLBACK: success"
else
    echo "ROLLBACK: failed"
fi
echo "from ${CURRENT_VERSION:-unknown} to ${TARGET_VERSION}"

[[ "${OVERALL_OK}" == "true" ]] && exit 0
exit 1