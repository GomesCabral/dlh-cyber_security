#!/bin/bash
# name: 5-post_patch_validate.sh
# purpose: Prove that every critical service is running, listening on its
#          expected port, and responding correctly after a patch run, by
#          comparing live system state against the pre-patch baseline
#          captured in pre_patch_state.json.
# Project: 2x03 - Patch Equation
# Task:    5 - The Post-Patch Service Validation
#
# Checks performed:
#   1. service state checks    -- pre_patch_state.json "services" block
#   2. listening socket checks -- pre_patch_state.json "listening" block,
#      verified against `ss -tulnp`
#   3. critical liveness probes -- service_dependency_map.json criticality
#      cross-referenced with service_probes.json (curl / mysqladmin ping /
#      ssh -o BatchMode=yes probes)
#
# Each check is classified pass, regression, or probe_failed.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
PRE_STATE_FILE="${SCRIPT_DIR}/pre_patch_state.json"
DEPS_FILE="${SCRIPT_DIR}/service_dependency_map.json"
PROBES_FILE="${SCRIPT_DIR}/service_probes.json"
OUTPUT_FILE="${SCRIPT_DIR}/post_patch_validation.json"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

fail() { echo "[FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for c in jq systemctl ss awk grep sed; do need "$c"; done

[[ -f "${PRE_STATE_FILE}" ]] || fail "pre_patch_state.json not found in ${SCRIPT_DIR} (run the snapshot step first)"
jq empty "${PRE_STATE_FILE}" >/dev/null 2>&1 || fail "pre_patch_state.json is invalid JSON"

[[ -f "${DEPS_FILE}" ]] || fail "service_dependency_map.json not found in ${SCRIPT_DIR} (run 1-service_deps.sh first)"
if ! DEPS_ARRAY="$(jq -s '.' "${DEPS_FILE}" 2>/dev/null)"; then
    fail "service_dependency_map.json contains invalid JSON"
fi

if [[ -f "${PROBES_FILE}" ]]; then
    jq empty "${PROBES_FILE}" >/dev/null 2>&1 || fail "service_probes.json is invalid JSON"
    PROBES_JSON="$(cat "${PROBES_FILE}")"
else
    echo "[WARN] service_probes.json not found -- no liveness probes will run" >&2
    PROBES_JSON='{}'
fi

DETAILS_FILE="${TMP_DIR}/details.jsonl"
: > "${DETAILS_FILE}"

add_detail() {
    # add_detail <check_type> <name> <status> <expected> <actual> <detail_msg>
    jq -cn \
      --arg check_type "$1" --arg name "$2" --arg status "$3" \
      --arg expected "$4" --arg actual "$5" --arg detail "$6" \
      '{check_type:$check_type, name:$name, status:$status,
        expected:$expected, actual:$actual, detail:$detail}' >> "${DETAILS_FILE}"
}

# ---------------------------------------------------------------------------
# 1. Service state checks
#    "verify it is in the same ActiveState or better (anything other than
#    active is a regression)" -- taken literally: the only passing current
#    state is "active", regardless of what the pre-patch state was.
# ---------------------------------------------------------------------------
SERVICE_TOTAL=0
SERVICE_PASS=0

while IFS= read -r svc_entry; do
    [[ -n "${svc_entry}" ]] || continue
    svc="$(jq -r '.service' <<< "${svc_entry}")"
    pre_state="$(jq -r '.active_state // "unknown"' <<< "${svc_entry}")"
    [[ -n "${svc}" && "${svc}" != "null" ]] || continue

    SERVICE_TOTAL=$((SERVICE_TOTAL + 1))
    current="$(systemctl is-active "${svc}" 2>/dev/null)"
    [[ -z "${current}" ]] && current="unknown"

    if [[ "${current}" == "active" ]]; then
        add_detail "service_state" "${svc}" "pass" "${pre_state}" "${current}" "service is active"
        SERVICE_PASS=$((SERVICE_PASS + 1))
    else
        add_detail "service_state" "${svc}" "regression" "${pre_state}" "${current}" "service is not active post-patch"
    fi
done < <(jq -c '.services // [] | .[]' "${PRE_STATE_FILE}")

# ---------------------------------------------------------------------------
# 2. Listening socket checks
# ---------------------------------------------------------------------------
LISTEN_TOTAL=0
LISTEN_PASS=0

port_is_listening() {
    local port="$1" proto="${2:-tcp}"
    # A single combined call covers both protocols and includes the owning
    # process, which is useful context even though this check only tests
    # for presence of the port. Column count in `ss` output varies across
    # iproute2 versions (the Netid column is sometimes absent), so rather
    # than trust a fixed field index, every field of every LISTEN line is
    # scanned for one ending exactly in ":PORT" -- robust to that variation
    # and to the extra Process column -p adds.
    ss -tulnp 2>/dev/null | awk -v want="${port}" -v proto="${proto}" '
        $1 ~ ("^" proto) && /LISTEN/ {
            for (i = 1; i <= NF; i++) {
                n = split($i, parts, ":")
                if (n >= 2 && parts[n] == want) { found = 1 }
            }
        }
        END { exit !found }
    '
}

while IFS= read -r sock_entry; do
    [[ -n "${sock_entry}" ]] || continue
    port="$(jq -r '.port' <<< "${sock_entry}")"
    proto="$(jq -r '.proto // "tcp"' <<< "${sock_entry}")"
    label="$(jq -r '.service // ("port " + (.port|tostring))' <<< "${sock_entry}")"
    [[ -n "${port}" && "${port}" != "null" ]] || continue

    LISTEN_TOTAL=$((LISTEN_TOTAL + 1))

    if port_is_listening "${port}" "${proto}"; then
        add_detail "listening_socket" "${label}" "pass" "listening:${port}/${proto}" "listening" "port ${port}/${proto} is listening"
        LISTEN_PASS=$((LISTEN_PASS + 1))
    else
        add_detail "listening_socket" "${label}" "regression" "listening:${port}/${proto}" "not listening" "port ${port}/${proto} is no longer listening"
    fi
done < <(jq -c '.listening // [] | .[]' "${PRE_STATE_FILE}")

# ---------------------------------------------------------------------------
# 3. Critical liveness probes
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

PROBE_TOTAL=0
PROBE_PASS=0

CRITICAL_SERVICES="$(jq -r '.[] | select(.criticality == "critical") | .service' <<< "${DEPS_ARRAY}" | sort -u)"

while IFS= read -r svc; do
    [[ -n "${svc}" ]] || continue

    probe_def="$(jq -c --arg s "${svc}" '.[$s] // empty' <<< "${PROBES_JSON}")"
    if [[ -z "${probe_def}" ]]; then
        # No probe configured for this critical service -- not counted as a
        # check (nothing to run), but surfaced so it isn't silently missed.
        echo "[WARN] no probe defined for critical service ${svc} in service_probes.json" >&2
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

    PROBE_TOTAL=$((PROBE_TOTAL + 1))
    status="${result%%|*}"
    msg="${result#*|}"

    add_detail "liveness_probe" "${svc}" "${status}" "${ptype}" "${status}" "${msg}"
    [[ "${status}" == "pass" ]] && PROBE_PASS=$((PROBE_PASS + 1))

done <<< "${CRITICAL_SERVICES}"

# ---------------------------------------------------------------------------
# 4-5. Emit post_patch_validation.json
# ---------------------------------------------------------------------------
DETAILS_ARRAY="$(jq -cs '.' "${DETAILS_FILE}")"
TOTAL_CHECKS=$((SERVICE_TOTAL + LISTEN_TOTAL + PROBE_TOTAL))
TOTAL_PASSED=$((SERVICE_PASS + LISTEN_PASS + PROBE_PASS))
TOTAL_FAILED=$((TOTAL_CHECKS - TOTAL_PASSED))

jq -n \
  --argjson total_checks "${TOTAL_CHECKS}" \
  --argjson passed "${TOTAL_PASSED}" \
  --argjson failed_count "${TOTAL_FAILED}" \
  --argjson details "${DETAILS_ARRAY}" \
  --argjson service_total "${SERVICE_TOTAL}" --argjson service_pass "${SERVICE_PASS}" \
  --argjson listen_total "${LISTEN_TOTAL}" --argjson listen_pass "${LISTEN_PASS}" \
  --argjson probe_total "${PROBE_TOTAL}" --argjson probe_pass "${PROBE_PASS}" \
  '{
     total_checks:$total_checks,
     passed:$passed,
     failed:$failed_count,
     details:$details,
     categories:{
       service_state: {total:$service_total, passed:$service_pass},
       listening_socket: {total:$listen_total, passed:$listen_pass},
       liveness_probe: {total:$probe_total, passed:$probe_pass}
     }
   }' > "${OUTPUT_FILE}"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "post_patch_validation.json is invalid JSON"

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------
printf 'Service state checks:     %d/%d   %s\n' "${SERVICE_PASS}" "${SERVICE_TOTAL}" \
    "$([[ ${SERVICE_PASS} -eq ${SERVICE_TOTAL} ]] && echo PASS || echo FAIL)"
printf 'Listening socket checks:  %d/%d   %s\n' "${LISTEN_PASS}" "${LISTEN_TOTAL}" \
    "$([[ ${LISTEN_PASS} -eq ${LISTEN_TOTAL} ]] && echo PASS || echo FAIL)"
printf 'Critical liveness probes: %d/%d     %s\n' "${PROBE_PASS}" "${PROBE_TOTAL}" \
    "$([[ ${PROBE_PASS} -eq ${PROBE_TOTAL} ]] && echo PASS || echo FAIL)"

if [[ "${TOTAL_PASSED}" -eq "${TOTAL_CHECKS}" ]]; then
    echo "VERDICT: PASS (${TOTAL_PASSED}/${TOTAL_CHECKS})"
else
    echo "VERDICT: FAIL (${TOTAL_PASSED}/${TOTAL_CHECKS})"
fi
echo "Report saved to: post_patch_validation.json"

[[ "${TOTAL_FAILED}" -eq 0 ]] && exit 0
exit 1