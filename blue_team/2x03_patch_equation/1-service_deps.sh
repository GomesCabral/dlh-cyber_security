#!/bin/bash
# name: 1-service_deps.sh
# purpose: Map each active systemd service to its executable's owning
#          package and every package providing a linked shared library,
#          so a patch to any of those packages tells you which services
#          need a restart / regression test.
# Project: 2x03 - Patch Equation
# Task:    1 - The Service Dependency Map
#
# Notes:
#   - dpkg -S only matches REAL (symlink-resolved) paths. Every path we
#     hand to dpkg -S is first resolved with `readlink -f`.
#   - Emits NDJSON (one JSON object per line) to service_dependency_map.json,
#     matching the task's expected output format (concatenated JSON docs,
#     not a single array).
#   - A service whose executable can't be resolved, or whose owning
#     package can't be found, is still emitted with best-effort fields
#     rather than aborting the whole run -- one bad service must not sink
#     the rest of the inventory.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
CRITICALITY_FILE="${SCRIPT_DIR}/service_criticality.json"
OUTPUT_FILE="${SCRIPT_DIR}/service_dependency_map.json"

log()  { echo "[*] $*"; }
warn() { echo "[WARN] $*" >&2; }
fail() { echo "[FAIL] $*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

for c in systemctl dpkg ldd readlink jq awk sed grep; do
    need "$c"
done

if [[ -f "${CRITICALITY_FILE}" ]]; then
    jq empty "${CRITICALITY_FILE}" >/dev/null 2>&1 || fail "service_criticality.json is invalid JSON"
else
    warn "service_criticality.json not found in ${SCRIPT_DIR} -- all services default to 'low'"
fi

HAVE_NEEDRESTART=0
command -v needrestart >/dev/null 2>&1 && HAVE_NEEDRESTART=1

: > "${OUTPUT_FILE}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Resolve a path to the dpkg package that owns it. Always resolves symlinks
# first, since dpkg -S only indexes real paths. Handles the ":arch" suffix
# and multi-package ("pkg1, pkg2: /path") diversion output by taking the
# first package name. Prints nothing (empty) if no package owns the path.
owning_package() {
    local path="$1"
    [[ -n "${path}" ]] || return 0

    local real
    real="$(readlink -f -- "${path}" 2>/dev/null)"
    [[ -n "${real}" ]] || real="${path}"

    local line
    line="$(dpkg -S -- "${real}" 2>/dev/null | head -1)"
    [[ -n "${line}" ]] || return 0

    # line looks like: "pkg1:amd64, pkg2: /real/path"
    local pkgs="${line%%: *}"
    local first="${pkgs%%,*}"
    first="${first#"${first%%[![:space:]]*}"}"   # ltrim
    first="${first%%[[:space:]]*}"                # rtrim (no embedded spaces expected)
    first="${first%%:*}"                          # strip :arch suffix
    printf '%s' "${first}"
}

# Resolve the executable path for a systemd service, preferring the
# ExecStart= unit directive, falling back to MainPID -> /proc/<pid>/exe.
resolve_exec_path() {
    local unit="$1"
    local raw path

    raw="$(systemctl show -p ExecStart --value "${unit}" 2>/dev/null)"
    if [[ -n "${raw}" && "${raw}" != "{ path= ; }" ]]; then
        path="$(printf '%s' "${raw}" | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -1)"
    fi

    if [[ -z "${path:-}" || "${path}" == "(null)" ]]; then
        local pid
        pid="$(systemctl show -p MainPID --value "${unit}" 2>/dev/null)"
        if [[ -n "${pid}" && "${pid}" != "0" ]]; then
            path="$(readlink -f "/proc/${pid}/exe" 2>/dev/null)"
        fi
    fi

    printf '%s' "${path:-}"
}

# List every shared library path a binary links against (skips vdso/linker
# pseudo-entries with no real path, and unresolved "not found" deps).
get_linked_lib_paths() {
    local exec="$1"
    ldd "${exec}" 2>/dev/null | awk '
        /=>/    { if ($3 ~ /^\//) print $3; next }
        $1 ~ /^\// { print $1 }
    '
    return 0
}

# Criticality lookup with default "low" when the file/entry is absent.
criticality_for() {
    local svc="$1"
    if [[ -f "${CRITICALITY_FILE}" ]]; then
        jq -r --arg s "${svc}" '.[$s] // "low"' "${CRITICALITY_FILE}" 2>/dev/null || echo "low"
    else
        echo "low"
    fi
}

# ---------------------------------------------------------------------------
# needrestart cross-check (optional): builds a set of service unit names
# that needrestart currently flags as needing a restart (already running
# stale/patched libraries). Used only as a cross-check signal; absence of
# the tool never blocks the run.
# ---------------------------------------------------------------------------
NEEDRESTART_SVCS="$(mktemp)"
trap 'rm -f "${NEEDRESTART_SVCS}"' EXIT

if [[ "${HAVE_NEEDRESTART}" -eq 1 ]]; then
    needrestart -b 2>/dev/null | awk -F': ' '/^NEEDRESTART-SVC:/ {print $2}' > "${NEEDRESTART_SVCS}" || true
fi

# ---------------------------------------------------------------------------
# 1. Enumerate active service units
# ---------------------------------------------------------------------------
log "Listing active systemd service units..."
UNITS="$(systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | awk '{print $1}')"
UNIT_COUNT="$(printf '%s\n' "${UNITS}" | grep -c . || true)"
echo "    Active service units: ${UNIT_COUNT}"

# ---------------------------------------------------------------------------
# 2-6. Resolve exec path, owning package, linked packages, criticality
# ---------------------------------------------------------------------------
log "Resolving executables and package dependencies..."

while IFS= read -r unit; do
    [[ -n "${unit}" ]] || continue

    exec_path="$(resolve_exec_path "${unit}")"
    if [[ -z "${exec_path}" ]]; then
        warn "Could not resolve executable for ${unit}, skipping"
        continue
    fi

    owning="$(owning_package "${exec_path}")"
    [[ -n "${owning}" ]] || owning="unknown"

    declare -A pkgset=()
    [[ "${owning}" != "unknown" ]] && pkgset["${owning}"]=1

    while IFS= read -r libpath; do
        [[ -n "${libpath}" ]] || continue
        libpkg="$(owning_package "${libpath}")"
        [[ -n "${libpkg}" ]] && pkgset["${libpkg}"]=1
    done < <(get_linked_lib_paths "${exec_path}")

    linked_count="${#pkgset[@]}"
    linked_json='[]'
    if [[ "${linked_count}" -gt 0 ]]; then
        linked_json="$(printf '%s\n' "${!pkgset[@]}" | sort -u | jq -Rsc 'split("\n")|map(select(length>0))')"
    fi

    crit="$(criticality_for "${unit}")"

    # Any active service that links against at least one package (its own,
    # or a shared library) needs a restart when that package is patched,
    # since the running process keeps the old code mapped in memory until
    # restarted. needrestart, when available, is used only as an
    # informational cross-check (not to override this).
    restart_flag=true
    if [[ "${linked_json}" == "[]" ]]; then
        restart_flag=false
    fi

    needrestart_flagged=false
    if [[ "${HAVE_NEEDRESTART}" -eq 1 ]] && grep -qxF "${unit}" "${NEEDRESTART_SVCS}" 2>/dev/null; then
        needrestart_flagged=true
    fi

    jq -cn \
      --arg service "${unit}" \
      --arg exec_path "${exec_path}" \
      --arg owning_package "${owning}" \
      --argjson linked_packages "${linked_json}" \
      --arg criticality "${crit}" \
      --argjson restart_required_on_patch "${restart_flag}" \
      --argjson needrestart_flagged "${needrestart_flagged}" \
      '{
         service:$service,
         exec_path:$exec_path,
         owning_package:$owning_package,
         linked_packages:$linked_packages,
         criticality:$criticality,
         restart_required_on_patch:$restart_required_on_patch,
         needrestart_flagged:$needrestart_flagged
       }' >> "${OUTPUT_FILE}"

    echo "    [${crit}] ${unit} -> ${owning} (${linked_count} linked pkgs resolved)"

    unset pkgset

done <<< "${UNITS}"

# Validate every emitted line is valid JSON (NDJSON check)
if [[ -s "${OUTPUT_FILE}" ]]; then
    while IFS= read -r line; do
        [[ -n "${line}" ]] || continue
        echo "${line}" | jq empty >/dev/null 2>&1 || fail "Emitted invalid JSON line in ${OUTPUT_FILE}"
    done < "${OUTPUT_FILE}"
fi

log "Service dependency map complete."
echo "Report saved to: service_dependency_map.json"