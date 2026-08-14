#!/bin/bash

set -euo pipefail

BASELINE_FILE="${1:-network_baseline.json}"
SERVICE_CATALOG="${2:-service_catalog.json}"
CRITICALITY_CATALOG="${3:-service_criticality.json}"
OUTPUT_FILE="${4:-attack_surface.json}"

require_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Error: required command not found: %s\n' "$command_name" >&2
        exit 1
    fi
}

require_file() {
    local file_path="$1"

    if [[ ! -r "$file_path" ]]; then
        printf 'Error: required input file is not readable: %s\n' "$file_path" >&2
        exit 1
    fi
}

cleanup() {
    rm -rf -- "$TEMP_DIR"
}

catalog_lookup() {
    local catalog_file="$1"
    local result_field="$2"
    local process_name="$3"
    local protocol="$4"
    local port="$5"
    local function_name="$6"
    local default_value="$7"

    jq -r \
        --arg field "$result_field" \
        --arg process "${process_name,,}" \
        --arg proto "${protocol,,}" \
        --arg port "$port" \
        --arg function "${function_name,,}" \
        --arg default "$default_value" '
        def value_from($value):
            if ($value | type) == "string" then $value
            elif ($value | type) == "object" then ($value[$field] // empty)
            else empty
            end;

        def entry_array:
            if type == "array" then .
            elif (.services? | type) == "array" then .services
            elif (.catalog? | type) == "array" then .catalog
            else []
            end;

        def object_lookup:
            if type != "object" then empty
            else
                (
                    .[$process]
                    // .[$function]
                    // .[$proto + "/" + $port]
                    // .[$port]
                    // .services?[$process]
                    // .services?[$function]
                    // .services?[$proto + "/" + $port]
                    // .services?[$port]
                    // empty
                ) | value_from(.)
            end;

        (
            first(
                entry_array[]
                | select(
                    ((.process // .name // .service // "") | ascii_downcase) as $entry_process
                    | ((.function // "") | ascii_downcase) as $entry_function
                    | ((.proto // .protocol // "") | ascii_downcase) as $entry_proto
                    | ((.port // "") | tostring) as $entry_port
                    | ($entry_process == "" or $entry_process == $process)
                    and ($entry_function == "" or $function == "" or $entry_function == $function)
                    and ($entry_proto == "" or $entry_proto == $proto)
                    and ($entry_port == "" or $entry_port == $port)
                )
                | .[$field]
                | select(. != null)
            )
            // object_lookup
            // $default
        )
    ' "$catalog_file"
}

resolve_binary() {
    local process_id="$1"
    local process_name="$2"
    local binary_path=""

    if [[ "$process_id" =~ ^[0-9]+$ ]] && [[ -e "/proc/$process_id/exe" ]]; then
        binary_path="$(readlink -f "/proc/$process_id/exe" 2>/dev/null || true)"
    fi

    if [[ -z "$binary_path" ]] && [[ -n "$process_name" ]]; then
        binary_path="$(command -v "$process_name" 2>/dev/null || true)"
    fi

    printf '%s\n' "$binary_path"
}

resolve_package() {
    local binary_path="$1"
    local package_name="unknown"

    # Resolve the owning Debian package with dpkg -S.
    if [[ -n "$binary_path" ]] && command -v dpkg >/dev/null 2>&1; then
        package_name="$(dpkg -S "$binary_path" 2>/dev/null | head -n 1 | cut -d: -f1 || true)"
        package_name="${package_name:-unknown}"
    fi

    printf '%s\n' "$package_name"
}

resolve_service_unit() {
    local process_id="$1"
    local service_unit=""

    if [[ "$process_id" =~ ^[0-9]+$ ]] && [[ -r "/proc/$process_id/cgroup" ]]; then
        service_unit="$(grep -Eo '[^/]+\.service' "/proc/$process_id/cgroup" | head -n 1 || true)"
    fi

    printf '%s\n' "$service_unit"
}

require_command jq
require_command date
require_command readlink
require_command dpkg
require_command systemctl

require_file "$BASELINE_FILE"
require_file "$SERVICE_CATALOG"
require_file "$CRITICALITY_CATALOG"

jq -e '.hostname and (.listening_sockets | type == "array")' "$BASELINE_FILE" >/dev/null
jq -e . "$SERVICE_CATALOG" >/dev/null
jq -e . "$CRITICALITY_CATALOG" >/dev/null

TEMP_DIR="$(mktemp -d)"
trap cleanup EXIT

SOCKET_METADATA="$TEMP_DIR/socket_metadata.ndjson"
: > "$SOCKET_METADATA"

while IFS= read -r socket; do
    protocol="$(jq -r '.protocol // "unknown"' <<< "$socket")"
    port="$(jq -r '.local.port // "unknown"' <<< "$socket")"
    bind_address="$(jq -r '.local.address // "unknown"' <<< "$socket")"
    process_name="$(jq -r '.process // "unknown"' <<< "$socket")"
    process_id="$(jq -r '.pid // ""' <<< "$socket")"

    binary_path="$(resolve_binary "$process_id" "$process_name")"
    package_name="$(resolve_package "$binary_path")"
    service_unit="$(resolve_service_unit "$process_id")"
    service_details=""

    # Resolve the configured systemd service unit with systemctl show.
    if [[ -n "$service_unit" ]]; then
        service_details="$(systemctl show "$service_unit" \
            --property=Id \
            --property=Description \
            --property=FragmentPath \
            --property=ExecStart \
            --no-pager 2>/dev/null || true)"
    fi

    function_name="$(catalog_lookup \
        "$SERVICE_CATALOG" function "$process_name" "$protocol" "$port" "" unknown)"
    function_name="${function_name,,}"

    criticality="$(catalog_lookup \
        "$CRITICALITY_CATALOG" criticality "$process_name" "$protocol" "$port" \
        "$function_name" low)"
    criticality="${criticality,,}"

    case "$criticality" in
        critical|high|medium|low) ;;
        *) criticality="low" ;;
    esac

    jq -cn \
        --arg proto "$protocol" \
        --arg port "$port" \
        --arg bind_addr "$bind_address" \
        --arg process "$process_name" \
        --arg pid "$process_id" \
        --arg binary "$binary_path" \
        --arg package "$package_name" \
        --arg service_unit "$service_unit" \
        --arg service_details "$service_details" \
        --arg function "$function_name" \
        --arg criticality "$criticality" '
        {
            proto: $proto,
            port: (try ($port | tonumber) catch $port),
            bind_addr: $bind_addr,
            process: $process,
            pid: (if $pid == "" then null else ($pid | tonumber) end),
            binary: (if $binary == "" then null else $binary end),
            package: $package,
            service_unit: (if $service_unit == "" then null else $service_unit end),
            service_details: (if $service_details == "" then null else $service_details end),
            function: $function,
            criticality: $criticality
        }
    ' >> "$SOCKET_METADATA"
done < <(jq -c '.listening_sockets[]' "$BASELINE_FILE")

SOCKETS_JSON="$(jq -s '
    def insecure_flag($function):
        {
            "telnet": "insecure_protocol_telnet",
            "ftp": "insecure_protocol_ftp",
            "snmpv1": "insecure_protocol_snmpv1",
            "snmpv2c": "insecure_protocol_snmpv2c",
            "rlogin": "insecure_protocol_rlogin",
            "nfs v2/v3": "insecure_protocol_nfs_v2_v3"
        }[$function] // empty;

    map(
        . as $socket
        | (
            []
            + (if .bind_addr == "0.0.0.0" and (.function == "database" or .function == "rpc")
               then ["bound_0.0.0.0", (.function + "_exposed")]
               else []
               end)
            + ([insecure_flag(.function)] | map(select(. != null)))
        ) as $flags
        | $socket + {exposure_flags: ($flags | unique)}
    )
' "$SOCKET_METADATA")"

jq -n \
    --arg generated_at "$(date --utc +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg hostname "$(jq -r '.hostname' "$BASELINE_FILE")" \
    --argjson sockets "$SOCKETS_JSON" '
    {
        generated_at: $generated_at,
        hostname: $hostname,
        sockets: $sockets,
        summary: {
            total_sockets: ($sockets | length),
            flagged_sockets: ([$sockets[] | select(.exposure_flags | length > 0)] | length),
            unknown_functions: ([$sockets[] | select(.function == "unknown")] | length),
            flagged_by_severity: {
                critical: ([$sockets[] | select(.criticality == "critical" and (.exposure_flags | length > 0))] | length),
                high: ([$sockets[] | select(.criticality == "high" and (.exposure_flags | length > 0))] | length),
                medium: ([$sockets[] | select(.criticality == "medium" and (.exposure_flags | length > 0))] | length),
                low: ([$sockets[] | select(.criticality == "low" and (.exposure_flags | length > 0))] | length)
            }
        }
    }
' > "$OUTPUT_FILE"

printf 'Attack surface report written to %s\n' "$OUTPUT_FILE"
jq '.summary' "$OUTPUT_FILE"
