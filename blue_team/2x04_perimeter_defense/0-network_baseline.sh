#!/bin/bash

set -euo pipefail

OUTPUT_FILE="${1:-network_baseline.json}"

require_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Error: required command not found: %s\n' "$command_name" >&2
        exit 1
    fi
}

cleanup() {
    rm -rf -- "$TEMP_DIR"
}

parse_ss_file() {
    local input_file="$1"

    jq -R -s '
        def endpoint:
            if test("^\\[.*\\]:[^:]+$") then
                capture("^\\[(?<address>.*)\\]:(?<port>[^:]+)$")
            elif test(".*:[^:]+$") then
                capture("^(?<address>.*):(?<port>[^:]+)$")
            else
                {address: ., port: null}
            end;

        def owner:
            if . == "" then
                {process: null, pid: null, details: null}
            else
                {
                    process: (try capture("\"(?<name>[^\"]+)\"").name catch null),
                    pid: (try (capture("pid=(?<pid>[0-9]+)").pid | tonumber) catch null),
                    details: .
                }
            end;

        split("\n")
        | map(select(length > 0))
        | map(
            capture("^(?<protocol>\\S+)\\s+(?<state>\\S+)\\s+(?<recv_q>\\S+)\\s+(?<send_q>\\S+)\\s+(?<local>\\S+)\\s+(?<peer>\\S+)(?:\\s+(?<owner>.*))?$")
            | (.owner // "") as $owner
            | {
                protocol: .protocol,
                state: .state,
                receive_queue: (try (.recv_q | tonumber) catch .recv_q),
                send_queue: (try (.send_q | tonumber) catch .send_q),
                local: (.local | endpoint),
                peer: (.peer | endpoint)
            } + ($owner | owner)
        )
    ' "$input_file"
}

require_command ip
require_command ss
require_command jq
require_command hostname
require_command date
require_command mktemp

TEMP_DIR="$(mktemp -d)"
trap cleanup EXIT

INTERFACES_RAW="$TEMP_DIR/interfaces.json"
ROUTES_RAW="$TEMP_DIR/routes.json"
NEIGHBORS_RAW="$TEMP_DIR/neighbors.json"
LISTENING_RAW="$TEMP_DIR/listening.txt"
ESTABLISHED_RAW="$TEMP_DIR/established.txt"
DNS_RAW="$TEMP_DIR/dns.json"

# Active interfaces: retain interface name, MAC address, link state and addresses.
ip -j addr show > "$INTERFACES_RAW"

# Routes: retain every route, including the default gateway.
ip -j route show table all > "$ROUTES_RAW"

# ARP/neighbor table: retain neighbor IP, MAC address and reachability state.
ip -j neigh show > "$NEIGHBORS_RAW"

# Listening TCP/UDP sockets and established TCP connections with process name and PID ownership.
ss -tulnpH > "$LISTENING_RAW"
ss -tnpH state established > "$ESTABLISHED_RAW"

INTERFACES_JSON="$(jq '
    map(select(.operstate == "UP" or .ifname == "lo"))
    | map({
        name: .ifname,
        mac: (.address // null),
        link_state: (.operstate // "UNKNOWN"),
        mtu: (.mtu // null),
        addresses: [
            (.addr_info // [])[]
            | {
                family: .family,
                address: .local,
                prefix_length: .prefixlen,
                scope: .scope
            }
        ]
    })
' "$INTERFACES_RAW")"

ROUTES_JSON="$(jq '
    map({
        destination: (.dst // "default"),
        gateway: (.gateway // null),
        device: (.dev // null),
        preferred_source: (.prefsrc // null),
        protocol: (.protocol // null),
        scope: (.scope // null),
        metric: (.metric // null),
        table: (.table // "main")
    })
' "$ROUTES_RAW")"

NEIGHBORS_JSON="$(jq '
    map({
        ip: .dst,
        mac: (.lladdr // null),
        device: (.dev // null),
        state: ((.state // []) | if type == "array" then join(",") else . end)
    })
' "$NEIGHBORS_RAW")"

LISTENING_JSON="$(parse_ss_file "$LISTENING_RAW")"
ESTABLISHED_JSON="$(parse_ss_file "$ESTABLISHED_RAW")"

RESOLV_CONF_JSON="$(jq -R -s '
    split("\n")
    | map(select(test("^[[:space:]]*nameserver[[:space:]]+")))
    | map(capture("^[[:space:]]*nameserver[[:space:]]+(?<address>[^[:space:]#]+)").address)
' /etc/resolv.conf)"

RESOLVECTL_ACTIVE=false
RESOLVECTL_STATUS=""
if command -v systemctl >/dev/null 2>&1 \
    && systemctl is-active --quiet systemd-resolved 2>/dev/null \
    && command -v resolvectl >/dev/null 2>&1; then
    RESOLVECTL_ACTIVE=true
    RESOLVECTL_STATUS="$(resolvectl status --no-pager 2>/dev/null || true)"
fi

jq -n \
    --argjson resolv_conf "$RESOLV_CONF_JSON" \
    --argjson systemd_resolved_active "$RESOLVECTL_ACTIVE" \
    --arg resolvectl_status "$RESOLVECTL_STATUS" \
    '{
        resolv_conf_nameservers: $resolv_conf,
        systemd_resolved_active: $systemd_resolved_active,
        resolvectl_status: (if $resolvectl_status == "" then null else $resolvectl_status end)
    }' > "$DNS_RAW"

jq -n \
    --arg timestamp "$(date --utc +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg hostname "$(hostname --fqdn 2>/dev/null || hostname)" \
    --argjson interfaces "$INTERFACES_JSON" \
    --argjson routes "$ROUTES_JSON" \
    --argjson neighbors "$NEIGHBORS_JSON" \
    --argjson listening_sockets "$LISTENING_JSON" \
    --argjson established_connections "$ESTABLISHED_JSON" \
    --slurpfile dns_resolvers "$DNS_RAW" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        interfaces: $interfaces,
        routes: $routes,
        neighbors: $neighbors,
        listening_sockets: $listening_sockets,
        established_connections: $established_connections,
        dns_resolvers: $dns_resolvers[0]
    }' > "$OUTPUT_FILE"

printf 'Network baseline written to %s\n' "$OUTPUT_FILE"
printf 'Active interfaces: %s\n' "$(jq '.interfaces | length' "$OUTPUT_FILE")"
printf 'Listening sockets: %s\n' "$(jq '.listening_sockets | length' "$OUTPUT_FILE")"
printf 'Established connections: %s\n' "$(jq '.established_connections | length' "$OUTPUT_FILE")"