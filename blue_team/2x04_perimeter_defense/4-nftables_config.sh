#!/bin/bash

set -euo pipefail

RULES_FILE="segmentation_rules.json"
OUTPUT_FILE="nftables.conf"
LOCAL_ZONE="${LOCAL_ZONE:-INTERNAL}"
APPLY_RULESET=false
PRECHANGE_JSON="nft_prechange_state.json"
VALIDATION_JSON="nft_postchange_validation.json"
RULE_NUMBER=0
TEMP_FILE=""
ROLLBACK_FILE=""
RULESET_APPLIED=false

# Named sets are rendered for every zone: DMZ, INTERNAL, MGMT and MEDDEV.
# The resulting names are dmz_zone, internal_zone, mgmt_zone and meddev_zone.

usage() {
    printf '%s\n' \
        'Usage: ./4-nftables_config.sh [--rules FILE] [--output FILE]' \
        '       [--local-zone ZONE] [--apply]'
}

require_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Error: required command not found: %s\n' "$command_name" >&2
        exit 1
    fi
}

cleanup() {
    if [[ -n "$TEMP_FILE" && -e "$TEMP_FILE" ]]; then
        rm -f -- "$TEMP_FILE"
    fi
}

rollback_on_error() {
    local exit_code=$?

    if [[ "$RULESET_APPLIED" == true && -n "$ROLLBACK_FILE" && -r "$ROLLBACK_FILE" ]]; then
        printf 'Verification failed; restoring %s\n' "$ROLLBACK_FILE" >&2
        nft -f "$ROLLBACK_FILE" || printf 'Automatic rollback failed. Restore manually.\n' >&2
    fi

    exit "$exit_code"
}

zone_set_name() {
    local zone_name="$1"

    printf '%s_zone\n' "${zone_name,,}"
}

escape_comment() {
    local comment_text="$1"

    comment_text="${comment_text//\\/\\\\}"
    comment_text="${comment_text//\"/\\\"}"
    printf '%s\n' "$comment_text"
}

emit_rule() {
    local rule_text="$1"
    local description="${2:-}"
    local rule_comment=""

    RULE_NUMBER=$((RULE_NUMBER + 1))
    rule_comment="$(printf 'md_rule_%03d' "$RULE_NUMBER")"
    if [[ -n "$description" ]]; then
        rule_comment="$rule_comment | $(escape_comment "$description")"
    fi
    printf '        %s comment "%s"\n' "$rule_text" "$rule_comment" >> "$TEMP_FILE"
}

host_expression() {
    local flow_json="$1"
    local field_name="$2"
    local direction="$3"
    local addresses=""

    addresses="$(jq -r --arg field "$field_name" '
        [.[$field] // [] | .[] | .ip] | join(", ")
    ' <<< "$flow_json")"

    if [[ -n "$addresses" ]]; then
        printf 'ip %saddr { %s }' "$direction" "$addresses"
    fi
}

zone_expression() {
    local zone_name="$1"
    local direction="$2"

    if [[ "$zone_name" == "ALL" ]]; then
        return 0
    fi

    printf 'ip %saddr @%s' "$direction" "$(zone_set_name "$zone_name")"
}

flow_rule_expression() {
    local flow_json="$1"
    local include_destination="$2"
    local source_zone=""
    local destination_zone=""
    local protocol=""
    local destination_port=""
    local source_expression=""
    local destination_expression=""
    local expression=""

    source_zone="$(jq -r '.src_zone' <<< "$flow_json")"
    destination_zone="$(jq -r '.dst_zone' <<< "$flow_json")"
    protocol="$(jq -r '.proto' <<< "$flow_json")"
    destination_port="$(jq -r '.dport' <<< "$flow_json")"

    source_expression="$(host_expression "$flow_json" src_hosts s)"
    if [[ -z "$source_expression" ]]; then
        source_expression="$(zone_expression "$source_zone" s)"
    fi

    if [[ "$include_destination" == true ]]; then
        destination_expression="$(host_expression "$flow_json" dst_hosts d)"
        if [[ -z "$destination_expression" && "$destination_zone" != "INTERNET" ]]; then
            destination_expression="$(zone_expression "$destination_zone" d)"
        fi
    fi

    expression="$source_expression"
    if [[ -n "$destination_expression" ]]; then
        expression="${expression:+$expression }$destination_expression"
    fi
    expression="${expression:+$expression }$protocol dport $destination_port accept"
    printf '%s\n' "$expression"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rules)
            RULES_FILE="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --local-zone)
            LOCAL_ZONE="${2^^}"
            shift 2
            ;;
        --apply)
            APPLY_RULESET=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            printf 'Error: unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

require_command jq
require_command mktemp
require_command date
require_command hostname

if [[ ! -r "$RULES_FILE" ]]; then
    printf 'Error: cannot read segmentation contract: %s\n' "$RULES_FILE" >&2
    exit 1
fi

jq -e '
    (.zones | type == "array" and length == 4)
    and (.flows | type == "array")
    and all(.zones[]; has("name") and has("cidr"))
' "$RULES_FILE" >/dev/null

if ! jq -e --arg zone "$LOCAL_ZONE" '.zones | any(.name == $zone)' "$RULES_FILE" >/dev/null; then
    printf 'Error: local zone is not defined: %s\n' "$LOCAL_ZONE" >&2
    exit 1
fi

TEMP_FILE="$(mktemp)"
trap cleanup EXIT

printf '%s\n' \
    '#!/usr/sbin/nft -f' \
    '# Generated from segmentation_rules.json by 4-nftables_config.sh.' \
    '# Denied packets are logged through the kernel logger and normally appear' \
    '# in /var/log/ufw.log or /var/log/syslog, depending on logger configuration.' \
    '' \
    'flush ruleset' \
    '' \
    'table inet meddefense {' > "$TEMP_FILE"

mapfile -t ZONES < <(jq -c '.zones[]' "$RULES_FILE")
for zone_json in "${ZONES[@]}"; do
    zone_name="$(jq -r '.name' <<< "$zone_json")"
    zone_cidr="$(jq -r '.cidr' <<< "$zone_json")"
    set_name="$(zone_set_name "$zone_name")"
    printf '    set %s {\n' "$set_name" >> "$TEMP_FILE"
    printf '%s\n' \
        '        type ipv4_addr' \
        '        flags interval' >> "$TEMP_FILE"
    printf '        elements = { %s }\n' "$zone_cidr" >> "$TEMP_FILE"
    printf '%s\n' '    }' '' >> "$TEMP_FILE"
done

printf '%s\n' \
    '    set trusted_zones {' \
    '        type ipv4_addr' \
    '        flags interval' >> "$TEMP_FILE"
printf '        elements = { %s }\n' "$(jq -r '[.zones[].cidr] | join(", ")' "$RULES_FILE")" >> "$TEMP_FILE"
printf '%s\n' '    }' '' >> "$TEMP_FILE"

printf '%s\n' \
    '    chain input {' \
    '        type filter hook input priority 0; policy drop;' >> "$TEMP_FILE"
emit_rule 'ct state established,related accept'
emit_rule 'iifname "lo" accept'
emit_rule 'ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept'
emit_rule 'ip6 nexthdr ipv6-icmp icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, nd-neighbor-solicit, nd-neighbor-advert } accept'

mapfile -t LOCAL_FLOWS < <(jq -c --arg zone "$LOCAL_ZONE" '
    .flows[] | select(.action == "allow" and .dst_zone == $zone)
' "$RULES_FILE")
for flow_json in "${LOCAL_FLOWS[@]}"; do
    emit_rule \
        "$(flow_rule_expression "$flow_json" false)" \
        "$(jq -r '.justification' <<< "$flow_json")"
done
emit_rule 'log prefix "MEDDEFENSE_INPUT_DROP " flags all counter drop'
printf '%s\n' '    }' '' >> "$TEMP_FILE"

printf '%s\n' \
    '    chain forward {' \
    '        type filter hook forward priority 0; policy drop;' >> "$TEMP_FILE"
emit_rule 'ct state established,related accept'

mapfile -t CROSS_ZONE_FLOWS < <(jq -c '
    .flows[] | select(.action == "allow" and .src_zone != .dst_zone)
' "$RULES_FILE")
for flow_json in "${CROSS_ZONE_FLOWS[@]}"; do
    emit_rule \
        "$(flow_rule_expression "$flow_json" true)" \
        "$(jq -r '.justification' <<< "$flow_json")"
done
emit_rule 'log prefix "MEDDEFENSE_FORWARD_DROP " flags all counter drop'
printf '%s\n' '    }' '' >> "$TEMP_FILE"

printf '%s\n' \
    '    chain output {' \
    '        type filter hook output priority 0; policy accept;' >> "$TEMP_FILE"

mapfile -t LOCAL_OUTPUT_ALLOWS < <(jq -c --arg zone "$LOCAL_ZONE" '
    .flows[] | select(.action == "allow" and (.src_zone == $zone or .src_zone == "ALL"))
' "$RULES_FILE")
for flow_json in "${LOCAL_OUTPUT_ALLOWS[@]}"; do
    emit_rule \
        "$(flow_rule_expression "$flow_json" true)" \
        "$(jq -r '.justification' <<< "$flow_json")"
done

mapfile -t LOCAL_DENIES < <(jq -c --arg zone "$LOCAL_ZONE" '
    .flows[] | select(.action == "deny_all" and .src_zone == $zone)
' "$RULES_FILE")
for flow_json in "${LOCAL_DENIES[@]}"; do
    destination_zone="$(jq -r '.dst_zone' <<< "$flow_json")"
    if [[ "$destination_zone" == "INTERNET" ]]; then
        emit_rule 'ip daddr != @trusted_zones log prefix "MEDDEFENSE_OUTPUT_DROP " flags all counter drop'
    elif jq -e --arg zone "$destination_zone" '.zones | any(.name == $zone)' "$RULES_FILE" >/dev/null; then
        emit_rule "ip daddr @$(zone_set_name "$destination_zone") log prefix \"MEDDEFENSE_OUTPUT_DROP \" flags all counter drop"
    fi
done
printf '%s\n' '    }' '}' >> "$TEMP_FILE"

mv -- "$TEMP_FILE" "$OUTPUT_FILE"
TEMP_FILE=""
EXPECTED_RULE_COUNT="$(grep -c 'comment "md_rule_' "$OUTPUT_FILE")"

printf 'Rendered %s with %s expected rules for local zone %s.\n' \
    "$OUTPUT_FILE" "$EXPECTED_RULE_COUNT" "$LOCAL_ZONE"

if command -v nft >/dev/null 2>&1; then
    # Check-only parse before any firewall change.
    nft -c -f "$OUTPUT_FILE"
    printf 'Check-only validation passed: nft -c -f %s\n' "$OUTPUT_FILE"
elif [[ "$APPLY_RULESET" == true ]]; then
    printf 'Error: nft is required for --apply.\n' >&2
    exit 1
else
    printf 'Warning: nft is unavailable; check-only validation was skipped.\n' >&2
fi

if [[ "$APPLY_RULESET" != true ]]; then
    printf 'Render-only mode. Review the file, then use sudo ./4-nftables_config.sh --apply.\n'
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    printf 'Error: --apply must be run as root.\n' >&2
    exit 1
fi

require_command nft
require_command install

BACKUP_DIR="/var/backups"
install -d -m 0700 "$BACKUP_DIR"
TIMESTAMP="$(date --utc +'%Y%m%dT%H%M%SZ')"
ROLLBACK_FILE="$BACKUP_DIR/nftables-rollback-$TIMESTAMP.nft"

# Required rollback capture: nft list ruleset > /var/backups/nftables-rollback-<timestamp>.nft
nft list ruleset > "$ROLLBACK_FILE"
TEMP_ROLLBACK="$(mktemp)"
printf 'flush ruleset\n' > "$TEMP_ROLLBACK"
cat "$ROLLBACK_FILE" >> "$TEMP_ROLLBACK"
mv -- "$TEMP_ROLLBACK" "$ROLLBACK_FILE"
chmod 0600 "$ROLLBACK_FILE"

CURRENT_RULESET="$(nft list ruleset)"
jq -n \
    --arg timestamp "$(date --utc +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg hostname "$(hostname --fqdn 2>/dev/null || hostname)" \
    --arg local_zone "$LOCAL_ZONE" \
    --arg rollback_file "$ROLLBACK_FILE" \
    --arg ruleset "$CURRENT_RULESET" \
    --argjson rule_count "$(grep -c 'comment "md_rule_' <<< "$CURRENT_RULESET" || true)" '
    {
        timestamp: $timestamp,
        hostname: $hostname,
        local_zone: $local_zone,
        rollback_file: $rollback_file,
        previous_rule_count: $rule_count,
        previous_ruleset: $ruleset
    }
' > "$PRECHANGE_JSON"

trap rollback_on_error ERR

# Atomic application: nft -f nftables.conf
nft -f "$OUTPUT_FILE"
RULESET_APPLIED=true

LOADED_RULESET="$(nft list ruleset)"
# Verify the loaded ruleset by comparing the expected rule count with the
# actual rule count returned after the atomic load.
ACTUAL_RULE_COUNT="$(grep -c 'comment "md_rule_' <<< "$LOADED_RULESET" || true)"

jq -n \
    --arg timestamp "$(date --utc +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg hostname "$(hostname --fqdn 2>/dev/null || hostname)" \
    --arg local_zone "$LOCAL_ZONE" \
    --arg rollback_file "$ROLLBACK_FILE" \
    --argjson expected_rule_count "$EXPECTED_RULE_COUNT" \
    --argjson actual_rule_count "$ACTUAL_RULE_COUNT" \
    --arg ruleset "$LOADED_RULESET" '
    {
        timestamp: $timestamp,
        hostname: $hostname,
        local_zone: $local_zone,
        rollback_file: $rollback_file,
        expected_rule_count: $expected_rule_count,
        actual_rule_count: $actual_rule_count,
        counts_match: ($expected_rule_count == $actual_rule_count),
        status: (if $expected_rule_count == $actual_rule_count then "passed" else "failed" end),
        loaded_ruleset: $ruleset
    }
' > "$VALIDATION_JSON"

if [[ "$ACTUAL_RULE_COUNT" -ne "$EXPECTED_RULE_COUNT" ]]; then
    printf 'Error: expected %s rules but loaded %s.\n' \
        "$EXPECTED_RULE_COUNT" "$ACTUAL_RULE_COUNT" >&2
    false
fi

RULESET_APPLIED=false
trap - ERR

printf 'Applied and verified %s rules.\n' "$ACTUAL_RULE_COUNT"
printf 'Rollback file: %s\n' "$ROLLBACK_FILE"
printf 'Evidence: %s and %s\n' "$PRECHANGE_JSON" "$VALIDATION_JSON"