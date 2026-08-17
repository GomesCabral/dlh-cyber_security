#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Idempotent package target: apt-get install -y suricata jq
# Provided rules directory: /home/analyst/MedDefense_Lab/suricata/rules/
# Installed rules directory: /var/lib/suricata/rules/
SOURCE_RULE_DIR="/home/analyst/MedDefense_Lab/suricata/rules"
TARGET_RULE_DIR="/var/lib/suricata/rules"
SMOKE_PCAP="/home/analyst/MedDefense_Lab/PCAPs/smoke.pcap"
SMOKE_LOG_DIR="/tmp/suricata-smoke"
CONFIG_FILE="$PROJECT_DIR/suricata.yaml"
PRECHANGE_FILE="$PROJECT_DIR/suricata_prechange_state.json"
OUTPUT_FILE="$PROJECT_DIR/setup_verification.json"

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        printf 'Error: run this script with sudo.\n' >&2
        exit 1
    fi
}

require_command() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Error: required command not found: %s\n' "$command_name" >&2
        exit 1
    fi
}

yaml_quote() {
    local value="$1"
    value="${value//\'/\'\'}"
    printf "'%s'" "$value"
}

capture_prechange_state() {
    local suricata_installed=false
    local jq_installed=false
    local service_state="unavailable"
    local existing_rule_files=0

    command -v suricata >/dev/null 2>&1 && suricata_installed=true
    command -v jq >/dev/null 2>&1 && jq_installed=true
    if [[ -d "$TARGET_RULE_DIR" ]]; then
        existing_rule_files="$(find "$TARGET_RULE_DIR" -maxdepth 1 -type f -name '*.rules' | wc -l)"
    fi
    if command -v systemctl >/dev/null 2>&1; then
        service_state="$(systemctl is-active suricata 2>/dev/null || true)"
        service_state="${service_state:-unknown}"
    fi

    jq -n \
        --arg captured_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --argjson suricata_installed "$suricata_installed" \
        --argjson jq_installed "$jq_installed" \
        --arg service_state "$service_state" \
        --argjson existing_rule_files "$existing_rule_files" \
        '{
            captured_at: $captured_at,
            suricata_installed: $suricata_installed,
            jq_installed: $jq_installed,
            suricata_service_state: $service_state,
            existing_rule_files: $existing_rule_files
        }' > "$PRECHANGE_FILE"
}

install_dependencies() {
    local packages=()

    command -v suricata >/dev/null 2>&1 || packages+=(suricata)
    command -v jq >/dev/null 2>&1 || packages+=(jq)

    if [[ "${#packages[@]}" -gt 0 ]]; then
        printf '[*] Installing: %s\n' "${packages[*]}"
        require_command apt-get
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
    else
        printf '[*] Suricata and jq are already installed.\n'
    fi

    # Offline-only project: ensure package installation did not leave a daemon running.
    if command -v systemctl >/dev/null 2>&1 \
        && systemctl is-active --quiet suricata 2>/dev/null; then
        systemctl stop suricata
    fi
}

copy_rules() {
    local source_file=""
    local target_file=""
    local source_count=0
    local verified_count=0

    if [[ ! -d "$SOURCE_RULE_DIR" ]]; then
        printf 'Error: provided rule directory not found: %s\n' "$SOURCE_RULE_DIR" >&2
        exit 1
    fi

    install -d -m 0755 "$TARGET_RULE_DIR"
    mapfile -d '' SOURCE_RULE_FILES < <(
        find "$SOURCE_RULE_DIR" -maxdepth 1 -type f -name '*.rules' -print0 | sort -z
    )

    source_count="${#SOURCE_RULE_FILES[@]}"
    if [[ "$source_count" -eq 0 ]]; then
        printf 'Error: no .rules files found in %s\n' "$SOURCE_RULE_DIR" >&2
        exit 1
    fi

    for source_file in "${SOURCE_RULE_FILES[@]}"; do
        target_file="$TARGET_RULE_DIR/$(basename -- "$source_file")"
        if [[ ! -f "$target_file" ]] || ! cmp -s -- "$source_file" "$target_file"; then
            install -m 0644 "$source_file" "$target_file"
        fi
        [[ -f "$target_file" ]] && verified_count=$((verified_count + 1))
    done

    if [[ ! -e "$TARGET_RULE_DIR/meddefense.rules" ]]; then
        install -m 0644 /dev/null "$TARGET_RULE_DIR/meddefense.rules"
    fi

    if [[ "$verified_count" -ne "$source_count" ]]; then
        printf 'Error: copied %d of %d provided rule files.\n' \
            "$verified_count" "$source_count" >&2
        exit 1
    fi

    printf '[*] Verified %d provided rule files.\n' "$verified_count"
}

render_configuration() {
    local source_file=""
    local rule_name=""

    {
        printf '%%YAML 1.1\n'
        printf '%s\n' '---'
        printf 'vars:\n'
        printf '  address-groups:\n'
        printf '    HOME_NET: "[10.10.0.0/16]"\n'
        printf '    EXTERNAL_NET: "!$HOME_NET"\n'
        printf 'default-rule-path: /var/lib/suricata/rules\n'
        printf 'rule-files:\n'
        for source_file in "${SOURCE_RULE_FILES[@]}"; do
            rule_name="$(basename -- "$source_file")"
            if [[ "$rule_name" != "meddefense.rules" ]]; then
                printf '  - %s\n' "$(yaml_quote "$rule_name")"
            fi
        done
        printf "  - 'meddefense.rules'\n"
        printf 'default-log-dir: /var/log/suricata\n'
        printf 'outputs:\n'
        printf '  - eve-log:\n'
        printf '      enabled: yes\n'
        printf '      filetype: regular\n'
        printf '      filename: eve.json\n'
        printf '      types:\n'
        printf '        - alert\n'
        printf '        - http\n'
        printf '        - dns\n'
        printf '        - tls\n'
        printf '        - fileinfo\n'
        printf 'pcap-file:\n'
        printf '  enabled: yes\n'
        printf '  checksum-checks: auto\n'
    } > "$CONFIG_FILE"
}

count_active_rules() {
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        /^[[:space:]]*(alert|drop|reject|pass)[[:space:]]/ { count++ }
        END { print count + 0 }
    ' "$TARGET_RULE_DIR"/*.rules
}

write_verification() {
    local installed_version="$1"
    local config_test_exit="$2"
    local smoke_alerts="$3"
    local rule_count="$4"
    local loaded_files_json=""

    loaded_files_json="$(
        printf '%s\0' "${SOURCE_RULE_FILES[@]}" "$TARGET_RULE_DIR/meddefense.rules" |
            xargs -0 -n1 basename -- |
            sort -u |
            jq -R -s 'split("\n") | map(select(length > 0))'
    )"

    jq -n \
        --arg installed_version "$installed_version" \
        --argjson rule_files_loaded "$loaded_files_json" \
        --argjson rule_count "$rule_count" \
        --argjson config_test_exit "$config_test_exit" \
        --arg smoke_pcap "$SMOKE_PCAP" \
        --argjson smoke_alerts "$smoke_alerts" \
        '{
            installed_version: $installed_version,
            rule_files_loaded: $rule_files_loaded,
            rule_count: $rule_count,
            config_test_exit: $config_test_exit,
            smoke_pcap: $smoke_pcap,
            smoke_alerts: $smoke_alerts
        }' > "$OUTPUT_FILE"
}

main() {
    local installed_version=""
    local config_test_exit=1
    local smoke_exit=1
    local smoke_alerts=0
    local rule_count=0

    require_root
    require_command date
    require_command find
    require_command awk
    require_command sort
    require_command install
    require_command cmp
    require_command xargs

    # jq is needed for the mandatory pre-change JSON. Install it first only when absent.
    if ! command -v jq >/dev/null 2>&1; then
        require_command apt-get
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y jq
    fi

    capture_prechange_state
    install_dependencies
    require_command suricata
    require_command jq

    copy_rules
    render_configuration
    rule_count="$(count_active_rules)"
    installed_version="$(suricata -V 2>&1 | awk '{print $NF}' | tail -n 1)"

    set +e
    suricata -T -c "$CONFIG_FILE" -v
    config_test_exit=$?
    set -e

    if [[ -f "$SMOKE_PCAP" && "$config_test_exit" -eq 0 ]]; then
        install -d -m 0755 "$SMOKE_LOG_DIR"
        find "$SMOKE_LOG_DIR" -mindepth 1 -maxdepth 1 -type f -delete

        set +e
        suricata -c "$CONFIG_FILE" -r "$SMOKE_PCAP" -l "$SMOKE_LOG_DIR/"
        smoke_exit=$?
        set -e

        if [[ -f "$SMOKE_LOG_DIR/eve.json" ]]; then
            smoke_alerts="$(jq -s '[.[] | select(.event_type == "alert")] | length' \
                "$SMOKE_LOG_DIR/eve.json")"
        fi
    else
        printf 'Error: smoke PCAP is missing or configuration validation failed.\n' >&2
    fi

    write_verification "$installed_version" "$config_test_exit" "$smoke_alerts" "$rule_count"

    printf '[*] Configuration: %s\n' "$CONFIG_FILE"
    printf '[*] Verification: %s\n' "$OUTPUT_FILE"
    printf '[*] Config test exit: %d; smoke alerts: %d\n' \
        "$config_test_exit" "$smoke_alerts"

    if [[ "$config_test_exit" -ne 0 || "$smoke_exit" -ne 0 || "$smoke_alerts" -lt 1 ]]; then
        printf 'Error: Suricata offline verification did not pass.\n' >&2
        exit 1
    fi
}

main "$@"