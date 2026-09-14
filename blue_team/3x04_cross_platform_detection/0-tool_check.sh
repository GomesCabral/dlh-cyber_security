#!/bin/bash

# Task 0 - CLI Toolkit Verification
# Verify the required tools, upstream packages, Wazuh exports,
# and the anchor scenario before beginning the investigation.

set -u

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

ENRICHED_EVENTS="$HANDOFF_DIR/data/enriched_events.json"
SIGMA_DIR="$CATALOG_DIR/rules/sigma"
ANCHOR_FILE="$ASSETS_DIR/anchor_event.json"

ERRORS=0

pass()
{
    printf '%-15s: %s\n' "$1" "$2"
}

fail()
{
    printf '%-15s: FAILED (%s)\n' "$1" "$2" >&2
    ERRORS=$((ERRORS + 1))
}

get_version()
{
    case "$1" in
        jq)
            jq --version 2>/dev/null | sed 's/^jq-//'
            ;;
        yq)
            yq --version 2>/dev/null |
                grep -oE '[0-9]+(\.[0-9]+)+' |
                head -n 1
            ;;
        python3)
            python3 --version 2>&1 | awk '{print $2}'
            ;;
        sigma|sigma-cli)
            "$1" version 2>&1 |
                grep -oE '[0-9]+(\.[0-9]+)+' |
                head -n 1
            ;;
        xmllint)
            xmllint --version 2>&1 |
                grep -oE '[0-9]+' |
                head -n 1
            ;;
        curl)
            curl --version 2>/dev/null |
                head -n 1 |
                awk '{print $2}'
            ;;
    esac
}

check_tool()
{
    local label="$1"
    local command_name="$2"
    local version

    if ! command -v "$command_name" >/dev/null 2>&1; then
        fail "$label" "not found on PATH"
        return
    fi

    version="$(get_version "$command_name")"
    pass "$label" "${version:-installed}"
}

check_directory()
{
    local label="$1"
    local directory="$2"

    if [[ -d "$directory" ]]; then
        pass "$label" "ok ($directory)"
    else
        fail "$label" "directory missing: $directory"
    fi
}

# Required command-line tools.
check_tool "jq" "jq"
check_tool "yq" "yq"
check_tool "python3" "python3"

if command -v sigma-cli >/dev/null 2>&1; then
    SIGMA_COMMAND="sigma-cli"
elif command -v sigma >/dev/null 2>&1; then
    SIGMA_COMMAND="sigma"
else
    SIGMA_COMMAND=""
fi

if [[ -n "$SIGMA_COMMAND" ]]; then
    SIGMA_VERSION="$(get_version "$SIGMA_COMMAND")"
    pass "sigma-cli" "${SIGMA_VERSION:-installed}"
else
    fail "sigma-cli" "neither sigma-cli nor sigma found on PATH"
fi

check_tool "xmllint" "xmllint"
check_tool "curl" "curl"

# Required upstream directories.
check_directory "HANDOFF_DIR" "$HANDOFF_DIR"
check_directory "BASELINE_PKG" "$BASELINE_PKG"
check_directory "CATALOG_DIR" "$CATALOG_DIR"
check_directory "TRIAGE_PKG" "$TRIAGE_PKG"
check_directory "ASSETS_DIR" "$ASSETS_DIR"

# Enriched events produced by project 3x00.
if [[ -s "$ENRICHED_EVENTS" ]]; then
    pass "handoff" "ok (enriched_events.json present)"
else
    fail "handoff" "missing or empty: $ENRICHED_EVENTS"
fi

# Sigma rules produced by project 3x02.
if [[ -d "$SIGMA_DIR" ]]; then
    SIGMA_COUNT="$(
        find "$SIGMA_DIR" -type f \
            \( -name '*.yml' -o -name '*.yaml' \) |
            wc -l |
            tr -d ' '
    )"

    if (( SIGMA_COUNT > 0 )); then
        pass "catalog" "ok ($SIGMA_COUNT sigma rules)"
    else
        fail "catalog" "no Sigma rules found in $SIGMA_DIR"
    fi
else
    fail "catalog" "missing directory: $SIGMA_DIR"
fi

# Wazuh search results and dashboard workflow traces.
WAZUH_REQUIRED_FILES=(
    "field_mapping.json"
    "index_metadata.json"
    "anchor_search_results.json"
    "scenario_a_search_results.json"
    "scenario_b_search_results.json"
    "scenario_c_search_results.json"
    "anchor_dashboard_trace.json"
    "scenario_a_dashboard_trace.json"
    "scenario_b_dashboard_trace.json"
    "scenario_c_dashboard_trace.json"
)

WAZUH_ERRORS=0

if [[ ! -d "$WAZUH_EXPORTS" ]]; then
    fail "wazuh_exports" "missing directory: $WAZUH_EXPORTS"
else
    for filename in "${WAZUH_REQUIRED_FILES[@]}"; do
        filepath="$WAZUH_EXPORTS/$filename"

        if [[ ! -s "$filepath" ]]; then
            printf 'missing Wazuh export: %s\n' "$filepath" >&2
            WAZUH_ERRORS=$((WAZUH_ERRORS + 1))
        elif ! jq empty "$filepath" >/dev/null 2>&1; then
            printf 'invalid Wazuh JSON: %s\n' "$filepath" >&2
            WAZUH_ERRORS=$((WAZUH_ERRORS + 1))
        fi
    done

    if (( WAZUH_ERRORS == 0 )); then
        pass "wazuh_exports" \
            "ok (field_mapping, index_metadata, 4 search_results, 4 dashboard_traces)"
    else
        fail "wazuh_exports" \
            "$WAZUH_ERRORS required file(s) missing or invalid"
    fi
fi

# Anchor verification against the enriched NDJSON event handoff.
if [[ ! -s "$ANCHOR_FILE" ]]; then
    fail "anchor" "missing or empty: $ANCHOR_FILE"
elif ! jq empty "$ANCHOR_FILE" >/dev/null 2>&1; then
    fail "anchor" "invalid JSON: $ANCHOR_FILE"
elif [[ ! -s "$ENRICHED_EVENTS" ]]; then
    fail "anchor" "enriched_events.json unavailable"
else
    TARGET_HOST="$(jq -r '.target_host // empty' "$ANCHOR_FILE")"
    TARGET_IP="$(jq -r '.target_ip // empty' "$ANCHOR_FILE")"
    WINDOW_START="$(jq -r '.time_window.start // empty' "$ANCHOR_FILE")"
    WINDOW_END="$(jq -r '.time_window.end // empty' "$ANCHOR_FILE")"

    if [[ -z "$TARGET_HOST" ||
          -z "$TARGET_IP" ||
          -z "$WINDOW_START" ||
          -z "$WINDOW_END" ]]; then
        fail "anchor" \
            "target_host, target_ip, or time_window missing from anchor_event.json"
    else
        ANCHOR_MATCH="$(
            jq -c \
                --arg host "$TARGET_HOST" \
                --arg target_ip "$TARGET_IP" \
                --arg start "$WINDOW_START" \
                --arg end "$WINDOW_END" '
                select(
                    (.timestamp >= $start)
                    and (.timestamp <= $end)
                    and (
                        (.hostname == $host)
                        or (.dst_ip == $target_ip)
                        or (.target_host == $host)
                        or (.target_ip == $target_ip)
                    )
                )
            ' "$ENRICHED_EVENTS" 2>/dev/null |
                head -n 1
        )"

        if [[ -n "$ANCHOR_MATCH" ]]; then
            MATCH_TIMESTAMP="$(
                printf '%s\n' "$ANCHOR_MATCH" |
                    jq -r '.timestamp // "unknown timestamp"'
            )"

            MATCH_TARGET="$(
                printf '%s\n' "$ANCHOR_MATCH" |
                    jq -r '
                        .hostname
                        // .dst_ip
                        // .target_host
                        // .target_ip
                        // "unknown target"
                    '
            )"

            pass "anchor" \
                "ok ($TARGET_HOST matched at $MATCH_TIMESTAMP via $MATCH_TARGET)"
        else
            fail "anchor" \
                "no event matched $TARGET_HOST/$TARGET_IP between $WINDOW_START and $WINDOW_END"
        fi
    fi
fi

# Final result and process exit status.
if (( ERRORS > 0 )); then
    pass "all checks" "failed ($ERRORS error(s))"
    exit 1
fi

pass "all checks" "passed"
exit 0
