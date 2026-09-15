#!/bin/bash

set -Eeuo pipefail

fail() {
    printf '[intake] ERROR: %s\n' "$*" >&2
    exit 1
}

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || fail "environment variable $name is not defined"
}

tool_version() {
    local tool="$1"
    local version

    command -v "$tool" >/dev/null 2>&1 ||
        fail "required binary missing: $tool"

    case "$tool" in
        jq)
            version="$(jq --version | sed 's/^jq-//')"
            ;;
        python3)
            version="$(python3 --version 2>&1 | awk '{print $2}')"
            ;;
        yq)
            version="$(yq --version 2>&1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/^v//')"
            ;;
        sigma-cli)
            version="$(sigma-cli version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
            ;;
        sha256sum)
            version="present"
            ;;
    esac

    [[ -n "$version" ]] || fail "could not determine version for $tool"

    if [[ "$tool" == "sha256sum" ]]; then
        printf '[intake] sha256sum OK\n'
    else
        printf '[intake] %s %s OK\n' "$tool" "$version"
    fi

    printf '%s' "$version"
}

for variable in \
    CAPSTONE_PACK ASSETS_DIR WAZUH_EXPORTS SHIFT_WORKSPACE \
    PIPELINE_BIN BASELINE_BIN CATALOG_DIR TRIAGE_BIN
do
    require_env "$variable"
done

declare -A TOOL_VERSIONS

for tool in jq python3 yq sigma-cli sha256sum
do
    TOOL_VERSIONS["$tool"]="$(tool_version "$tool" | tail -1)"
done

[[ -x "$PIPELINE_BIN" ]] ||
    fail "PIPELINE_BIN is missing or not executable: $PIPELINE_BIN"
printf '[intake] PIPELINE_BIN OK\n'

[[ -x "$BASELINE_BIN" ]] ||
    fail "BASELINE_BIN is missing or not executable: $BASELINE_BIN"
printf '[intake] BASELINE_BIN OK\n'

[[ -d "$CATALOG_DIR" && -r "$CATALOG_DIR" ]] ||
    fail "CATALOG_DIR is not a readable directory: $CATALOG_DIR"

rule_count="$(
    find "$CATALOG_DIR" -type f -name '*.yml' -readable | wc -l
)"
(( rule_count > 0 )) ||
    fail "CATALOG_DIR contains no readable .yml files"
printf '[intake] CATALOG_DIR OK (%s rules)\n' "$rule_count"

[[ -x "$TRIAGE_BIN" ]] ||
    fail "TRIAGE_BIN is missing or not executable: $TRIAGE_BIN"
printf '[intake] TRIAGE_BIN OK\n'

[[ -d "$CAPSTONE_PACK" && -r "$CAPSTONE_PACK" ]] ||
    fail "CAPSTONE_PACK is not accessible: $CAPSTONE_PACK"

find "$CAPSTONE_PACK" -mindepth 1 -maxdepth 1 -type d -print -quit |
    grep -q . ||
    fail "CAPSTONE_PACK is empty"

printf '[intake] CAPSTONE_PACK OK\n'
printf '[intake] top-level directories:\n'
find "$CAPSTONE_PACK" \
    -mindepth 1 -maxdepth 1 -type d -printf '  - %f\n' |
    sort

required_meta=(
    assets.json
    ioc_feed.json
    hc_red7_advisory.md
    change_tickets.json
    prior_shift_notes.md
)

for file in "${required_meta[@]}"
do
    [[ -r "$ASSETS_DIR/$file" ]] ||
        fail "missing context file: $ASSETS_DIR/$file"
done
printf '[intake] ASSETS_DIR: 5 meta files OK\n'

required_exports=(
    incident_A_search_results.json
    incident_B_search_results.json
    incident_C_search_results.json
    campaign_dashboard_summary.md
)

for file in "${required_exports[@]}"
do
    [[ -r "$WAZUH_EXPORTS/$file" ]] ||
        fail "missing Wazuh export: $WAZUH_EXPORTS/$file"
done
printf '[intake] WAZUH_EXPORTS: 4 export files OK\n'

jq empty "$ASSETS_DIR/ioc_feed.json" 2>/dev/null ||
    fail "ioc_feed.json is not valid JSON"

ioc_count="$(
    jq -er '.iocs | length' "$ASSETS_DIR/ioc_feed.json"
)" || fail "could not read .iocs from ioc_feed.json"

[[ "$ioc_count" =~ ^[0-9]+$ ]] ||
    fail "invalid IOC count: $ioc_count"
printf '[intake] ioc_feed.json OK (%s entries)\n' "$ioc_count"

cluster_id="$(
    grep -o 'HC-RED7' "$ASSETS_DIR/hc_red7_advisory.md" |
        head -1
)" || true

[[ "$cluster_id" == "HC-RED7" ]] ||
    fail "HC-RED7 not found in advisory"
printf '[intake] advisory HC-RED7 loaded\n'

mkdir -p \
    "$SHIFT_WORKSPACE/runtime" \
    "$SHIFT_WORKSPACE/enriched" \
    "$SHIFT_WORKSPACE/alerts" \
    "$SHIFT_WORKSPACE/investigations" \
    "$SHIFT_WORKSPACE/campaign" \
    "$SHIFT_WORKSPACE/reports" \
    "$SHIFT_WORKSPACE/response" \
    "$SHIFT_WORKSPACE/handoff"

stub_files=(
    "MANIFEST.json"
    "runtime/shift_start.json"
    "runtime/pipeline_run.json"
    "runtime/baseline_run.json"
    "runtime/catalog_run.json"
    "enriched/enriched_events.jsonl"
    "enriched/timeline.jsonl"
    "enriched/baseline.json"
    "enriched/source_stats.json"
    "alerts/alert_queue.json"
    "alerts/shift_briefing.json"
    "alerts/triage_log.jsonl"
    "alerts/incidents.json"
    "investigations/incident_A.json"
    "investigations/incident_B.json"
    "investigations/incident_C_cli.json"
    "investigations/incident_C_export.json"
    "campaign/campaign_assessment.json"
    "reports/incident_A.md"
    "reports/incident_B.md"
    "reports/incident_C.md"
    "response/tuning_recommendations.json"
    "response/containment.json"
    "response/ioc_package.json"
    "handoff/shift_handoff.md"
)

for file in "${stub_files[@]}"
do
    : > "$SHIFT_WORKSPACE/$file"
done

printf '[intake] workspace layout created at %s\n' "$SHIFT_WORKSPACE"

started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
shift_id="SHIFT-$(date -u '+%Y%m%d-%H%M')"
analyst_host="$(hostname)"
resolved_pack="$(readlink -f "$CAPSTONE_PACK")"

jq -n \
    --arg shift_id "$shift_id" \
    --arg analyst_host "$analyst_host" \
    --arg started_at "$started_at" \
    --arg jq_version "${TOOL_VERSIONS[jq]}" \
    --arg python_version "${TOOL_VERSIONS[python3]}" \
    --arg yq_version "${TOOL_VERSIONS[yq]}" \
    --arg sigma_version "${TOOL_VERSIONS[sigma-cli]}" \
    --arg capstone_pack "$resolved_pack" \
    --arg cluster_id "$cluster_id" \
    --argjson ioc_count "$ioc_count" \
    '{
        shift_id: $shift_id,
        analyst_host: $analyst_host,
        started_at: $started_at,
        tools: {
            jq: $jq_version,
            python3: $python_version,
            yq: $yq_version,
            "sigma-cli": $sigma_version,
            sha256sum: "present"
        },
        prior_project_bins: {
            pipeline: true,
            baseline: true,
            catalog: true,
            triage: true
        },
        capstone_pack: $capstone_pack,
        ioc_feed_count: $ioc_count,
        advisory_cluster_id: $cluster_id,
        wazuh_exports_verified: true
    }' > "$SHIFT_WORKSPACE/runtime/shift_start.json"

printf '[intake] shift_start.json written\n'
