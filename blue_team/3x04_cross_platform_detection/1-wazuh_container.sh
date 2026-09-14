#!/bin/bash

# Task 1 - Wazuh Evidence Workspace Preparation
# Prepare an auditable Wazuh export workspace without requiring a live SIEM.

set -u

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"
QUERY_RESULTS="$ASSETS_DIR/query_results"
WORKSPACE_DIR="workspace"
WORKSPACE_FILE="$WORKSPACE_DIR/workspace_init.json"

INDEX_METADATA="$WAZUH_EXPORTS/index_metadata.json"
FIELD_MAPPING="$WAZUH_EXPORTS/field_mapping.json"
CREDENTIALS_FILE="$ASSETS_DIR/dashboard_credentials.json"

ERRORS=0
EXPORT_FILES_VERIFIED=true
FIELD_MAPPING_LOADED=false

pass()
{
    printf '%-15s: %s\n' "$1" "$2"
}

fail()
{
    printf '%-15s: FAILED (%s)\n' "$1" "$2" >&2
    ERRORS=$((ERRORS + 1))
}

require_json()
{
    local filepath="$1"

    if [[ ! -s "$filepath" ]]; then
        printf 'missing file   : %s\n' "$filepath" >&2
        EXPORT_FILES_VERIFIED=false
        ERRORS=$((ERRORS + 1))
        return
    fi

    if ! jq empty "$filepath" >/dev/null 2>&1; then
        printf 'invalid JSON   : %s\n' "$filepath" >&2
        EXPORT_FILES_VERIFIED=false
        ERRORS=$((ERRORS + 1))
    fi
}

WAZUH_REQUIRED=(
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

QUERY_REQUIRED=(
    "kql_anchor_query.json"
    "lucene_anchor_query.json"
    "kql_scenario_a.json"
    "kql_scenario_b.json"
    "kql_scenario_c.json"
)

pass "mode" "wazuh_export (no live dashboard required)"

# Verify every required Wazuh export and saved query result.
for filename in "${WAZUH_REQUIRED[@]}"; do
    require_json "$WAZUH_EXPORTS/$filename"
done

for filename in "${QUERY_REQUIRED[@]}"; do
    require_json "$QUERY_RESULTS/$filename"
done

# Read and validate the index metadata.
if [[ -s "$INDEX_METADATA" ]] &&
   jq empty "$INDEX_METADATA" >/dev/null 2>&1; then
    SOURCE_INDEX="$(jq -r '.source_index // empty' "$INDEX_METADATA")"
    TOTAL_DOCUMENTS="$(jq -r '.total_documents // empty' "$INDEX_METADATA")"
    EARLIEST="$(jq -r '.time_range.earliest // empty' "$INDEX_METADATA")"
    LATEST="$(jq -r '.time_range.latest // empty' "$INDEX_METADATA")"

    if [[ -z "$SOURCE_INDEX" ||
          ! "$TOTAL_DOCUMENTS" =~ ^[0-9]+$ ||
          -z "$EARLIEST" ||
          -z "$LATEST" ]]; then
        fail "metadata" "required index metadata fields are missing"
        SOURCE_INDEX="${SOURCE_INDEX:-unknown}"
        TOTAL_DOCUMENTS="${TOTAL_DOCUMENTS:-0}"
        EARLIEST="${EARLIEST:-unknown}"
        LATEST="${LATEST:-unknown}"
    else
        pass "index" "$SOURCE_INDEX"
        pass "documents" "$(printf "%'d" "$TOTAL_DOCUMENTS")"
        pass "time range" "$EARLIEST to $LATEST"
    fi
else
    fail "metadata" "index_metadata.json is missing or invalid"
    SOURCE_INDEX="unknown"
    TOTAL_DOCUMENTS=0
    EARLIEST="unknown"
    LATEST="unknown"
fi

# Read only the username. The password is never selected or printed.
if [[ -s "$CREDENTIALS_FILE" ]] &&
   jq empty "$CREDENTIALS_FILE" >/dev/null 2>&1; then
    USERNAME="$(
        jq -r '
            .username
            // .user
            // .kibana_username
            // .credentials.username
            // empty
        ' "$CREDENTIALS_FILE"
    )"

    if [[ -n "$USERNAME" ]]; then
        pass "credentials" "$USERNAME (from dashboard_credentials.json)"
    else
        fail "credentials" "username not found"
    fi
else
    fail "credentials" "dashboard_credentials.json is missing or invalid"
fi

# Load the field mapping and print the first ten commonly used mappings.
if [[ -s "$FIELD_MAPPING" ]] &&
   jq -e '.mappings | type == "array" and length > 0' \
      "$FIELD_MAPPING" >/dev/null 2>&1; then
    MAPPING_COUNT="$(jq '.mappings | length' "$FIELD_MAPPING")"
    FIELD_MAPPING_LOADED=true

    pass "field mapping" "loaded ($MAPPING_COUNT mappings)"
    printf '  %-20s -> %s\n' "normalized field" "Wazuh field"

    jq -r '.mappings[0:10][] | [.normalized, .wazuh] | @tsv' \
        "$FIELD_MAPPING" |
        while IFS=$'\t' read -r normalized wazuh; do
            printf '  %-20s -> %s\n' "$normalized" "$wazuh"
        done
else
    fail "field mapping" "field_mapping.json is missing or invalid"
fi

REQUIRED_COUNT=$((${#WAZUH_REQUIRED[@]} + ${#QUERY_REQUIRED[@]}))

if [[ "$EXPORT_FILES_VERIFIED" == true ]]; then
    pass "export files" "all present ($REQUIRED_COUNT files verified)"
else
    fail "export files" "one or more required files failed validation"
fi

# Only initialize the workspace when all required inputs are valid.
if (( ERRORS > 0 )); then
    fail "workspace" "initialization aborted with $ERRORS error(s)"
    exit 1
fi

mkdir -p "$WORKSPACE_DIR"
INITIALIZED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
TEMP_FILE="$WORKSPACE_FILE.tmp"

jq -n \
    --arg mode "wazuh_export" \
    --arg source_index "$SOURCE_INDEX" \
    --argjson total_documents "$TOTAL_DOCUMENTS" \
    --arg earliest "$EARLIEST" \
    --arg latest "$LATEST" \
    --argjson export_files_verified "$EXPORT_FILES_VERIFIED" \
    --argjson field_mapping_loaded "$FIELD_MAPPING_LOADED" \
    --arg initialized_at "$INITIALIZED_AT" '
    {
        mode: $mode,
        source_index: $source_index,
        total_documents: $total_documents,
        time_range: {
            earliest: $earliest,
            latest: $latest
        },
        export_files_verified: $export_files_verified,
        field_mapping_loaded: $field_mapping_loaded,
        initialized_at: $initialized_at
    }
' > "$TEMP_FILE"

mv "$TEMP_FILE" "$WORKSPACE_FILE"
pass "workspace" "$WORKSPACE_FILE written"

exit 0

