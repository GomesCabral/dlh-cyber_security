#!/bin/bash

# Task 9 - Hunt H5: Service Account Abuse
# MITRE ATT&CK T1078.002 - Domain Accounts

set -euo pipefail

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
MATRIX="reference/service_accounts.txt"

for file in "$ALERTS" "$SYSMON" "$MATRIX"; do
    if [[ ! -f "$file" ]]; then
        echo "[ERROR] Missing file: $file" >&2
        exit 1
    fi
done

command -v jq >/dev/null 2>&1 || {
    echo "[ERROR] jq is required." >&2
    exit 1
}

AUTH_EVENTS=$(mktemp)
UNAUTHORIZED=$(mktemp)
LATERAL=$(mktemp)

trap 'rm -f "$AUTH_EVENTS" "$UNAUTHORIZED" "$LATERAL"' EXIT

# ------------------------------------------------------------
# Service accounts documented in authorization matrix
# ------------------------------------------------------------

SERVICE_ACCOUNTS=(
    "svc_healthsync"
    "svc_insurance"
    "svc_backup"
    "svc_patchdeploy"
    "svc_av"
    "svc_ad_replication"
)

authorized_source()
{
    local account="$1"
    local source="$2"

    case "$account" in
        svc_healthsync)
            [[ "$source" == "SRV-HEALTH-DB" ]]
            ;;
        svc_insurance)
            [[ "$source" == "SRV-INS-DB" ]]
            ;;
        svc_backup)
            [[ "$source" == "SRV-BACKUP-01" ]]
            ;;
        svc_patchdeploy)
            [[ "$source" == "SRV-PATCH-01" ]]
            ;;
        svc_av)
            [[ "$source" == "SRV-AV-01" ]]
            ;;
        svc_ad_replication)
            [[ "$source" == "SRV-DC-01" || "$source" == "SRV-DC-02" ]]
            ;;
        *)
            return 1
            ;;
    esac
}

# ------------------------------------------------------------
# 1. Extract successful service-account authentications
# ------------------------------------------------------------

jq -c '
    select(.data.win.system.eventID == "4624")
    | select(
        (.data.win.eventdata.targetUserName // "")
        | test("^svc_"; "i")
    )
' "$ALERTS" > "$AUTH_EVENTS"

# ------------------------------------------------------------
# 2. Classify AUTHORIZED / UNAUTHORIZED
# ------------------------------------------------------------

while IFS= read -r event; do

    ACCOUNT=$(jq -r '.data.win.eventdata.targetUserName // "unknown"' <<< "$event")
    SOURCE=$(jq -r '.data.win.eventdata.workstationName // "unknown"' <<< "$event")
    LOGON=$(jq -r '.data.win.eventdata.logonType // "unknown"' <<< "$event")
    AUTH=$(jq -r '.data.win.eventdata.authenticationPackageName // "unknown"' <<< "$event")

    BAD=0

    # Undocumented service account
    KNOWN=0
    for svc in "${SERVICE_ACCOUNTS[@]}"; do
        if [[ "$ACCOUNT" == "$svc" ]]; then
            KNOWN=1
            break
        fi
    done

    if (( KNOWN == 0 )); then
        BAD=1
    fi

    # Wrong source host
    if ! authorized_source "$ACCOUNT" "$SOURCE"; then
        BAD=1
    fi

    # Any workstation-originated service account authentication
    if [[ "$SOURCE" == WS-* ]]; then
        BAD=1
    fi

    # Interactive / RemoteInteractive / CachedInteractive
    if [[ "$LOGON" == "2" || "$LOGON" == "10" || "$LOGON" == "11" ]]; then
        BAD=1
    fi

    # Service accounts should use Kerberos
    if [[ "${AUTH^^}" == "NTLM" ]]; then
        BAD=1
    fi

    if (( BAD == 1 )); then
        printf '%s\n' "$event" >> "$UNAUTHORIZED"
    fi

done < "$AUTH_EVENTS"

# ------------------------------------------------------------
# 3. Find lateral movement involving service accounts
# ------------------------------------------------------------

jq -c '
    select(.data.win.system.eventID == "1")
    | select(
        (
            .data.win.eventdata.user // ""
            | test("svc_"; "i")
        )
        or
        (
            .data.win.eventdata.commandLine // ""
            | test("svc_"; "i")
        )
    )
    | select(
        (
            .data.win.eventdata.image // ""
            | test("psexec|wmic|powershell"; "i")
        )
        or
        (
            .data.win.eventdata.commandLine // ""
            | test(
                "psexec|wmic|Invoke-WmiMethod|Enter-PSSession|New-PSSession|Invoke-Command";
                "i"
            )
        )
    )
' "$SYSMON" > "$LATERAL"

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

echo "================================================================"
echo "   HUNT EXECUTION - H5: Service Account Abuse"
echo "   Technique: T1078.002 Domain Accounts"
echo "================================================================"

echo
echo "SERVICE ACCOUNT AUTHORIZATION MATRIX:"
echo "  svc_healthsync:    SRV-HEALTH-DB"
echo "  svc_insurance:     SRV-INS-DB"
echo "  svc_backup:        SRV-BACKUP-01"
echo "  svc_patchdeploy:   SRV-PATCH-01"
echo "  svc_av:            SRV-AV-01"
echo "  svc_ad_replication: SRV-DC-01 / SRV-DC-02"

echo
echo "AUTHENTICATION AUDIT:"

TOTAL_ALL=0
AUTHORIZED_ALL=0
UNAUTHORIZED_ALL=0

for ACCOUNT in "${SERVICE_ACCOUNTS[@]}"; do

    TOTAL=$(jq -s \
        --arg account "$ACCOUNT" \
        '[.[] |
          select(
            (.data.win.eventdata.targetUserName // "") == $account
          )
        ] | length' \
        "$AUTH_EVENTS")

    UNAUTH=$(jq -s \
        --arg account "$ACCOUNT" \
        '[.[] |
          select(
            (.data.win.eventdata.targetUserName // "") == $account
          )
        ] | length' \
        "$UNAUTHORIZED")

    AUTHORIZED=$((TOTAL - UNAUTH))

    TOTAL_ALL=$((TOTAL_ALL + TOTAL))
    AUTHORIZED_ALL=$((AUTHORIZED_ALL + AUTHORIZED))
    UNAUTHORIZED_ALL=$((UNAUTHORIZED_ALL + UNAUTH))

    echo
    printf "  %s:\n" "$ACCOUNT"
    printf "    Total auth events: %s\n" "$TOTAL"
    printf "    Authorized:        %s\n" "$AUTHORIZED"
    printf "    UNAUTHORIZED:      %s\n" "$UNAUTH"

    if (( UNAUTH > 0 )); then

        jq -c \
            --arg account "$ACCOUNT" \
            'select(
                (.data.win.eventdata.targetUserName // "") == $account
            )' \
            "$UNAUTHORIZED" |
        while IFS= read -r event; do

            TIMESTAMP=$(jq -r '.timestamp // "unknown"' <<< "$event")
            SOURCE=$(jq -r '.data.win.eventdata.workstationName // "unknown"' <<< "$event")
            TARGET=$(jq -r '.agent.name // "unknown"' <<< "$event")
            LOGON=$(jq -r '.data.win.eventdata.logonType // "unknown"' <<< "$event")
            AUTH=$(jq -r '.data.win.eventdata.authenticationPackageName // "unknown"' <<< "$event")

            echo
            printf "      %s\n" "$TIMESTAMP"
            printf "        Source: %s\n" "$SOURCE"
            printf "        Target: %s\n" "$TARGET"
            printf "        Logon Type: %s\n" "$LOGON"
            printf "        Authentication: %s\n" "$AUTH"

            echo "        ANOMALY FLAGS:"

            if [[ "$SOURCE" == WS-* ]]; then
                echo "          [!] Service account authentication from workstation"
            fi

            if ! authorized_source "$ACCOUNT" "$SOURCE"; then
                echo "          [!] Source host is not authorized for this account"
            fi

            if [[ "$LOGON" == "2" || "$LOGON" == "10" || "$LOGON" == "11" ]]; then
                echo "          [!] Interactive service-account logon"
            fi

            if [[ "${AUTH^^}" == "NTLM" ]]; then
                echo "          [!] NTLM authentication - service accounts should use Kerberos"
            fi

        done
    fi

done

echo
echo "SUMMARY:"
printf "  Total service-account authentications: %s\n" "$TOTAL_ALL"
printf "  AUTHORIZED:                            %s\n" "$AUTHORIZED_ALL"
printf "  UNAUTHORIZED:                          %s\n" "$UNAUTHORIZED_ALL"

echo
echo "CORRELATED LATERAL MOVEMENT:"

LATERAL_COUNT=$(wc -l < "$LATERAL")

if (( LATERAL_COUNT > 0 )); then

    while IFS= read -r event; do

        TIMESTAMP=$(jq -r '.timestamp // "unknown"' <<< "$event")
        SOURCE=$(jq -r '.agent.name // "unknown"' <<< "$event")
        USER=$(jq -r '.data.win.eventdata.user // "unknown"' <<< "$event")
        TARGET=$(jq -r '.hunt_meta.target_host // "unknown"' <<< "$event")
        TOOL=$(jq -r '.hunt_meta.tool // "unknown"' <<< "$event")
        COMMAND=$(jq -r '.data.win.eventdata.commandLine // "unknown"' <<< "$event")

        echo
        printf "  %s\n" "$TIMESTAMP"
        printf "    Source:  %s\n" "$SOURCE"
        printf "    User:    %s\n" "$USER"
        printf "    Tool:    %s\n" "$TOOL"
        printf "    Target:  %s\n" "$TARGET"
        printf "    Command: %s\n" "$COMMAND"

    done < "$LATERAL"

else
    echo "  No correlated lateral movement found."
fi

echo
echo "FINDING:"

if (( UNAUTHORIZED_ALL > 0 && LATERAL_COUNT > 0 )); then

    echo "  Status: POSITIVE - CRITICAL CONFIDENCE"
    echo "  Evidence:"
    echo "    - Service-account authentication violated the authorization matrix"
    echo "    - Service account was used from unauthorized workstation source(s)"
    echo "    - Unauthorized activity correlates with lateral movement tooling"
    echo
    echo "  Assessment:"
    echo "    Service-account credentials were used outside their documented"
    echo "    operational context and are strongly associated with lateral movement."
    echo
    echo "  Recommendation: ESCALATE"

elif (( UNAUTHORIZED_ALL > 0 )); then

    echo "  Status: POSITIVE - HIGH CONFIDENCE"
    echo "  Evidence: Unauthorized service-account authentication detected"
    echo "  Recommendation: Investigate immediately"

else

    echo "  Status: NEGATIVE"
    echo "  Evidence: All observed service-account usage matches the authorization matrix"

fi

echo
echo "================================================================"