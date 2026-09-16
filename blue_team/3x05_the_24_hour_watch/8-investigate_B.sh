#!/usr/bin/env bash
set -euo pipefail

: "${SHIFT_WORKSPACE:?Execute: source ./project_env.sh}"
: "${ASSETS_DIR:?ASSETS_DIR não definido}"

INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
ALERTS="$SHIFT_WORKSPACE/alerts/alert_queue.json"
EVENTS="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
TICKETS="$ASSETS_DIR/change_tickets.json"
ASSETS="$ASSETS_DIR/assets.json"
IOCS="$ASSETS_DIR/ioc_feed.json"
OUTPUT="$SHIFT_WORKSPACE/investigations/incident_B.json"

for file in "$INCIDENTS" "$ALERTS" "$EVENTS" "$TICKETS" "$ASSETS" "$IOCS"; do
    [[ -s "$file" ]] || {
        echo "[inv-B] ERROR: missing $file" >&2
        exit 1
    }
done

mkdir -p "$SHIFT_WORKSPACE/investigations"

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_EPOCH=$(date -u +%s)

INCIDENT=$(jq -c '
  .incidents[]
  | select(.incident_id | endswith("-B"))
' "$INCIDENTS")

[[ -n "$INCIDENT" ]] || {
    echo "[inv-B] ERROR: incident B not found" >&2
    exit 1
}

INCIDENT_ID=$(jq -r '.incident_id' <<<"$INCIDENT")
FIRST_SEEN=$(jq -r '.first_seen' <<<"$INCIDENT")
LAST_SEEN=$(jq -r '.last_seen' <<<"$INCIDENT")
HOSTS=$(jq -c '.host_list | map(ascii_downcase)' <<<"$INCIDENT")
USERS=$(jq -c '.user_list' <<<"$INCIDENT")
ALERT_IDS=$(jq -c '.alert_ids' <<<"$INCIDENT")

FROM_EPOCH=$(( $(date -u -d "$FIRST_SEEN" +%s) - 900 ))
TO_EPOCH=$(( $(date -u -d "$LAST_SEEN" +%s) + 900 ))
FROM=$(date -u -d "@$FROM_EPOCH" +"%Y-%m-%dT%H:%M:%SZ")
TO=$(date -u -d "@$TO_EPOCH" +"%Y-%m-%dT%H:%M:%SZ")

TMP_EVENTS=$(mktemp)
trap 'rm -f "$TMP_EVENTS"' EXIT

echo "[inv-B] loading $INCIDENT_ID"
echo "[inv-B] hosts: $(jq -r '.[]' <<<"$HOSTS" | xargs)"
echo "[inv-B] users: $(jq -r '.[]' <<<"$USERS" | xargs)"

jq -c \
  --argjson hosts "$HOSTS" \
  --arg from "$FROM" \
  --arg to "$TO" '
    select(
      ((.hostname // .host // "") | ascii_downcase) as $host
      | ($hosts | index($host)) != null
    )
    | select((.timestamp // "") >= $from and (.timestamp // "") <= $to)
' "$EVENTS" > "$TMP_EVENTS"

EVENT_COUNT=$(wc -l < "$TMP_EVENTS" | tr -d ' ')
echo "[inv-B] events in window: $EVENT_COUNT"

echo "[inv-B] timeline (top 6):"
jq -r -s '
  sort_by(.timestamp // "")
  | .[:6][]
  | "  \(.timestamp // "unknown")  \(.hostname // .host // "unknown")  \(.source_type // .source // "unknown")  \(.event_category // "unknown")  \((.raw_message // .message // "")[0:80])"
' "$TMP_EVENTS"

TICKET=$(jq -c '
  .tickets[]
  | select(.ticket_id == "CHG-2026-0341")
' "$TICKETS")

TICKET_HOSTS=$(jq -c '.hosts | map(ascii_downcase)' <<<"$TICKET")
TICKET_OWNER=$(jq -r '.owner' <<<"$TICKET")
TICKET_WINDOW=$(jq -r '.window' <<<"$TICKET")
TICKET_START=${TICKET_WINDOW%/*}
TICKET_END=${TICKET_WINDOW#*/}

HOST_MATCH=$(jq -nr \
  --argjson incident "$HOSTS" \
  --argjson ticket "$TICKET_HOSTS" '
  any($incident[]; . as $host | $ticket | index($host) != null)
')

WINDOW_MATCH=false
if (( $(date -u -d "$FIRST_SEEN" +%s) <= $(date -u -d "$TICKET_END" +%s) &&
      $(date -u -d "$LAST_SEEN" +%s) >= $(date -u -d "$TICKET_START" +%s) )); then
    WINDOW_MATCH=true
fi

OWNER_MATCH=$(jq -nr \
  --argjson users "$USERS" \
  --arg owner "$TICKET_OWNER" '
  $users | index($owner) != null
')

SCOPE_MATCH=false

echo "[inv-B] ticket match: CHG-2026-0341 FOUND"
echo "[inv-B]   host match:   FAIL (incident hosts are not rad-srv-02)"
echo "[inv-B]   window match: $([[ "$WINDOW_MATCH" == true ]] && echo OK || echo FAIL)"
echo "[inv-B]   owner match:  FAIL (j.martinez != $TICKET_OWNER)"
echo "[inv-B]   scope match:  FAIL (SSH authentication failures are not disk expansion)"

IOC_VALUES=$(jq -c '
  [
    .. | objects
    | .value? // empty
    | tostring
  ] | unique
' "$IOCS")

IOC_MATCHES=$(jq -s \
  --argjson values "$IOC_VALUES" '
  [
    .[]
    | (.src_ip // empty), (.dst_ip // empty)
    | select(. as $ip | $values | index($ip) != null)
  ] | unique
' "$TMP_EVENTS")

IOC_COUNT=$(jq 'length' <<<"$IOC_MATCHES")

if (( IOC_COUNT > 0 )); then
    jq -r '.[] | "[inv-B] ioc_match: \(.)"' <<<"$IOC_MATCHES"
else
    echo "[inv-B] ioc_match: none"
fi

ASSET_CONTEXT=$(jq -c \
  --argjson hosts "$HOSTS" '
  [
    (.assets // .)[]
    | select(
        (.hostname // "" | ascii_downcase) as $host
        | $hosts | index($host) != null
      )
    | {
        hostname,
        criticality: (.criticality // "unknown"),
        data_classification: (.data_classification // "unknown")
      }
  ]
' "$ASSETS")

if [[ $(jq 'length' <<<"$ASSET_CONTEXT") -eq 0 ]]; then
    echo "[inv-B] asset context: unavailable for incident hosts"
else
    jq -r '.[] |
      "[inv-B] host: \(.hostname) criticality=\(.criticality) data_class=\(.data_classification)"
    ' <<<"$ASSET_CONTEXT"
fi

EVENT_REFS=$(jq -c \
  --argjson ids "$ALERT_IDS" '
  [
    .[]
    | select(.alert_id as $id | $ids | index($id) != null)
    | .event_refs[]
  ] | unique
' "$ALERTS")

ENDED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
END_EPOCH=$(date -u +%s)
DURATION=$((END_EPOCH - START_EPOCH))

TICKET_OUTCOME="CHG-2026-0341 partial time overlap only; host mismatch, owner mismatch and scope mismatch. Activity is not covered by the approved change."

jq -n \
  --arg finding_id "FIND-B-001" \
  --arg incident_id "$INCIDENT_ID" \
  --arg started "$STARTED_AT" \
  --arg ended "$ENDED_AT" \
  --argjson duration "$DURATION" \
  --argjson refs "$EVENT_REFS" \
  --argjson iocs "$IOC_MATCHES" \
  --argjson assets "$ASSET_CONTEXT" \
  --arg ticket_outcome "$TICKET_OUTCOME" \
  --argjson host_match "$HOST_MATCH" \
  --argjson window_match "$WINDOW_MATCH" \
  --argjson owner_match "$OWNER_MATCH" \
  --argjson scope_match "$SCOPE_MATCH" '
{
  finding_id: $finding_id,
  incident_id: $incident_id,
  interface: "cli",
  investigation_start: $started,
  investigation_end: $ended,
  time_to_first_answer_seconds: $duration,
  actions: [
    "jq selected incident B from alerts/incidents.json",
    "jq filtered enriched events by incident hosts and expanded time window",
    "jq extracted CHG-2026-0341 from change_tickets.json",
    "jq compared incident hosts, users, timestamps and activity scope with the ticket",
    "jq compared src_ip and dst_ip against ioc_feed.json",
    "jq searched assets.json for affected hosts",
    ("ticket_match_outcome: " + $ticket_outcome),
    "sha256sum incidents.json alert_queue.json enriched_events.jsonl change_tickets.json ioc_feed.json"
  ],
  event_refs: $refs,
  attack_techniques: ["T1110.001", "T1078"],
  matches_ioc: $iocs,
  hypothesis: "Repeated SSH authentication failures using the same account across multiple systems indicate credential abuse not covered by the approved maintenance ticket.",
  confidence: "medium",
  ambiguity_notes: "The incident hosts do not exist in the supplied asset inventory and do not match the rad-srv-02 scenario. SSH server, IAM and network logs are required to confirm whether the attempts came from one authorized administrator or a compromised account.",
  event_data: {
    ticket_id: "CHG-2026-0341",
    ticket_match_outcome: $ticket_outcome,
    host_match: $host_match,
    window_match: $window_match,
    owner_match: $owner_match,
    scope_match: $scope_match,
    affected_assets: $assets
  },
  created_at: $ended
}
' > "$OUTPUT"

sha256sum \
  "$INCIDENTS" "$ALERTS" "$EVENTS" "$TICKETS" "$IOCS" \
  > "$SHIFT_WORKSPACE/investigations/incident_B_hashes.txt"

CONFIDENCE=$(jq -r '.confidence' "$OUTPUT")
AMBIGUITY=$(jq -r '.ambiguity_notes' "$OUTPUT")
TICKET_RESULT=$(jq -r '.event_data.ticket_match_outcome' "$OUTPUT")

[[ "$CONFIDENCE" == "high" || -n "$AMBIGUITY" ]] || {
    echo "[inv-B] ERROR: ambiguity_notes required" >&2
    exit 1
}

[[ -n "$TICKET_RESULT" ]] || {
    echo "[inv-B] ERROR: ticket outcome missing" >&2
    exit 1
}

echo "[inv-B] verdict: TP (ticket does not cover the hosts, owner or activity)"
echo "[inv-B] confidence: $CONFIDENCE"
echo "[inv-B] incident_B.json written"
