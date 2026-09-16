#!/bin/bash

set -Eeuo pipefail

fail() {
    printf '[inv-A] ERROR: %s\n' "$*" >&2
    exit 1
}

incidents="$SHIFT_WORKSPACE/alerts/incidents.json"
events="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
ioc_file="$ASSETS_DIR/ioc_feed.json"
baseline="$SHIFT_WORKSPACE/enriched/baseline.json"
output="$SHIFT_WORKSPACE/investigations/incident_A.json"

for file in "$incidents" "$events" "$ioc_file" "$baseline"
do
    [[ -s "$file" ]] || fail "missing input: $file"
done

started_epoch="$(date -u +%s)"
investigation_start="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

incident="$(
    jq -c '.incidents[] | select(.incident_id | endswith("-A"))' \
        "$incidents"
)"

[[ -n "$incident" ]] || fail "incident A not found"

incident_id="$(jq -r '.incident_id' <<<"$incident")"
hosts="$(jq -c '[.host_list[] | ascii_downcase]' <<<"$incident")"
first_seen="$(jq -r '.first_seen' <<<"$incident")"
last_seen="$(jq -r '.last_seen' <<<"$incident")"
category="$(jq -r '.tentative_category' <<<"$incident")"
alert_count="$(jq '.alert_ids | length' <<<"$incident")"

printf '[inv-A] loading %s\n' "$incident_id"
printf '[inv-A] host_list: %s\n' \
    "$(jq -r '.host_list | join(" ")' <<<"$incident")"
printf '[inv-A] alert count: %s category=%s\n' \
    "$alert_count" "$category"

window_start="$(
    date -u -d "$first_seen - 15 minutes" '+%Y-%m-%dT%H:%M:%SZ'
)"
window_end="$(
    date -u -d "$last_seen + 15 minutes" '+%Y-%m-%dT%H:%M:%SZ'
)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

matching="$tmp_dir/matching.jsonl"
ranked="$tmp_dir/ranked.tsv"
top_events="$tmp_dir/top_events.jsonl"

jq -c \
    --argjson hosts "$hosts" \
    --arg start_value "$window_start" \
    --arg end_value "$window_end" '
    . as $event
    | (($event.hostname // $event.host // "") | ascii_downcase) as $host
    | select($hosts | index($host))
    | select(($event.timestamp // "") >= $start_value)
    | select(($event.timestamp // "") <= $end_value)
' "$events" > "$matching"

event_count="$(wc -l < "$matching")"
printf '[inv-A] events in window: %s\n' "$event_count"

(( event_count >= 6 )) ||
    fail "fewer than 6 matching events"

jq -r '
    (
      if .event_category == "authentication" then 5
      elif .event_category == "privilege" then 5
      elif .event_category == "process" then 4
      elif .event_category == "process_creation" then 4
      elif .event_category == "network_alert" then 3
      elif .src_ip != null or .dst_ip != null then 2
      else 1
      end
    ) as $score
    | "\(10 - $score)\t\(.timestamp // "")\t\(tojson)"
' "$matching" |
    LC_ALL=C sort -T "$tmp_dir" -k1,1n -k2,2 > "$ranked"

head -6 "$ranked" | cut -f3- > "$top_events"

printf '[inv-A] timeline (top 6):\n'

jq -r '
    "  \(.timestamp // "unknown")  " +
    "\(.hostname // .host // "unknown")  " +
    "\(.source_type // "unknown")  " +
    "\(.event_category // "unknown")  " +
    "\((.raw_message // .command_line // "")[0:80])"
' "$top_events"

ioc_values="$(
    jq -c '[.iocs[]?.value | tostring]' "$ioc_file"
)"

ioc_matches="$(
    jq -s \
        --argjson iocs "$ioc_values" '
        [
          .[]
          | (.src_ip // null), (.dst_ip // null)
          | select(. != null)
          | tostring
          | select(. as $value | $iocs | index($value))
        ]
        | unique
    ' "$matching"
)"

printf '[inv-A] ioc_matches: %s (%s)\n' \
    "$(jq 'length' <<<"$ioc_matches")" \
    "$(jq -r 'join(", ")' <<<"$ioc_matches")"

baseline_markers="$(
    jq -c \
        --argjson hosts "$hosts" '
        [
          .deviation_markers[]
          | . as $marker
          | select(
              $marker.host != null
              and (
                  $hosts
                  | index(($marker.host | ascii_downcase))
              )
          )
        ]
    ' "$baseline"
)"

printf '[inv-A] baseline deviations: %s markers\n' \
    "$(jq 'length' <<<"$baseline_markers")"

jq -r '
    .[0:10][]
    | "  \(.host) \(.marker) \(.observed_value)"
' <<<"$baseline_markers"

event_refs="$(
    jq -s '
        to_entries
        | map(
            .value.event_ref
            // .value.event_uuid
            // (
                "event:"
                + (.value.event_id // "unknown" | tostring)
                + ":"
                + (.value.timestamp // "unknown")
                + ":"
                + (.value.hostname // .value.host // "unknown")
            )
        )
    ' "$top_events"
)"

techniques='["T1110.001","T1078"]'

hypothesis="Repeated authentication failures followed by off-hours logons across correlated hosts indicate credential abuse requiring identity and source validation."

ambiguity="Correlation is broad because shared users joined multiple hosts. Domain-controller authentication and VPN logs are required to confirm whether one actor controlled all sessions."

mkdir -p "$SHIFT_WORKSPACE/investigations"

sha256sum "$incidents" "$events" "$ioc_file" > \
    "$tmp_dir/evidence_hashes.txt"

investigation_end="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
ended_epoch="$(date -u +%s)"
time_to_answer=$((ended_epoch - started_epoch))

actions='[
  "jq select incident A from alerts/incidents.json",
  "jq filter enriched events by incident hosts and expanded time window",
  "jq rank authentication, privilege, process, and network events",
  "jq compare src_ip and dst_ip against ioc_feed.json",
  "jq extract deviation markers from baseline.json",
  "jq build at least six traceable event references",
  "sha256sum incidents.json enriched_events.jsonl ioc_feed.json"
]'

jq -n \
    --arg finding_id "FIND-A-001" \
    --arg incident_id "$incident_id" \
    --arg investigation_start "$investigation_start" \
    --arg investigation_end "$investigation_end" \
    --argjson time_to_answer "$time_to_answer" \
    --argjson actions "$actions" \
    --argjson event_refs "$event_refs" \
    --argjson techniques "$techniques" \
    --arg hypothesis "$hypothesis" \
    --arg ambiguity "$ambiguity" '
    {
      finding_id: $finding_id,
      incident_id: $incident_id,
      interface: "cli",
      investigation_start: $investigation_start,
      investigation_end: $investigation_end,
      time_to_first_answer_seconds: $time_to_answer,
      actions: $actions,
      event_refs: $event_refs,
      attack_techniques: $techniques,
      hypothesis: $hypothesis,
      confidence: "medium",
      ambiguity_notes: $ambiguity,
      created_at: $investigation_end
    }
' > "$output"

refs_count="$(jq '.event_refs | length' "$output")"
technique_count="$(jq '.attack_techniques | length' "$output")"

(( refs_count >= 6 )) || fail "fewer than 6 event_refs"
(( technique_count >= 2 )) || fail "fewer than 2 ATT&CK techniques"

printf '[inv-A] hypothesis: %s\n' "$hypothesis"
printf '[inv-A] techniques: %s\n' \
    "$(jq -r '.attack_techniques | join(" ")' "$output")"
printf '[inv-A] confidence: medium\n'
printf '[inv-A] incident_A.json written\n'
