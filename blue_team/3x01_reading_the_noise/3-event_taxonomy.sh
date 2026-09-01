#!/bin/bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"
readonly DATASET="${HANDOFF_DIR}/data/enriched_events.json"
readonly TAXONOMY_FILE="${SCRIPT_DIR}/event_taxonomy.json"
readonly LABELED_FILE="${SCRIPT_DIR}/labeled_events.json"

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

command -v jq >/dev/null 2>&1 || die "jq is required"
[[ -r "$DATASET" ]] || die "dataset is not readable: $DATASET"
jq empty "$DATASET" 2>/dev/null || die "dataset is not valid JSON or NDJSON: $DATASET"

taxonomy_tmp=$(mktemp "${SCRIPT_DIR}/.event_taxonomy.XXXXXX")
labeled_tmp=$(mktemp "${SCRIPT_DIR}/.labeled_events.XXXXXX")
cleanup() {
    rm -f -- "$taxonomy_tmp" "$labeled_tmp"
}
trap cleanup EXIT

cat >"$taxonomy_tmp" <<'JSON'
{
  "taxonomy_version": 1,
  "matching_policy": "first matching rule wins",
  "canonical_labels": [
    {
      "label": "account_lockout",
      "rules": [
        {"source_type":"windows","match":{"event_id":4740},"label":"account_lockout"},
        {"source_type":"linux","match":{"event_category":"authentication","event_action":"account_lockout"},"label":"account_lockout"}
      ]
    },
    {
      "label": "login_failure",
      "rules": [
        {"source_type":"windows","match":{"event_id":4625},"label":"login_failure"},
        {"source_type":"linux","match":{"event_category":"authentication","outcome":"failure"},"label":"login_failure"}
      ]
    },
    {
      "label": "login_success",
      "rules": [
        {"source_type":"windows","match":{"event_id":4624},"label":"login_success"},
        {"source_type":"linux","match":{"event_category":"authentication","outcome":"success"},"label":"login_success"}
      ]
    },
    {
      "label": "logout",
      "rules": [
        {"source_type":"windows","match":{"event_id":4634},"label":"logout"},
        {"source_type":"windows","match":{"event_id":4647},"label":"logout"},
        {"source_type":"linux","match":{"event_category":"session","event_action":"logout"},"label":"logout"},
        {"source_type":"linux","match":{"event_category":"session","event_action":"session_closed"},"label":"logout"}
      ]
    },
    {
      "label": "privilege_escalation",
      "rules": [
        {"source_type":"windows","match":{"event_id":4672},"label":"privilege_escalation"},
        {"source_type":"linux","match":{"event_category":"privilege"},"label":"privilege_escalation"},
        {"source_type":"linux","match":{"event_action":"sudo"},"label":"privilege_escalation"}
      ]
    },
    {
      "label": "child_process_spawn",
      "rules": [
        {"source_type":"windows","match":{"event_id":1,"event_category":"process"},"label":"child_process_spawn"},
        {"source_type":"linux","match":{"audit_type":"EXECVE","event_category":"process"},"label":"child_process_spawn"}
      ]
    },
    {
      "label": "process_start",
      "rules": [
        {"source_type":"windows","match":{"event_id":4688},"label":"process_start"},
        {"source_type":"windows","match":{"event_category":"process","event_action":"process_start"},"label":"process_start"},
        {"source_type":"linux","match":{"event_category":"process","event_action":"process_start"},"label":"process_start"},
        {"source_type":"linux","match":{"event_category":"process","outcome":"success"},"label":"process_start"}
      ]
    },
    {
      "label": "process_stop",
      "rules": [
        {"source_type":"windows","match":{"event_id":4689},"label":"process_stop"},
        {"source_type":"windows","match":{"event_id":5,"event_category":"process"},"label":"process_stop"},
        {"source_type":"linux","match":{"event_category":"process","event_action":"process_stop"},"label":"process_stop"}
      ]
    },
    {
      "label": "file_permission_change",
      "rules": [
        {"source_type":"linux","match":{"event_category":"file_operation","event_action":"chmod"},"label":"file_permission_change"},
        {"source_type":"linux","match":{"event_category":"file_operation","event_action":"chown"},"label":"file_permission_change"},
        {"source_type":"linux","match":{"audit_type":"CHMOD"},"label":"file_permission_change"},
        {"source_type":"linux","match":{"audit_type":"CHOWN"},"label":"file_permission_change"},
        {"source_type":"windows","match":{"event_id":4670},"label":"file_permission_change"}
      ]
    },
    {
      "label": "file_read_sensitive",
      "rules": [
        {"source_type":"linux","match":{"event_action":"read","file_path":"/etc/shadow"},"label":"file_read_sensitive"},
        {"source_type":"linux","match":{"event_action":"read","file_path":"/etc/sudoers"},"label":"file_read_sensitive"},
        {"source_type":"linux","match":{"event_action":"read","file_path":"/etc/ssh/sshd_config"},"label":"file_read_sensitive"},
        {"source_type":"windows","match":{"event_id":4663,"event_action":"read_sensitive"},"label":"file_read_sensitive"}
      ]
    },
    {
      "label": "file_write_sensitive",
      "rules": [
        {"source_type":"linux","match":{"event_action":"write","file_path":"/etc/shadow"},"label":"file_write_sensitive"},
        {"source_type":"linux","match":{"event_action":"write","file_path":"/etc/sudoers"},"label":"file_write_sensitive"},
        {"source_type":"linux","match":{"event_action":"write","file_path":"/etc/ssh/sshd_config"},"label":"file_write_sensitive"},
        {"source_type":"windows","match":{"event_id":11,"event_category":"file_operation"},"label":"file_write_sensitive"}
      ]
    },
    {
      "label": "network_blocked",
      "rules": [
        {"source_type":"firewall","match":{"action":"BLOCK"},"label":"network_blocked"},
        {"source_type":"firewall","match":{"outcome":"blocked"},"label":"network_blocked"}
      ]
    },
    {
      "label": "network_alert",
      "rules": [
        {"source_type":"suricata","match":{"event_category":"network_alert"},"label":"network_alert"},
        {"source_type":"suricata","match":{"event_category":"alert"},"label":"network_alert"}
      ]
    },
    {
      "label": "network_connection_outbound",
      "rules": [
        {"source_type":"firewall","match":{"action":"ALLOW","network_direction":"outbound"},"label":"network_connection_outbound"},
        {"source_type":"windows","match":{"event_category":"network","network_direction":"outbound"},"label":"network_connection_outbound"},
        {"source_type":"linux","match":{"event_category":"network","network_direction":"outbound"},"label":"network_connection_outbound"},
        {"source_type":"pcap","match":{"event_category":"network_flow","network_direction":"outbound"},"label":"network_connection_outbound"}
      ]
    },
    {
      "label": "network_connection_inbound",
      "rules": [
        {"source_type":"firewall","match":{"action":"ALLOW","network_direction":"inbound"},"label":"network_connection_inbound"},
        {"source_type":"windows","match":{"event_category":"network","network_direction":"inbound"},"label":"network_connection_inbound"},
        {"source_type":"linux","match":{"event_category":"network","network_direction":"inbound"},"label":"network_connection_inbound"},
        {"source_type":"pcap","match":{"event_category":"network_flow","network_direction":"inbound"},"label":"network_connection_inbound"}
      ]
    }
  ]
}
JSON

jq -e '
    .canonical_labels as $labels
    | ($labels | length) == 15
      and all($labels[]; (.label | type) == "string" and (.rules | length) > 0)
      and all($labels[].rules[];
          (.source_type | type) == "string"
          and (.match | type) == "object"
          and (.label | type) == "string")
' "$taxonomy_tmp" >/dev/null || die "generated taxonomy failed validation"

jq -c --slurpfile taxonomy "$taxonomy_tmp" '
    def records: if type == "array" then .[] else . end;
    def field_value($name):
        if ($name | contains(".")) then getpath($name | split("."))?
        else .[$name]?
        end;
    def same_value($actual; $expected):
        if ($actual | type) == "array"
        then any($actual[]; . == $expected or tostring == ($expected | tostring))
        else $actual == $expected or ($actual != null and ($actual | tostring) == ($expected | tostring))
        end;
    def rule_matches($event; $rule):
        ($event.source_type? == $rule.source_type)
        and all($rule.match | to_entries[];
            . as $criterion
            | same_value($event | field_value($criterion.key); $criterion.value));
    def choose_label($event):
        [ $taxonomy[0].canonical_labels[].rules[]
          | select(rule_matches($event; .))
          | .label ][0] // "unlabeled";
    records | . as $event | . + {canonical_label: choose_label($event)}
' "$DATASET" >"$labeled_tmp"

taxonomy_rules=$(jq '[.canonical_labels[].rules[]] | length' "$taxonomy_tmp")
records_labeled=$(jq -r 'select(.canonical_label != "unlabeled") | 1' "$labeled_tmp" |
    awk 'END { print NR + 0 }')
records_unlabeled=$(jq -r 'select(.canonical_label == "unlabeled") | 1' "$labeled_tmp" |
    awk 'END { print NR + 0 }')

mv -f -- "$taxonomy_tmp" "$TAXONOMY_FILE"
mv -f -- "$labeled_tmp" "$LABELED_FILE"
chmod 0644 "$TAXONOMY_FILE" "$LABELED_FILE"

printf 'taxonomy rules         : %s\n' "$taxonomy_rules"
printf 'records labeled        : %s\n' "$records_labeled"
printf 'records unlabeled      : %s\n' "$records_unlabeled"
printf 'canonical label distribution (top 10):\n'
jq -r '.canonical_label' "$LABELED_FILE" |
    LC_ALL=C sort |
    uniq -c |
    LC_ALL=C sort -k1,1nr -k2,2 |
    awk 'NR <= 10 { printf "  %-27s %s\n", $2, $1 }'
printf 'event_taxonomy.json written\n'
printf 'labeled_events.json written\n'

