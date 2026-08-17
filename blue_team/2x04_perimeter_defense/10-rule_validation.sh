#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RULES="${RULE_FILE:-$SCRIPT_DIR/meddefense.rules}"
LABEL_DIR="${LABEL_DIR:-/home/analyst/MedDefense_Lab/PCAPs/labels}"
CONFIG="${SURICATA_CONFIG:-/etc/suricata/suricata.yaml}"
OUTPUT_JSON="${OUTPUT_JSON:-$SCRIPT_DIR/rule_validation.json}"

declare -a TESTS=(
  "9000001|MEDDEV TCP to Internet|meddev_egress.pcap"
  "9000007|MEDDEV UDP to Internet Non-NTP|meddev_egress.pcap"
  "9000002|Guest to SMB|guest_smb.pcap"
  "9000003|Large Outbound From Server|large_outbound.pcap"
  "9000004|DNS Tunneling Long Label|dns_tunnel.pcap"
  "9000005|Clinical to Unauthorized DB|clinical_wrong_db.pcap"
  "9000006|Telnet to MEDDEV|telnet_meddev.pcap"
)

die() {
  printf '[!] %s\n' "$*" >&2
  exit 2
}

command -v suricata >/dev/null 2>&1 || die "suricata is not installed"
command -v jq >/dev/null 2>&1 || die "jq is not installed"
[[ -r "$RULES" ]] || die "rule file not readable: $RULES"
[[ -r "$CONFIG" ]] || die "Suricata config not readable: $CONFIG"
[[ -d "$LABEL_DIR" ]] || die "labeled PCAP directory not found: $LABEL_DIR"

rule_count="$(grep -Evc '^[[:space:]]*(#|$)' "$RULES")"
printf '[*] Loading meddefense.rules...          %s rules\n' "$rule_count"

# Validate syntax before replaying any capture. -T returns non-zero on bad rules.
syntax_log="$(mktemp "${TMPDIR:-/tmp}/meddefense-rule-test.XXXXXX")"
if ! suricata -T -c "$CONFIG" -S "$RULES" >"$syntax_log" 2>&1; then
  cat "$syntax_log" >&2
  unlink "$syntax_log"
  die "Suricata rejected meddefense.rules"
fi
unlink "$syntax_log"

printf '[*] Running validation against labeled PCAPs...\n\n'
passed=0
failed=0
declare -a RESULTS_JSON=()

for test_case in "${TESTS[@]}"; do
  IFS='|' read -r sid name filename <<<"$test_case"
  pcap="$LABEL_DIR/$filename"
  logdir="$(mktemp -d "${TMPDIR:-/tmp}/meddefense-sid-${sid}.XXXXXX")"
  eve="$logdir/eve.json"

  printf 'sid %s %s\n' "$sid" "$name"
  printf '  target: %s\n' "$filename"
  printf '  expected: fire\n'

  hits=0
  status="PASS"
  if [[ ! -r "$pcap" ]]; then
    printf '  observed: PCAP missing'
    status="FAIL"
  elif ! suricata -c "$CONFIG" -S "$RULES" -r "$pcap" -l "$logdir" \
      >"$logdir/suricata.stdout" 2>"$logdir/suricata.stderr"; then
    printf '  observed: Suricata execution error'
    status="FAIL"
  elif [[ ! -f "$eve" ]]; then
    printf '  observed: eve.json missing'
    status="FAIL"
  else
    hits="$(jq -r --argjson sid "$sid" \
      'select(.event_type == "alert" and .alert.signature_id == $sid) | 1' \
      "$eve" | awk '{sum += $1} END {print sum + 0}')"
    if ((hits > 0)); then
      suffix="hits"
      ((hits == 1)) && suffix="hit"
      printf '  observed: fire (%s %s)' "$hits" "$suffix"
    else
      printf '  observed: did not fire'
      status="FAIL"
    fi
  fi

  if [[ "$status" == "PASS" ]]; then
    ((passed += 1))
  else
    ((failed += 1))
    # Preserve useful diagnostics for a failed engine execution.
    if [[ -s "$logdir/suricata.stderr" ]]; then
      printf '\n  diagnostic: %s' "$(tail -n 1 "$logdir/suricata.stderr")"
    fi
  fi
  printf '%*s%s\n\n' 16 '' "$status"

  RESULTS_JSON+=("$(jq -nc \
    --argjson sid "$sid" \
    --arg name "$name" \
    --arg target "$filename" \
    --argjson hits "$hits" \
    --arg status "$status" \
    '{sid: $sid, name: $name, target: $target, expected: "fire", observed_hits: $hits, status: $status}')")

  rm -rf -- "$logdir"
done

printf 'Rules:  %s\n' "${#TESTS[@]}"
printf 'Passed: %s\n' "$passed"
printf 'Failed: %s\n' "$failed"

printf '%s\n' "${RESULTS_JSON[@]}" | jq -s \
  --argjson rules "${#TESTS[@]}" \
  --argjson passed "$passed" \
  --argjson failed "$failed" \
  '{rules: $rules, passed: $passed, failed: $failed, results: .}' \
  > "$OUTPUT_JSON"
printf '[*] Wrote %s\n' "$OUTPUT_JSON"

if ((failed == 0)); then
  exit 0
else
  exit 1
fi