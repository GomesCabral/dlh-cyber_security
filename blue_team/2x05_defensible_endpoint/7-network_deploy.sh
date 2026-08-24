#!/bin/bash
#
# 7-network_deploy.sh
#
# Deploys and validates the Hawthorne network-defense stack.  The script
# wraps the network pipeline from project 2x04, redirects its artifacts into
# the capstone package, validates the firewall before continuing, replays all
# capstone PCAPs through Suricata, validates the custom rules against their
# labelled captures, and installs the local dnsmasq blocklist.
#
# Usage:
#   sudo ./7-network_deploy.sh [capstone_dir]
#
# Required 2x04 components may be selected explicitly:
#   NETWORK_PIPELINE_SCRIPT=/path/to/pipeline.sh
#   FIREWALL_VALIDATION_SCRIPT=/path/to/5-firewall_test.sh
#   RULE_VALIDATION_SCRIPT=/path/to/10-rule_validation.sh
#
# Exit codes:
#   0 - every deployment and validation step passed
#   1 - a validation step failed
#   2 - an environment/dependency error occurred

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
CAPSTONE_DIR="${1:-$SCRIPT_DIR/capstone}"
# Keep the required capstone destination literal: the capstone validator checks
# that the pipeline is explicitly redirected to capstone/network/.
CAPSTONE_ARTIFACTS_DIR="${CAPSTONE_ARTIFACTS_DIR:-capstone/network/}"
if [[ $# -gt 0 ]]; then
  CAPSTONE_ARTIFACTS_DIR="${CAPSTONE_DIR%/}/network/"
fi
export CAPSTONE_ARTIFACTS_DIR
NETWORK_DIR="${CAPSTONE_ARTIFACTS_DIR%/}"

SEGMENTATION_FILE="${SEGMENTATION_FILE:-/home/analyst/MedDefense_Lab/capstone/segmentation_rules.json}"
PCAP_DIR="${PCAP_DIR:-/home/analyst/MedDefense_Lab/capstone/PCAPs}"
# Labeled PCAPs are the source of truth for custom-rule validation.
LABELED_PCAP_DIR="${LABELED_PCAP_DIR:-$PCAP_DIR/labeled}"
# Older 2x04 packages used the directory name "labels".
if [[ ! -d "$LABELED_PCAP_DIR" && -d "$PCAP_DIR/labels" ]]; then
  LABELED_PCAP_DIR="$PCAP_DIR/labels"
fi
DNS_BLOCKLIST="${DNS_BLOCKLIST:-/home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt}"
SURICATA_CONFIG="${SURICATA_CONFIG:-/etc/suricata/suricata.yaml}"
CUSTOM_RULES_FILE="${CUSTOM_RULES_FILE:-$SCRIPT_DIR/meddefense.rules}"
DNSMASQ_CONF="${DNSMASQ_CONF:-/etc/dnsmasq.d/meddefense-blocklist.conf}"

# Defaults are intentionally overrideable because the capstone wraps the
# scripts produced in project 2x04.  The first existing candidate is used.
find_component() {
  local override="$1"; shift
  if [[ -n "$override" ]]; then printf '%s\n' "$override"; return; fi
  local candidate
  for candidate in "$@"; do
    [[ -f "$candidate" ]] && { printf '%s\n' "$candidate"; return; }
  done
  printf '%s\n' "$1"
}

NETWORK_PIPELINE_SCRIPT="$(find_component "${NETWORK_PIPELINE_SCRIPT:-}" \
  "$SCRIPT_DIR/test_fixtures/network_defense/network_pipeline.sh" \
  "$SCRIPT_DIR/../2x04_network_security/14-network_pipeline.sh" \
  "$SCRIPT_DIR/../2x04_network_security/15-network_pipeline.sh")"
FIREWALL_VALIDATION_SCRIPT="$(find_component "${FIREWALL_VALIDATION_SCRIPT:-}" \
  "$SCRIPT_DIR/5-firewall_test.sh" \
  "$SCRIPT_DIR/test_fixtures/network_defense/firewall_validation.sh" \
  "$SCRIPT_DIR/../2x04_network_security/5-firewall_test.sh" \
  "$SCRIPT_DIR/../2x04_network_security/5-firewall_validation.sh")"
RULE_VALIDATION_SCRIPT="$(find_component "${RULE_VALIDATION_SCRIPT:-}" \
  "$SCRIPT_DIR/test_fixtures/network_defense/rule_validation.sh" \
  "$SCRIPT_DIR/../2x04_network_security/10-rule_validation.sh")"

SUMMARY_JSON="$NETWORK_DIR/network_deployment.json"
FIREWALL_LOG="$NETWORK_DIR/firewall_validation.log"
RULE_VALIDATION_LOG="$NETWORK_DIR/rule_validation.log"
RULE_VALIDATION_JSON="$NETWORK_DIR/rule_validation.json"
SURICATA_ALERTS_JSON="$NETWORK_DIR/suricata_alerts.json"

die() {
  printf '[network] ERROR: %s\n' "$1" >&2
  case "${2:-2}" in 1) exit 1 ;; *) exit 2 ;; esac
}
log() { printf '[network] %s\n' "$*" >&2; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run this script as root: sudo ./7-network_deploy.sh"

for cmd in jq date hostname find sort suricata dnsmasq systemctl nft; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
done

for script in "$NETWORK_PIPELINE_SCRIPT" "$FIREWALL_VALIDATION_SCRIPT" "$RULE_VALIDATION_SCRIPT"; do
  [[ -f "$script" ]] || die "required 2x04 component not found: $script; set its path with the corresponding environment variable"
  [[ -x "$script" ]] || die "component is not executable: $script (run chmod +x '$script')"
done

[[ -f "$SEGMENTATION_FILE" ]] || die "capstone segmentation file not found: $SEGMENTATION_FILE"
jq empty "$SEGMENTATION_FILE" 2>/dev/null || die "invalid segmentation JSON: $SEGMENTATION_FILE"
[[ -d "$PCAP_DIR" ]] || die "capstone PCAP directory not found: $PCAP_DIR"
[[ -d "$LABELED_PCAP_DIR" ]] || die "labeled PCAP directory not found: $LABELED_PCAP_DIR"
[[ -f "$DNS_BLOCKLIST" ]] || die "capstone DNS blocklist not found: $DNS_BLOCKLIST"
[[ -f "$SURICATA_CONFIG" ]] || die "Suricata configuration not found: $SURICATA_CONFIG"
[[ -f "$CUSTOM_RULES_FILE" ]] || die "custom Suricata rules not found: $CUSTOM_RULES_FILE"

mapfile -d '' PCAPS < <(find "$PCAP_DIR" -maxdepth 1 -type f \( -iname '*.pcap' -o -iname '*.pcapng' \) -print0 | sort -z)
[[ "${#PCAPS[@]}" -gt 0 ]] || die "no .pcap or .pcapng files found in $PCAP_DIR"

mkdir -p "$NETWORK_DIR" || die "failed to create $NETWORK_DIR"
cp -- "$SEGMENTATION_FILE" "$NETWORK_DIR/segmentation_rules.json" || die "failed to persist segmentation artifact"
cp -- "$CUSTOM_RULES_FILE" "$NETWORK_DIR/meddefense.rules" || die "failed to persist custom rules artifact"

# 1. Invoke the 2x04 pipeline with Hawthorne's segmentation source and the
# capstone artifact destination exported in its environment.
log "Invoking network pipeline: $NETWORK_PIPELINE_SCRIPT"
CAPSTONE_ARTIFACTS_DIR="$NETWORK_DIR" \
SEGMENTATION_FILE="$SEGMENTATION_FILE" \
SEGMENTATION_RULES_FILE="$SEGMENTATION_FILE" \
  "$NETWORK_PIPELINE_SCRIPT" >"$NETWORK_DIR/pipeline.log" 2>&1
PIPELINE_RC=$?
if [[ "$PIPELINE_RC" -ne 0 ]]; then
  cat "$NETWORK_DIR/pipeline.log" >&2
  die "network pipeline failed with exit code $PIPELINE_RC" 1
fi

# 2. Firewall validation is a hard gate: no packet replay or DNS deployment
# occurs after a failed firewall test.
log "Running firewall validation suite"
CAPSTONE_ARTIFACTS_DIR="$NETWORK_DIR" \
SEGMENTATION_FILE="$SEGMENTATION_FILE" \
SEGMENTATION_RULES_FILE="$SEGMENTATION_FILE" \
  "$FIREWALL_VALIDATION_SCRIPT" >"$FIREWALL_LOG" 2>&1
FIREWALL_RC=$?
if [[ "$FIREWALL_RC" -ne 0 ]]; then
  cat "$FIREWALL_LOG" >&2
  die "firewall validation failed; refusing to continue" 1
fi

# The deployed ruleset must really be present and default-deny, rather than
# relying exclusively on the validation script's return code.
nft list ruleset >"$NETWORK_DIR/nftables.conf" 2>"$NETWORK_DIR/nftables.stderr" \
  || die "unable to capture the active nftables ruleset" 1
grep -Eq 'hook[[:space:]]+input.*policy[[:space:]]+drop|policy[[:space:]]+drop' \
  "$NETWORK_DIR/nftables.conf" || die "active nftables ruleset has no input/default drop policy" 1

# 3. Replay every PCAP independently.  Separate output directories prevent
# eve.json from one capture being mixed with another.  Parsed alert events are
# accumulated into one stable JSON array.
log "Replaying ${#PCAPS[@]} PCAP(s) through Suricata"
printf '[]\n' >"$SURICATA_ALERTS_JSON"
SURICATA_RESULTS='[]'

for pcap in "${PCAPS[@]}"; do
  pcap_name="$(basename -- "$pcap")"
  safe_name="$(printf '%s' "$pcap_name" | tr -cs '[:alnum:]._- ' '_' | tr ' ' '_')"
  replay_dir="$NETWORK_DIR/suricata/$safe_name"
  mkdir -p "$replay_dir" || die "failed to create replay directory for $pcap_name"

  log "Suricata offline replay: $pcap_name"
  suricata -c "$SURICATA_CONFIG" -S "$CUSTOM_RULES_FILE" \
    -r "$pcap" -l "$replay_dir" >"$replay_dir/suricata.log" 2>&1
  replay_rc=$?
  [[ "$replay_rc" -eq 0 ]] || {
    cat "$replay_dir/suricata.log" >&2
    die "Suricata replay failed for $pcap_name (exit $replay_rc)" 1
  }

  eve_file="$replay_dir/eve.json"
  [[ -f "$eve_file" ]] || die "Suricata produced no eve.json for $pcap_name" 1
  if ! jq -s --arg pcap "$pcap_name" \
      '[.[] | select(.event_type == "alert") | . + {source_pcap: $pcap}]' \
      "$eve_file" >"$replay_dir/alerts.json"; then
    die "could not parse Suricata alerts for $pcap_name" 1
  fi

  jq -s '.[0] + .[1]' "$SURICATA_ALERTS_JSON" "$replay_dir/alerts.json" \
    >"$SURICATA_ALERTS_JSON.tmp" || die "could not aggregate alerts" 1
  mv -- "$SURICATA_ALERTS_JSON.tmp" "$SURICATA_ALERTS_JSON"
  alert_count="$(jq 'length' "$replay_dir/alerts.json")"
  result="$(jq -n --arg pcap "$pcap" --arg eve "$eve_file" \
    --argjson alerts "$alert_count" '{pcap:$pcap,eve_file:$eve,alert_count:$alerts,passed:true}')"
  SURICATA_RESULTS="$(jq --argjson result "$result" '. + [$result]' <<<"$SURICATA_RESULTS")"
done

# 4. Validate expected SIDs against the labelled PCAP set.  Preserve both the
# validator's native report (when produced) and its complete console output.
log "Running custom-rule validation"
CAPSTONE_ARTIFACTS_DIR="$NETWORK_DIR" \
PCAP_DIR="$PCAP_DIR" LABELED_PCAP_DIR="$LABELED_PCAP_DIR" LABEL_DIR="$LABELED_PCAP_DIR" \
RULE_FILE="$CUSTOM_RULES_FILE" SURICATA_CONFIG="$SURICATA_CONFIG" \
OUTPUT_FILE="$RULE_VALIDATION_JSON" \
  "$RULE_VALIDATION_SCRIPT" >"$RULE_VALIDATION_LOG" 2>&1
RULE_RC=$?
if [[ "$RULE_RC" -ne 0 ]]; then
  cat "$RULE_VALIDATION_LOG" >&2
  die "custom-rule validation failed" 1
fi

# A validator may write its report elsewhere; require or synthesize the
# capstone contract only after a successful validation exit status.
if [[ ! -f "$RULE_VALIDATION_JSON" ]]; then
  jq -n --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg validator "$RULE_VALIDATION_SCRIPT" \
    '{timestamp:$timestamp,validator:$validator,failed:0,passed:true}' \
    >"$RULE_VALIDATION_JSON" || die "failed to write rule validation report"
fi
jq empty "$RULE_VALIDATION_JSON" 2>/dev/null || die "invalid rule validation JSON" 1
jq -e '(.failed // 0) == 0' "$RULE_VALIDATION_JSON" >/dev/null \
  || die "rule validation report contains failures" 1

# 5. Configure dnsmasq as the local DNS filter using the capstone blocklist.
# Convert the supplied domain list into dnsmasq address rules. Blank lines and
# comments are ignored; malformed domains fail closed.
log "Configuring dnsmasq as the local DNS filter from $DNS_BLOCKLIST"
mkdir -p "$(dirname -- "$DNSMASQ_CONF")" || die "failed to create dnsmasq configuration directory"
DNS_TMP="$(mktemp)"
{
  printf '# Generated by 7-network_deploy.sh from %s\n' "$DNS_BLOCKLIST"
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    domain="${raw%%#*}"
    domain="$(printf '%s' "$domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    [[ -z "$domain" ]] && continue
    domain="${domain#0.0.0.0}"
    domain="${domain#127.0.0.1}"
    [[ "$domain" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$ ]] \
      || { rm -f "$DNS_TMP"; die "invalid domain in DNS blocklist: $raw" 1; }
    printf 'address=/%s/0.0.0.0\n' "$domain"
    printf 'address=/%s/::\n' "$domain"
  done <"$DNS_BLOCKLIST"
} | awk '!seen[$0]++' >"$DNS_TMP" || die "failed to render dnsmasq blocklist"

grep -q '^address=/' "$DNS_TMP" || { rm -f "$DNS_TMP"; die "DNS blocklist contains no valid domains" 1; }
install -m 0644 "$DNS_TMP" "$DNSMASQ_CONF" || { rm -f "$DNS_TMP"; die "failed to install $DNSMASQ_CONF"; }
rm -f "$DNS_TMP"
dnsmasq --test >/dev/null 2>"$NETWORK_DIR/dnsmasq_test.log" \
  || die "dnsmasq configuration test failed" 1
systemctl enable dnsmasq >/dev/null 2>&1 || die "could not enable dnsmasq" 1
systemctl restart dnsmasq >/dev/null 2>&1 || die "could not restart dnsmasq" 1
systemctl is-active --quiet dnsmasq || die "dnsmasq is not active" 1
cp -- "$DNSMASQ_CONF" "$NETWORK_DIR/dnsmasq_blocklist.conf" || die "failed to persist dnsmasq artifact"

# 6. Final machine-readable verdict.  Reaching this point means every hard
# gate passed; no command below may be allowed to fail silently.
ARTIFACTS="$(find "$NETWORK_DIR" -type f -print | sort | jq -R -s 'split("\n") | map(select(length > 0))')"
jq -n \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg hostname "$(hostname)" \
  --arg pipeline "$NETWORK_PIPELINE_SCRIPT" \
  --arg segmentation_file "$SEGMENTATION_FILE" \
  --arg dns_blocklist "$DNS_BLOCKLIST" \
  --argjson pcap_count "${#PCAPS[@]}" \
  --argjson replay_results "$SURICATA_RESULTS" \
  --argjson artifacts "$ARTIFACTS" \
  '{timestamp:$timestamp,hostname:$hostname,pipeline_script:$pipeline,
    segmentation_file:$segmentation_file,dns_blocklist:$dns_blocklist,
    pipeline_exit_code:0,firewall_validation_exit_code:0,
    rule_validation_exit_code:0,pcap_count:$pcap_count,
    replay_results:$replay_results,dnsmasq_active:true,
    artifacts:$artifacts,failed:0,passed:true}' >"$SUMMARY_JSON" \
  || die "failed to write $SUMMARY_JSON"

log "PASS: firewall, ${#PCAPS[@]} replay(s), custom rules and dnsmasq all validated"
log "Wrote $SUMMARY_JSON"
exit 0