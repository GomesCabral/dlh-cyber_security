#!/bin/bash
# MedDefense IR-2026-0420-01 | fail-closed recovery validation
# Reads independently exported evidence from a trusted validation directory.
# It does NOT connect to production or change any endpoint. No checks are pre-marked PASS.
# Requires bash, jq, sha256sum, curl, date (GNU date).
set -uo pipefail
DIR="${EVIDENCE_DIR:-./validation_evidence}"
C2_DOMAIN='staging.office365-cdn.net'
C2_IP='45.152.66.114'
HOSTS=(CS-WS-101 CS-WS-104 CS-WS-107 CS-WS-112 FILE-SVR-01)
failed=0
pass(){ printf '[PASS] %s: %s\n' "$1" "$2"; }
fail(){ printf '[FAIL] %s: %s\n' "$1" "$2"; failed=$((failed+1)); }
need_json(){ [[ -s "$1" ]] && jq -e . "$1" >/dev/null 2>&1; }
now_epoch=$(date -u +%s)

# Expected JSON exports (schema defined in README-like comments below):
# process_events.json: [{"host":"...","timestamp":"ISO UTC","image":"...","parent_image":"..."}]
# network_events.json: [{"host":"...","timestamp":"ISO UTC","destination":"domain or IP","action":"allow|block"}]
# staging_inventory.json: [{"host":"...","path":"...","malicious":true|false}]
# edr_agents.json: [{"host":"...","last_seen":"ISO UTC","healthy":true|false}]
# sigma_status.json: {"rule":"sigma_cobalt_strike_beacon.yml","enabled":true,"test_hit":true,"tested_at":"ISO UTC"}
# hashes.sha256: standard sha256sum lines, relative to DIR; baseline from independent acquisition record.
# Note: these files MUST be complete trusted exports, not hand-authored samples.

if need_json "$DIR/process_events.json"; then
  # Export must be marked complete for all hosts and the entire lookback interval.
  if [[ -f "$DIR/process_coverage.json" ]] && jq -e --argjson n 5 '.complete == true and (.hosts|length) == $n and .window_hours >= 24' "$DIR/process_coverage.json" >/dev/null 2>&1; then
    bad=$(jq --argjson now "$now_epoch" --arg domain "$C2_DOMAIN" '
      [ .[] | select((.image // "" | ascii_downcase | contains("svchost32.exe")) or
       (.parent_image // "" | ascii_downcase | contains("svchost32.exe"))) |
       select((.timestamp | fromdateiso8601?) as $t | $t != null and $t >= ($now-86400) and $t <= $now)] | length' "$DIR/process_events.json" 2>/dev/null) || bad='error'
    if [[ "$bad" == 0 ]]; then pass beacon 'No suspicious svchost32.exe process ancestry in complete 24h export'; else fail beacon "Suspicious process events or invalid timestamps (count=$bad)"; fi
  else fail beacon 'Missing/incomplete 24h process telemetry coverage for five hosts'; fi
else fail beacon 'Missing/invalid process_events.json'; fi

if need_json "$DIR/network_events.json" && [[ -f "$DIR/network_coverage.json" ]] && jq -e '.complete == true and .window_hours >= 24 and (.hosts|length) == 5' "$DIR/network_coverage.json" >/dev/null 2>&1; then
  bad=$(jq --arg dom "$C2_DOMAIN" --arg ip "$C2_IP" --argjson now "$now_epoch" '
    [ .[] | select((.destination|ascii_downcase) == $dom or .destination == $ip) |
      select((.action|ascii_downcase) == "allow" or (.action|ascii_downcase) == "success") |
      select((.timestamp | fromdateiso8601?) as $t | $t != null and $t >= ($now-86400) and $t <= $now)] | length' "$DIR/network_events.json" 2>/dev/null) || bad='error'
  if [[ "$bad" == 0 ]]; then pass c2 'No successful C2 connections in complete 24h export'; else fail c2 "Allowed C2 connections or invalid export (count=$bad)"; fi
else fail c2 'Missing/incomplete network events or coverage'; fi

if need_json "$DIR/staging_inventory.json"; then
  if [[ -f "$DIR/staging_coverage.json" ]] && jq -e '.complete == true and (.hosts|length) == 5 and .paths_scanned == ["C:\\Windows\\System32", "C:\\ProgramData", "C:\\Windows\\Tasks"]' "$DIR/staging_coverage.json" >/dev/null 2>&1; then
    bad=$(jq '[.[] | select(.malicious == true and (.path|ascii_downcase|test("\\.(bat|ps1)$")))] | length' "$DIR/staging_inventory.json" 2>/dev/null) || bad='error'
    if [[ "$bad" == 0 ]]; then pass 'ransomware staging' 'No identified malicious scripts in scanned system directories'; else fail 'ransomware staging' "Malicious scripts found or invalid inventory (count=$bad)"; fi
  else fail 'ransomware staging' 'Inventory coverage incomplete'; fi
else fail 'ransomware staging' 'Missing/invalid staging_inventory.json'; fi

# URLs supplied by operator; no default fake endpoint or success.
service_fail=0
for service in epic-api lis-api scheduling-api; do
  var="${service//-/_}_URL"; var="${var^^}"; url="${!var:-}"
  if [[ -z "$url" || "$url" != https://* ]]; then service_fail=1; continue; fi
  code=$(curl -sS -k --connect-timeout 5 --max-time 12 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null) || code=000
  [[ "$code" == 200 ]] || service_fail=1
done
if [[ "$service_fail" == 0 ]]; then pass services 'epic-api, lis-api, scheduling-api returned HTTP 200'; else fail services 'One or more HTTPS service endpoints missing or not HTTP 200'; fi

if need_json "$DIR/edr_agents.json"; then
  edr_bad=$(jq --argjson now "$now_epoch" --argjson hosts "$(printf '%s\n' "${HOSTS[@]}" | jq -R . | jq -s .)" '
    [ $hosts[] as $h | if ([.[] | select(.host == $h and .healthy == true and ((.last_seen | fromdateiso8601?) as $t | $t != null and $t >= ($now-300) and $t <= $now))] | length) > 0 then empty else $h end ] | length' "$DIR/edr_agents.json" 2>/dev/null) || edr_bad='error'
  if [[ "$edr_bad" == 0 ]]; then pass edr 'All five EDR agents healthy and reporting within 5 minutes'; else fail edr "Missing/stale/unhealthy hosts (count=$edr_bad)"; fi
else fail edr 'Missing/invalid edr_agents.json'; fi

if need_json "$DIR/sigma_status.json" && jq -e --argjson now "$now_epoch" '.rule == "sigma_cobalt_strike_beacon.yml" and .enabled == true and .test_hit == true and ((.tested_at | fromdateiso8601?) as $t | $t != null and $t >= ($now-86400) and $t <= $now)' "$DIR/sigma_status.json" >/dev/null 2>&1; then
 pass detection 'Sigma rule enabled; synthetic event hit verified within 24h'
else fail detection 'Missing/inactive Sigma rule or no recent successful test'; fi

if [[ -s "$DIR/hashes.sha256" ]]; then
  count=$(grep -cE '^[a-fA-F0-9]{64}  ' "$DIR/hashes.sha256" || true)
  if [[ "$count" == 11 ]] && (cd "$DIR" && sha256sum --status -c hashes.sha256) 2>/dev/null; then
    pass 'evidence hashes' '11/11 artifacts match independently recorded SHA-256 baselines'
  else fail 'evidence hashes' 'Missing artifact, checksum mismatch, or not exactly 11 baselines'; fi
else fail 'evidence hashes' 'Missing hashes.sha256 baseline manifest'; fi

if ((failed == 0)); then echo 'ALL CHECKS PASSED'; exit 0; else printf 'RECOVERY NOT VALIDATED: %d check(s) failed\n' "$failed"; exit 1; fi
