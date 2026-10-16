#!/bin/bash
# MedDefense | IR-2026-0414-01 | LH-2026-0414-01
# Verify three forensic artifacts before analysis. Never alter evidence files.
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="${EVIDENCE_DIR:-$SCRIPT_DIR}"
HASH_FILE="$SCRIPT_DIR/hashes.txt"
LOG_FILE="$SCRIPT_DIR/verification_log.txt"
ACTOR="${ACTOR:-$(id -un)}"

IDS=(ART-001 ART-002 ART-003)
NAMES=(wst-ws-031.dd wst-ws-031.mem wst-ws-017.mem)

utc_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log_event() {
  # TSV: UTC timestamp, actor, artifact ID, status, expected SHA-256, computed SHA-256
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(utc_now)" "$ACTOR" "$1" "$2" "$3" "$4" >> "$LOG_FILE"
}
fail_all() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

command -v sha256sum >/dev/null 2>&1 || fail_all 'sha256sum not installed'
[[ -d "$EVIDENCE_DIR" ]] || fail_all "Evidence directory not found: $EVIDENCE_DIR"
[[ ! -L "$HASH_FILE" && ! -L "$LOG_FILE" ]] || fail_all 'Refusing symlinked baseline or log file'

# Prevent concurrent runs from establishing conflicting baselines.
command -v flock >/dev/null 2>&1 || fail_all 'flock not installed'
exec 9>"$SCRIPT_DIR/.verify_artifacts.lock" || fail_all 'Cannot open lock file'
flock -x 9 || fail_all 'Cannot acquire lock'

# Compute all hashes before creating a baseline; never create a partial baseline.
declare -a COMPUTED=()
missing=0
for i in "${!NAMES[@]}"; do
  path="$EVIDENCE_DIR/${NAMES[$i]}"
  if [[ ! -f "$path" || -L "$path" || ! -r "$path" ]]; then
    printf '[FAIL] %s %s expected=unknown computed=unavailable (missing, unreadable, or symlink)\n' "${IDS[$i]}" "${NAMES[$i]}" >&2
    log_event "${IDS[$i]}" 'FAIL' 'unknown' 'unavailable' || fail_all 'Could not append verification log'
    COMPUTED+=(unavailable)
    missing=1
    continue
  fi
  # Hash only the file content. No command output or filenames are treated as hashes.
  if hash=$(sha256sum -- "$path"); then
    hash="${hash:0:64}"
    if [[ "$hash" =~ ^[[:xdigit:]]{64}$ ]]; then
      COMPUTED+=("${hash,,}")
    else
      COMPUTED+=(unavailable)
      missing=1
    fi
  else
    COMPUTED+=(unavailable)
    missing=1
  fi
done
(( missing == 0 )) || fail_all 'One or more artifacts cannot be hashed. No analysis permitted.'

if [[ ! -e "$HASH_FILE" ]]; then
  tmp=$(mktemp "$SCRIPT_DIR/.hashes.XXXXXXXX") || fail_all 'Cannot create temporary baseline'
  trap 'rm -f -- "$tmp"' EXIT
  chmod 600 "$tmp"
  for i in "${!NAMES[@]}"; do
    printf '%s\t%s\t%s\n' "${IDS[$i]}" "${NAMES[$i]}" "${COMPUTED[$i]}" >> "$tmp"
  done
  # No replacement of an existing baseline. Lock guards normal concurrent invocations.
  [[ ! -e "$HASH_FILE" ]] || fail_all 'Baseline appeared during creation; refusing overwrite'
  mv -n -- "$tmp" "$HASH_FILE" || fail_all 'Cannot write baseline'
  [[ -f "$HASH_FILE" ]] || fail_all 'Baseline not created'
  trap - EXIT
  for i in "${!NAMES[@]}"; do
    printf '[BASELINE_SET] %s %s sha256=%s\n' "${IDS[$i]}" "${NAMES[$i]}" "${COMPUTED[$i]}"
    log_event "${IDS[$i]}" 'BASELINE_SET' 'not_acquired' "${COMPUTED[$i]}" || fail_all 'Cannot append verification log'
  done
  printf 'Baseline written to %s. Run again to verify.\n' "$HASH_FILE"
  # Baseline creation is not verification: require a second run before analysis.
  exit 2
fi

# Strictly validate baseline: exactly three lines in fixed ID/name order.
mapfile -t LINES < "$HASH_FILE" || fail_all 'Cannot read baseline'
[[ ${#LINES[@]} -eq 3 ]] || fail_all 'Invalid baseline: expected exactly 3 entries'
declare -a EXPECTED=()
for i in "${!NAMES[@]}"; do
  IFS=$'\t' read -r id name hash extra <<< "${LINES[$i]}"
  [[ "$id" == "${IDS[$i]}" && "$name" == "${NAMES[$i]}" && "$hash" =~ ^[0-9a-f]{64}$ && -z "${extra:-}" ]] || fail_all "Invalid baseline entry for ${IDS[$i]}"
  EXPECTED+=("$hash")
done

failures=0
for i in "${!NAMES[@]}"; do
  if [[ "${EXPECTED[$i]}" == "${COMPUTED[$i]}" ]]; then
    result=PASS
  else
    result=FAIL
    failures=1
  fi
  printf '[%s] %s %s expected=%s computed=%s\n' "$result" "${IDS[$i]}" "${NAMES[$i]}" "${EXPECTED[$i]}" "${COMPUTED[$i]}"
  log_event "${IDS[$i]}" "$result" "${EXPECTED[$i]}" "${COMPUTED[$i]}" || fail_all 'Could not append verification log'
  if [[ "$result" == FAIL ]]; then
    printf 'DEVIATION %s %s: SHA-256 mismatch; stop analysis and preserve evidence.\n' "$(utc_now)" "${IDS[$i]}" | tee -a "$LOG_FILE" >&2
  fi
done
if (( failures )); then
  printf 'ARTIFACT VERIFICATION FAILED — DO NOT BEGIN ANALYSIS\n' >&2
  exit 1
fi
printf 'ALL ARTIFACTS VERIFIED\n'
exit 0
