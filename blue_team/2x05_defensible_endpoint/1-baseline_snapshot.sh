#!/bin/bash
#
# 1-baseline_snapshot.sh
#
# Runs a recognized hardening audit (lynis) against the Linux endpoint and
# persists the raw baseline output plus the extracted score. This number
# is the denominator of the delta reported at the end of the capstone --
# the intake (task 0) says what is there; this says how far it is from
# hardened.
#
# Usage:
#   sudo ./1-baseline_snapshot.sh [capstone_dir]
#
# Exit codes:
#   0 - success, baseline captured and written
#   1 - controlled failure (audit ran but a required value could not be parsed)
#   2 - environment error (missing lynis / cannot install it / cannot write output)
#
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
CAPSTONE_DIR="${1:-$SCRIPT_DIR/capstone}"
BASELINE_DIR="$CAPSTONE_DIR/baseline"
LOG_FILE="$BASELINE_DIR/lynis_baseline.log"
OUTPUT_JSON="$BASELINE_DIR/baseline_linux.json"
LYNIS_REPORT_DAT="${LYNIS_REPORT_DAT:-/var/log/lynis-report.dat}"

WARNINGS=0
log()  { printf '[baseline] %s\n' "$*" >&2; }
warn() { printf '[baseline] WARNING: %s\n' "$*" >&2; WARNINGS=$((WARNINGS + 1)); }
die()  { printf '[baseline] ERROR: %s\n' "$*" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "this script must be run as root (sudo ./1-baseline_snapshot.sh)"

for cmd in hostname date jq; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
done

# lynis is installed idempotently, matching the pattern used elsewhere in
# this project (e.g. 13-dns_filtering.sh installing dnsmasq if missing).
if ! command -v lynis >/dev/null 2>&1; then
  log "lynis not found -- installing"
  apt-get update -qq || die "apt-get update failed; cannot install lynis"
  DEBIAN_FRONTEND=noninteractive apt-get install -y lynis >/dev/null \
    || die "failed to install lynis"
fi
command -v lynis >/dev/null 2>&1 || die "lynis installation did not produce a usable binary"

mkdir -p "$BASELINE_DIR" || die "failed to create $BASELINE_DIR"
[[ -w "$BASELINE_DIR" ]] || die "$BASELINE_DIR is not writable"

LYNIS_VERSION="$(lynis --version 2>/dev/null | head -1)"
[[ -n "$LYNIS_VERSION" ]] || LYNIS_VERSION="unknown"

# ---------------------------------------------------------------------------
# Run the audit. --quick auto-advances through prompts; --no-colors keeps
# the captured log readable outside a terminal.
# ---------------------------------------------------------------------------
log "Running lynis audit system --quick --no-colors (this can take a minute)..."
lynis audit system --quick --no-colors > "$LOG_FILE" 2>&1
LYNIS_EXIT=$?
log "lynis exited with code $LYNIS_EXIT; full log at $LOG_FILE"

[[ -s "$LOG_FILE" ]] || die "lynis produced an empty log at $LOG_FILE"

# ---------------------------------------------------------------------------
# Parse the Hardening Index and warning/suggestion counts.
#
# Primary source: lynis's own structured report.dat (hardening_index=NN,
# one warning[]=... / suggestion[]=... line per finding) -- this is more
# reliable than regexing the free-text summary, and it IS lynis's own
# output, just in its machine-readable form rather than the terminal log.
#
# Fallback: regex against the captured terminal log itself, used only if
# report.dat is unavailable, so the script still produces a result on a
# lynis install/config that doesn't write report.dat to the usual path.
# ---------------------------------------------------------------------------
HARDENING_INDEX=""
WARNINGS_COUNT=""
SUGGESTIONS_COUNT=""

if [[ -r "$LYNIS_REPORT_DAT" ]]; then
  HARDENING_INDEX="$(grep -m1 '^hardening_index=' "$LYNIS_REPORT_DAT" | cut -d= -f2)"
  WARNINGS_COUNT="$(grep -c '^warning\[\]' "$LYNIS_REPORT_DAT")"
  SUGGESTIONS_COUNT="$(grep -c '^suggestion\[\]' "$LYNIS_REPORT_DAT")"
else
  warn "lynis report.dat not readable at $LYNIS_REPORT_DAT; falling back to log parsing"
fi

if [[ -z "$HARDENING_INDEX" ]]; then
  HARDENING_INDEX="$(grep -m1 -oE 'Hardening index[[:space:]]*:[[:space:]]*[0-9]+' "$LOG_FILE" \
    | grep -oE '[0-9]+$')"
fi
if [[ -z "$WARNINGS_COUNT" ]]; then
  WARNINGS_COUNT="$(grep -m1 -oE 'Warnings[[:space:]]*\([0-9]+\)' "$LOG_FILE" \
    | grep -oE '[0-9]+')"
fi
if [[ -z "$SUGGESTIONS_COUNT" ]]; then
  SUGGESTIONS_COUNT="$(grep -m1 -oE 'Suggestions[[:space:]]*\([0-9]+\)' "$LOG_FILE" \
    | grep -oE '[0-9]+')"
fi

if [[ -z "$HARDENING_INDEX" ]]; then
  warn "could not parse Hardening Index from either report.dat or the log"
  HARDENING_INDEX="null"
fi
[[ -n "$WARNINGS_COUNT" ]] || { warn "could not parse warnings count"; WARNINGS_COUNT="null"; }
[[ -n "$SUGGESTIONS_COUNT" ]] || { warn "could not parse suggestions count"; SUGGESTIONS_COUNT="null"; }

# ---------------------------------------------------------------------------
# Emit baseline_linux.json
# ---------------------------------------------------------------------------
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME_VAL="$(hostname)"

jq -n \
  --arg timestamp "$TIMESTAMP" \
  --arg hostname "$HOSTNAME_VAL" \
  --arg lynis_version "$LYNIS_VERSION" \
  --argjson hardening_index "$HARDENING_INDEX" \
  --argjson warnings_count "$WARNINGS_COUNT" \
  --argjson suggestions_count "$SUGGESTIONS_COUNT" \
  --arg log_path "$LOG_FILE" \
  '{
    timestamp: $timestamp,
    hostname: $hostname,
    lynis_version: $lynis_version,
    hardening_index: $hardening_index,
    warnings_count: $warnings_count,
    suggestions_count: $suggestions_count,
    log_path: $log_path
  }' > "$OUTPUT_JSON" || die "failed to write $OUTPUT_JSON"

log "Wrote $OUTPUT_JSON"
log "hardening_index=$HARDENING_INDEX warnings=$WARNINGS_COUNT suggestions=$SUGGESTIONS_COUNT"

if [[ "$WARNINGS" -gt 0 ]]; then
  log "completed with $WARNINGS warning(s) -- see above"
  exit 1
fi

exit 0