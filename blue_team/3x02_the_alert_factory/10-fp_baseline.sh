#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
RULES_DIR="${RULES_DIR:-$SCRIPT_DIR/rules/sigma}"
RUNNER="${SIGMA_RUNNER:-$SCRIPT_DIR/3-sigma_runner.sh}"
BASELINE_SUMMARY="$BASELINE_PKG/baselines/baseline_summary.json"
OUTPUT="${OUTPUT_FILE:-$SCRIPT_DIR/fp_baseline.json}"

for path in "$BASELINE_SUMMARY" "$RUNNER"; do
    [[ -r "$path" ]] || { printf 'ERROR: unreadable dependency: %s\n' "$path" >&2; exit 1; }
done
[[ -x "$RUNNER" ]] || { printf 'ERROR: runner is not executable: %s\n' "$RUNNER" >&2; exit 1; }
[[ -d "$RULES_DIR" ]] || { printf 'ERROR: rules directory missing: %s\n' "$RULES_DIR" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { printf 'ERROR: jq is required\n' >&2; exit 1; }

readarray -t bounds < <(python3 -W error /dev/fd/3 "$BASELINE_SUMMARY" 3<<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    document = json.load(stream)

start_paths = (
    ("baseline_window_start",), ("baseline_window", "start"),
    ("baseline", "window_start"), ("baseline", "start"),
    ("window_start",), ("window", "start"),
)
end_paths = (
    ("baseline_window_end",), ("baseline_window", "end"),
    ("baseline", "window_end"), ("baseline", "end"),
    ("window_end",), ("window", "end"),
)

def find(paths):
    for path in paths:
        value = document
        for key in path:
            if not isinstance(value, dict) or key not in value:
                break
            value = value[key]
        else:
            if isinstance(value, str) and value:
                return value
    raise ValueError("baseline window boundary not found")

print(find(start_paths))
print(find(end_paths))
PY
)

if (( ${#bounds[@]} != 2 )); then
    printf 'ERROR: could not derive baseline window from %s\n' "$BASELINE_SUMMARY" >&2
    exit 1
fi
window_start="${bounds[0]}"
window_end="${bounds[1]}"

window_days="$(python3 -W error - "$window_start" "$window_end" <<'PY'
import datetime as dt
import sys

def parse(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))

duration = (parse(sys.argv[2]) - parse(sys.argv[1])).total_seconds() / 86400
if duration <= 0:
    raise ValueError("baseline window is empty or reversed")
print(f"{duration:.10f}")
PY
)"

mapfile -t rules < <(find "$RULES_DIR" -maxdepth 1 -type f \
    \( -name '*.yml' -o -name '*.yaml' \) -print | sort)
(( ${#rules[@]} > 0 )) || { printf 'ERROR: no Sigma rules found\n' >&2; exit 1; }

printf 'evaluating %d rules against baseline window %s -> %s\n' \
    "${#rules[@]}" "${window_start%%T*}" "${window_end%%T*}"

entries=()
rows=()
for rule in "${rules[@]}"; do
    if ! result="$("$RUNNER" "$rule" --window "$window_start,$window_end")"; then
        printf 'ERROR: runner failed for %s\n' "$rule" >&2
        exit 1
    fi
    jq -e 'has("rule_id") and has("rule_title") and has("level") and
        (.match_count | type == "number")' >/dev/null <<<"$result" || {
        printf 'ERROR: invalid runner JSON for %s\n' "$rule" >&2
        exit 1
    }

    rule_id="$(jq -r '.rule_id' <<<"$result")"
    rule_title="$(jq -r '.rule_title' <<<"$result")"
    level="$(jq -r '.level' <<<"$result")"
    fp_count="$(jq -r '.match_count' <<<"$result")"

    entries+=("$(jq -cn --arg id "$rule_id" --arg title "$rule_title" \
        --arg level "$level" --arg start "$window_start" --arg end "$window_end" \
        --argjson fp "$fp_count" --argjson days "$window_days" \
        '{rule_id:$id,rule_title:$title,level:$level,fp_count:$fp,
          baseline_window_start:$start,baseline_window_end:$end,
          fp_rate_per_day:(($fp/$days*10000)|round/10000)}')")

    name="$(basename -- "$rule")"
    number="${name:0:3}"
    name="${name%.*}"
    name="${name#*_}"
    marker=""
    (( fp_count > 10 )) && marker="[TUNE]"
    rows+=("${fp_count}"$'\t'"${number}"$'\t'"${name}"$'\t'"${marker}")
done

printf '%s\n' "${entries[@]}" | jq -s 'sort_by(.rule_id)' > "$OUTPUT"
printf '%s\n' "${rows[@]}" | sort -t $'\t' -k1,1nr -k2,2 |
while IFS=$'\t' read -r fp number name marker; do
    printf '  %s %-32s fp=%3d' "$number" "$name" "$fp"
    [[ -z "$marker" ]] || printf '   %s' "$marker"
    printf '\n'
done
printf '%s written\n' "$(basename -- "$OUTPUT")"
