#!/bin/bash

set -Eeuo pipefail

readonly HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"
readonly DATASET="${HANDOFF_DIR}/data/enriched_events.json"

usage() {
    cat <<'EOF'
query_toolkit.sh <verb> [options]
  filter   emit matching records as ndjson
  top      top N values of a field
  distinct distinct values of a field
  count    number of matching records
  window   bucketed counts by time window
  help     this message

Filters (accepted in any combination):
  --source <type>   source type
  --host <host>     host name
  --from <iso>      timestamp at or after this ISO-8601 value
  --to <iso>        timestamp before this ISO-8601 value
  --category <cat>  event category

Verb-specific options:
  top      --field <name> --limit <positive integer>
  distinct --field <name>
  window   --field <name> --bucket <hour|day>
EOF
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

[[ $# -gt 0 ]] || {
    usage >&2
    exit 2
}

verb=$1
shift

case "$verb" in
    help)
        [[ $# -eq 0 ]] || die "help does not accept options"
        usage
        exit 0
        ;;
    filter | top | distinct | count | window) ;;
    *)
        usage >&2
        die "unknown verb: $verb"
        ;;
esac

source_filter=''
host_filter=''
from_filter=''
to_filter=''
category_filter=''
field=''
limit=''
bucket=''

while [[ $# -gt 0 ]]; do
    option=$1
    case "$option" in
        --source | --host | --from | --to | --category | --field | --limit | --bucket)
            [[ $# -ge 2 ]] || die "missing value for $option"
            value=$2
            shift 2
            ;;
        *)
            die "unknown option: $option"
            ;;
    esac

    case "$option" in
        --source) source_filter=$value ;;
        --host) host_filter=$value ;;
        --from) from_filter=$value ;;
        --to) to_filter=$value ;;
        --category) category_filter=$value ;;
        --field) field=$value ;;
        --limit) limit=$value ;;
        --bucket) bucket=$value ;;
    esac
done

[[ -r "$DATASET" ]] || die "dataset is not readable: $DATASET"
jq empty "$DATASET" 2>/dev/null || die "dataset is not valid JSON or NDJSON: $DATASET"

case "$verb" in
    filter | count)
        [[ -z "$field" && -z "$limit" && -z "$bucket" ]] ||
            die "$verb does not accept --field, --limit, or --bucket"
        ;;
    top)
        [[ -n "$field" ]] || die "top requires --field"
        [[ "$limit" =~ ^[1-9][0-9]*$ ]] || die "top requires a positive integer --limit"
        [[ -z "$bucket" ]] || die "top does not accept --bucket"
        ;;
    distinct)
        [[ -n "$field" ]] || die "distinct requires --field"
        [[ -z "$limit" && -z "$bucket" ]] ||
            die "distinct does not accept --limit or --bucket"
        ;;
    window)
        [[ -n "$field" ]] || die "window requires --field"
        [[ "$bucket" == "hour" || "$bucket" == "day" ]] ||
            die "window requires --bucket hour or --bucket day"
        [[ -z "$limit" ]] || die "window does not accept --limit"
        ;;
esac

readonly JQ_COMMON='
  def records: if type == "array" then .[] else . end;
  def by_path($name):
    if ($name | contains(".")) then getpath($name | split("."))?
    else .[$name]?
    end;
  def source_value:
    .source_type? // .source.type? // .source? // .event.source? // .observer.type?;
  def host_value:
    .host.name? // .host.hostname? // .hostname? // .host? // .computer_name? // .agent.name?;
  def category_value:
    .event.category? // .event_category? // .category?;
  def time_value:
    .timestamp? // .["@timestamp"]? // .event.created? // .event.start? // .time?;
  def scalar_match($actual; $wanted):
    if ($actual | type) == "array"
    then any($actual[]; tostring == $wanted)
    else ($actual != null and ($actual | tostring) == $wanted)
    end;
  def selected:
    ($source == "" or scalar_match(source_value; $source)) and
    ($host == "" or scalar_match(host_value; $host)) and
    ($category == "" or scalar_match(category_value; $category)) and
    ($from == "" or ((time_value // "") >= $from)) and
    ($to == "" or ((time_value // "") < $to));
'

jq_args=(
    --arg source "$source_filter"
    --arg host "$host_filter"
    --arg from "$from_filter"
    --arg to "$to_filter"
    --arg category "$category_filter"
)

case "$verb" in
    filter)
        jq -c "${JQ_COMMON} records | select(selected)" "${jq_args[@]}" "$DATASET"
        ;;
    count)
        jq -s "${JQ_COMMON} [ .[] | records | select(selected) ] | length" \
            "${jq_args[@]}" "$DATASET"
        ;;
    top)
        jq -rs "${JQ_COMMON}
            [ .[] | records | select(selected) | by_path(\$field)
              | if type == \"array\" then .[] else . end
              | select(. != null) | tostring ]
            | group_by(.)
            | map({value: .[0], count: length})
            | sort_by([-.count, .value])
            | .[:\$limit][]
            | [ .value, (.count | tostring) ] | @tsv" \
            "${jq_args[@]}" --arg field "$field" --argjson limit "$limit" "$DATASET"
        ;;
    distinct)
        jq -rs "${JQ_COMMON}
            [ .[] | records | select(selected) | by_path(\$field)
              | if type == \"array\" then .[] else . end
              | select(. != null) | tostring ]
            | unique[]" \
            "${jq_args[@]}" --arg field "$field" -r "$DATASET"
        ;;
    window)
        jq -rs "${JQ_COMMON}
            def bucket_value(\$value):
              if \$bucket == \"hour\" then \$value[0:13] + \":00:00Z\"
              else \$value[0:10]
              end;
            [ .[] | records | select(selected) | by_path(\$field)
              | select(type == \"string\" and length >= 10)
              | bucket_value(.) ]
            | group_by(.)
            | map({bucket: .[0], count: length})
            | sort_by(.bucket)[]
            | [ .bucket, (.count | tostring) ] | @tsv" \
            "${jq_args[@]}" --arg field "$field" --arg bucket "$bucket" -r "$DATASET"
        ;;
esac


