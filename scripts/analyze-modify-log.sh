#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  analyze-modify-log.sh [options] <modify-log-path>

Print summary analytics from --log-file output (NDJSON).

Options:
  --status <status>     Filter by summary.status (ok, failed, strict_failed, all)
  --category <category> Filter by failure_category (strict|parse|compare|write|modify| - for empty|all)
  --last <n>            Analyze only the last N log entries
  --max-failures <n>    Exit with code 1 when filtered failure count exceeds N
  --since <RFC3339>     Include only entries at/after timestamp (e.g. 2026-03-04T10:00:00Z)
  --until <RFC3339>     Include only entries at/before timestamp (e.g. 2026-03-04T11:00:00Z)
  --json                Output machine-readable summary JSON (same as --format json)
  --format <format>     Output format: text|json|csv (default: text)
  --top <n>             Limit top failure reasons to n entries (default: 10)
  --quiet               Print summary only in text/csv output
  --help                Show this message
EOF
}

LOG_PATH=""
STATUS_FILTER=""
STATUS_FILTER_SET=false
CATEGORY_FILTER=""
LAST_LINES=0
MAX_FAILURES=""
SINCE_TS=""
UNTIL_TS=""
SINCE_EPOCH=0
UNTIL_EPOCH=0
CATEGORY_EMPTY_ONLY=false
CATEGORY_FILTER_SET=false
TOP_FAILURE_REASONS=10
QUIET=false
OUTPUT_FORMAT="text"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required (not found in PATH)" >&2
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --status)
      shift
      if [[ $# -eq 0 ]]; then
        echo "error: --status requires argument" >&2
        exit 1
      fi
      STATUS_FILTER="$1"
      if [[ "$STATUS_FILTER" == "all" ]]; then
        STATUS_FILTER=""
        STATUS_FILTER_SET=false
      elif [[ ! "$STATUS_FILTER" =~ ^(ok|failed|strict_failed)$ ]]; then
        echo "error: --status must be one of ok, failed, strict_failed, all" >&2
        exit 1
      else
        STATUS_FILTER_SET=true
      fi
      ;;
    --category)
      shift
      if [[ $# -eq 0 ]]; then
        echo "error: --category requires argument" >&2
        exit 1
      fi
      CATEGORY_FILTER="$1"
      if [[ "$CATEGORY_FILTER" == "all" ]]; then
        CATEGORY_FILTER=""
        CATEGORY_FILTER_SET=false
        CATEGORY_EMPTY_ONLY=false
      elif [[ "$CATEGORY_FILTER" == "-" ]]; then
        CATEGORY_FILTER=""
        CATEGORY_FILTER_SET=true
        CATEGORY_EMPTY_ONLY=true
        ;;
      elif [[ ! "$CATEGORY_FILTER" =~ ^(strict|parse|compare|write|modify)$ ]]; then
        echo "error: --category must be one of strict, parse, compare, write, modify, or - for empty category" >&2
        exit 1
      fi
      if [[ "$CATEGORY_FILTER" != "all" && "$CATEGORY_FILTER" != "-" ]]; then
        CATEGORY_FILTER_SET=true
        CATEGORY_EMPTY_ONLY=false
      fi
      ;;
    --last)
      shift
      if [[ $# -eq 0 ]]; then
        echo "error: --last requires integer argument" >&2
        exit 1
      fi
      LAST_LINES="$1"
      if [[ ! "$LAST_LINES" =~ ^[0-9]+$ ]]; then
        echo "error: --last requires integer" >&2
        exit 1
      fi
      ;;
    --max-failures)
      shift
      if [[ $# -eq 0 ]]; then
        echo "error: --max-failures requires integer argument" >&2
        exit 1
      fi
      MAX_FAILURES="$1"
      if [[ ! "$MAX_FAILURES" =~ ^[0-9]+$ ]]; then
        echo "error: --max-failures requires integer" >&2
        exit 1
      fi
      ;;
    --since)
      shift
      if [[ $# -eq 0 ]]; then
        echo "error: --since requires timestamp argument" >&2
        exit 1
      fi
      SINCE_TS="$1"
      ;;
    --until)
      shift
      if [[ $# -eq 0 ]]; then
        echo "error: --until requires timestamp argument" >&2
        exit 1
      fi
      UNTIL_TS="$1"
      ;;
    --json)
      OUTPUT_FORMAT="json"
      ;;
    --format)
      shift
      if [[ $# -eq 0 ]]; then
        echo "error: --format requires argument" >&2
        exit 1
      fi
      OUTPUT_FORMAT="$1"
      if [[ ! "$OUTPUT_FORMAT" =~ ^(text|json|csv)$ ]]; then
        echo "error: --format must be one of text, json, csv" >&2
        exit 1
      fi
      ;;
    --top)
      shift
      if [[ $# -eq 0 ]]; then
        echo "error: --top requires integer argument" >&2
        exit 1
      fi
      TOP_FAILURE_REASONS="$1"
      if [[ ! "$TOP_FAILURE_REASONS" =~ ^[0-9]+$ ]] || [[ "$TOP_FAILURE_REASONS" -eq 0 ]]; then
        echo "error: --top requires positive integer" >&2
        exit 1
      fi
      ;;
    --quiet)
      QUIET=true
      ;;
    --help)
      usage
      exit 0
      ;;
    --*)
      echo "error: unknown option $1" >&2
      usage
      exit 1
      ;;
    *)
      if [[ -n "$LOG_PATH" ]]; then
        echo "error: unexpected extra argument: $1" >&2
        usage
        exit 1
      fi
      LOG_PATH="$1"
      ;;
  esac
  shift
done

if [[ -z "$LOG_PATH" ]]; then
  usage
  exit 1
fi

if [[ ! -f "$LOG_PATH" ]]; then
  echo "log file not found: $LOG_PATH" >&2
  exit 1
fi

if [[ -n "$SINCE_TS" ]]; then
  if ! SINCE_EPOCH=$(date -u -d "$SINCE_TS" +%s 2>/dev/null); then
    echo "error: invalid --since timestamp: $SINCE_TS" >&2
    exit 1
  fi
fi

if [[ -n "$UNTIL_TS" ]]; then
  if ! UNTIL_EPOCH=$(date -u -d "$UNTIL_TS" +%s 2>/dev/null); then
    echo "error: invalid --until timestamp: $UNTIL_TS" >&2
    exit 1
  fi
fi

if (( SINCE_EPOCH > 0 )) && (( UNTIL_EPOCH > 0 )) && (( SINCE_EPOCH > UNTIL_EPOCH )); then
  echo "error: --since cannot be later than --until" >&2
  exit 1
fi

buildFilter() {
  local filter='try fromjson catch empty'
  if [[ "$STATUS_FILTER_SET" == "true" ]]; then
    filter="$filter | select(.summary.status == \"$STATUS_FILTER\")"
  fi
  if [[ "$CATEGORY_FILTER_SET" == "true" ]]; then
    if [[ "$CATEGORY_EMPTY_ONLY" == "true" ]]; then
      filter="$filter | select((.failure_category // \"\") == \"\")"
    else
      filter="$filter | select(.failure_category == \"$CATEGORY_FILTER\")"
    fi
  fi
  if (( SINCE_EPOCH > 0 )); then
    filter="$filter | select((.timestamp | try fromdateiso8601 catch -1) >= $SINCE_EPOCH)"
  fi
  if (( UNTIL_EPOCH > 0 )); then
    filter="$filter | select((.timestamp | try fromdateiso8601 catch -1) <= $UNTIL_EPOCH)"
  fi
  echo "$filter"
}

readjson() {
  local filter
  filter="$(buildFilter)"
  if (( LAST_LINES > 0 )); then
    tail -n "$LAST_LINES" "$LOG_PATH" | jq -R "$filter"
  else
    jq -R "$filter" "$LOG_PATH"
  fi
}

REPORT_JSON="$(readjson | jq -s --argjson topReasons "$TOP_FAILURE_REASONS" '
  {
    total_lines: length,
    status: ((sort_by(.summary.status) | group_by(.summary.status))
      | map({status: .[0].summary.status, count: length})
      | sort_by(-.count)),
    failure_category: ((sort_by((.failure_category // "-")) | group_by((.failure_category // "-")))
      | map({category: (.[0].failure_category // "-"), count: length})
      | sort_by(-.count)),
    by_input: ((sort_by(.summary.input_file) | group_by(.summary.input_file))
      | map({input_file: .[0].summary.input_file, count: length})
      | sort_by(-.count)),
    failed_entries: [
      .[] | select(.summary.status != "ok")
      | {
          timestamp: .timestamp,
          input_file: .summary.input_file,
          output_file: .summary.output_file,
          failure_category: (.failure_category // "-"),
          failure_reason: .failure_reason
        }
    ],
    top_failure_reasons: ([
      .[] | select(.summary.status != "ok") | .failure_reason
    ] | sort | group_by(.) | map({reason: .[0], count: length}) | sort_by([-.count, .reason]) | .[0:$topReasons]),
    failure_count: ([.[] | select(.summary.status != "ok")] | length)
  }
')"

failure_count=$(jq -r '.failure_count' <<< "$REPORT_JSON")
THRESHOLD_EXCEEDED=false
if [[ -n "$MAX_FAILURES" ]] && (( failure_count > MAX_FAILURES )); then
  THRESHOLD_EXCEEDED=true
fi

if [[ "$OUTPUT_FORMAT" == "json" ]]; then
  if [[ -n "$MAX_FAILURES" ]]; then
    REPORT_JSON="$(jq -n --argjson report "$REPORT_JSON" --argjson max "$MAX_FAILURES" --argjson exceeded "$THRESHOLD_EXCEEDED" '
      $report + {threshold_exceeded: $exceeded, threshold: $max}
    ')"
  fi
  echo "$REPORT_JSON"
  if [[ "$THRESHOLD_EXCEEDED" == "true" ]]; then
    exit 1
  fi
  exit 0
fi

if [[ "$OUTPUT_FORMAT" == "csv" ]]; then
  echo "kind,name,value,count,extra1,extra2"
  if [[ "$QUIET" == "true" ]]; then
    QUIET_CSV=true
  else
    QUIET_CSV=false
  fi
  jq -r --argjson quiet "$QUIET_CSV" '
    (
      [["summary", "total_lines", "", (.total_lines|tostring), "", ""]] +
      (.status | map(["status", .status, "", (.count|tostring), "", ""])) +
      (.failure_category | map(["failure_category", .category, "", (.count|tostring), "", ""])) +
      (.by_input | map(["input_file", .input_file, "", (.count|tostring), "", ""])) +
      (if $quiet == false then
         (if (.failed_entries | length) == 0
          then [["failed_entry", "none", "", "", "", ""]]
          else (.failed_entries | map(["failed_entry", .timestamp, .failure_category, .failure_reason, .input_file, .output_file]))
          end)
       else [] end) +
      (if $quiet == false then
         (if (.top_failure_reasons | length) == 0
          then [["top_failure_reason", "none", "", "", "", ""]]
          else (.top_failure_reasons | map(["top_failure_reason", .reason, "", (.count|tostring), "", ""]))
          end)
       else [] end)
    )[] | @csv
  ' <<< "$REPORT_JSON"
  if [[ -n "$MAX_FAILURES" ]]; then
    jq -rn --arg threshold "$MAX_FAILURES" --argjson failure_count "$failure_count" --argjson exceeded "$THRESHOLD_EXCEEDED" '
      @csv ["threshold", "max", "", $threshold, $failure_count|tostring, $exceeded]
    '
  fi
  if [[ "$THRESHOLD_EXCEEDED" == "true" ]]; then
    exit 1
  fi
  exit 0
fi

echo "== vdexcli modify log summary =="
jq -r '
  {
    total_lines: .total_lines,
    status: .status,
    failure_category: .failure_category,
    by_input: .by_input
  } | to_entries[] | "\(.key)=\(.value|tojson)"
' <<< "$REPORT_JSON"

if [[ "${QUIET}" == "true" ]]; then
  if [[ "$THRESHOLD_EXCEEDED" == "true" ]]; then
    echo
    echo "== failure threshold check =="
    echo "failures: ${failure_count} (exceeds threshold ${MAX_FAILURES})"
    exit 1
  fi
  exit 0
fi

echo
echo "== failed entries (reason) =="
if [[ "$failure_count" -eq 0 ]]; then
  echo "none"
else
  jq -r '.failed_entries[] | "\(.timestamp)\t\(.input_file)\t\(.output_file)\t\(.failure_category)\t\(.failure_reason)"' <<< "$REPORT_JSON"
fi

echo
echo "== top failure reasons =="
top_len="$(jq -r '.top_failure_reasons | length' <<< "$REPORT_JSON")"
if [[ "$top_len" -eq 0 ]]; then
  echo "none"
else
  jq -r '.top_failure_reasons[] | "\(.count)\t\(.reason)"' <<< "$REPORT_JSON"
fi

if [[ "$THRESHOLD_EXCEEDED" == "true" ]]; then
  echo
  echo "== failure threshold check =="
  echo "failures: ${failure_count} (exceeds threshold ${MAX_FAILURES})"
  exit 1
fi
