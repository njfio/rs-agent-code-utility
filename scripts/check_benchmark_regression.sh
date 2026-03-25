#!/usr/bin/env bash
set -euo pipefail

criterion_dir="${1:-target/criterion}"
baseline_name="${2:-base}"
candidate_name="${3:-pr}"
threshold_percent="${4:-10}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to compare Criterion benchmark estimates." >&2
  exit 1
fi

benchmarks=(
  "parse_rust_file"
)

optional_benchmarks=(
  "parse_javascript"
)

printf 'Parser regression threshold: %s%%\n' "$threshold_percent"
printf '%-24s %14s %14s %10s %8s\n' "Benchmark" "Baseline (us)" "Candidate (us)" "Delta" "Status"

status=0

for benchmark in "${benchmarks[@]}"; do
  baseline_file="${criterion_dir}/${benchmark}/${baseline_name}/estimates.json"
  candidate_file="${criterion_dir}/${benchmark}/${candidate_name}/estimates.json"

  if [[ ! -f "$baseline_file" ]]; then
    echo "Missing baseline estimates for ${benchmark}: ${baseline_file}" >&2
    exit 1
  fi

  if [[ ! -f "$candidate_file" ]]; then
    echo "Missing candidate estimates for ${benchmark}: ${candidate_file}" >&2
    exit 1
  fi

  baseline_mean_ns="$(jq -r '.mean.point_estimate' "$baseline_file")"
  candidate_mean_ns="$(jq -r '.mean.point_estimate' "$candidate_file")"

  baseline_mean_us="$(awk -v ns="$baseline_mean_ns" 'BEGIN { printf "%.2f", ns / 1000 }')"
  candidate_mean_us="$(awk -v ns="$candidate_mean_ns" 'BEGIN { printf "%.2f", ns / 1000 }')"
  delta_percent="$(awk -v base="$baseline_mean_ns" -v candidate="$candidate_mean_ns" 'BEGIN { printf "%.2f", ((candidate - base) / base) * 100 }')"

  benchmark_status="PASS"
  if awk -v delta="$delta_percent" -v threshold="$threshold_percent" 'BEGIN { exit !(delta > threshold) }'; then
    benchmark_status="FAIL"
    status=1
  fi

  printf '%-24s %14s %14s %9s%% %8s\n' \
    "$benchmark" \
    "$baseline_mean_us" \
    "$candidate_mean_us" \
    "$delta_percent" \
    "$benchmark_status"
done

for benchmark in "${optional_benchmarks[@]}"; do
  baseline_file="${criterion_dir}/${benchmark}/${baseline_name}/estimates.json"
  candidate_file="${criterion_dir}/${benchmark}/${candidate_name}/estimates.json"

  if [[ ! -f "$baseline_file" && ! -f "$candidate_file" ]]; then
    continue
  fi

  if [[ ! -f "$baseline_file" || ! -f "$candidate_file" ]]; then
    echo "Optional benchmark ${benchmark} is missing from one side of the comparison." >&2
    exit 1
  fi

  baseline_mean_ns="$(jq -r '.mean.point_estimate' "$baseline_file")"
  candidate_mean_ns="$(jq -r '.mean.point_estimate' "$candidate_file")"

  baseline_mean_us="$(awk -v ns="$baseline_mean_ns" 'BEGIN { printf "%.2f", ns / 1000 }')"
  candidate_mean_us="$(awk -v ns="$candidate_mean_ns" 'BEGIN { printf "%.2f", ns / 1000 }')"
  delta_percent="$(awk -v base="$baseline_mean_ns" -v candidate="$candidate_mean_ns" 'BEGIN { printf "%.2f", ((candidate - base) / base) * 100 }')"

  benchmark_status="PASS"
  if awk -v delta="$delta_percent" -v threshold="$threshold_percent" 'BEGIN { exit !(delta > threshold) }'; then
    benchmark_status="FAIL"
    status=1
  fi

  printf '%-24s %14s %14s %9s%% %8s\n' \
    "$benchmark" \
    "$baseline_mean_us" \
    "$candidate_mean_us" \
    "$delta_percent" \
    "$benchmark_status"
done

if [[ "$status" -ne 0 ]]; then
  echo "Parser benchmark regression exceeded ${threshold_percent}%." >&2
  exit 1
fi
