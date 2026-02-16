#!/usr/bin/env bash
# Run all Bulwark criterion benchmarks and summarize results.
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORKSPACE_ROOT"

echo "=== Bulwark Benchmark Suite ==="
echo ""

# Optionally filter by benchmark name.
FILTER="${1:-}"

run_bench() {
    local crate="$1"
    local bench="$2"
    echo "--- Running: $crate / $bench ---"
    if [ -n "$FILTER" ]; then
        cargo bench --package "$crate" --bench "$bench" -- "$FILTER"
    else
        cargo bench --package "$crate" --bench "$bench"
    fi
    echo ""
}

run_bench bulwark-policy policy_evaluation
run_bench bulwark-inspect content_inspection
run_bench bulwark-audit audit_write

echo "=== All benchmarks complete ==="
echo "HTML reports available in: target/criterion/"
