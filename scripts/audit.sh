#!/bin/bash
# scripts/audit.sh — Architectural fitness checks for AccessGraph.
# Catches violations that golangci-lint does not: layer dependency direction,
# compile-time interface checks, comment style, MetricFloat usage, and
# sensitive data patterns.
#
# Usage: make audit   (or: bash scripts/audit.sh)
# Exit 0 = all checks pass. Exit 1 = at least one violation.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

FAIL=0
MODULE="github.com/JamesOlaitan/accessgraph"

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
header(){ printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }

fail_check() {
  red "  FAIL: $1"
  FAIL=1
}

pass_check() {
  green "  PASS: $1"
}

# 1. Layer dependency enforcement
#    model/ must not import any internal/ package.
#    store/ may import model/ only.
#    Layer 2a packages must not import service/ or cmd/.
#    No internal/ package may import cmd/.
#    cmd/ must not import Layer 2a packages directly (only service/).

header "Layer dependency enforcement"

# Helper: get internal imports for a package (excludes stdlib and external)
internal_imports() {
  go list -f '{{join .Imports "\n"}}' "$1" 2>/dev/null | grep "^${MODULE}/internal/" || true
}

# 1a. model/ must have zero internal imports
MODEL_IMPORTS=$(internal_imports "${MODULE}/internal/model")
if [[ -n "$MODEL_IMPORTS" ]]; then
  fail_check "internal/model imports internal packages (must have none):"
  echo "$MODEL_IMPORTS" | sed 's/^/    /'
else
  pass_check "internal/model has no internal imports"
fi

# 1b. store/ may only import model/ and config/
STORE_PKGS=$(go list "${MODULE}/internal/store/..." 2>/dev/null)
for pkg in $STORE_PKGS; do
  BAD_STORE=$(internal_imports "$pkg" | grep -v -E "internal/(model|config)$" || true)
  if [[ -n "$BAD_STORE" ]]; then
    fail_check "$(echo "$pkg" | sed "s|${MODULE}/||") imports forbidden packages:"
    echo "$BAD_STORE" | sed 's/^/    /'
  fi
done
if [[ $FAIL -eq 0 ]]; then
  pass_check "internal/store imports only model/ and config/"
fi

# 1c. Layer 2a packages must not import service/ or cmd/
LAYER2A="parser graph analyzer policy benchmark report"
for pkg_name in $LAYER2A; do
  SUBPKGS=$(go list "${MODULE}/internal/${pkg_name}/..." 2>/dev/null || true)
  for pkg in $SUBPKGS; do
    BAD_UP=$(internal_imports "$pkg" | grep -E "internal/service" || true)
    if [[ -n "$BAD_UP" ]]; then
      fail_check "$(echo "$pkg" | sed "s|${MODULE}/||") imports service/ (upward dependency):"
      echo "$BAD_UP" | sed 's/^/    /'
    fi
  done
done
# Separate check: no internal/ package imports cmd/
ALL_INTERNAL=$(go list "${MODULE}/internal/..." 2>/dev/null)
for pkg in $ALL_INTERNAL; do
  CMD_IMPORT=$(go list -f '{{join .Imports "\n"}}' "$pkg" 2>/dev/null | grep "^${MODULE}/cmd" || true)
  if [[ -n "$CMD_IMPORT" ]]; then
    fail_check "$(echo "$pkg" | sed "s|${MODULE}/||") imports cmd/ (forbidden):"
    echo "$CMD_IMPORT" | sed 's/^/    /'
  fi
done

# 1d. cmd/ must not import Layer 2a packages directly
CMD_PKGS=$(go list "${MODULE}/cmd/..." 2>/dev/null)
for pkg in $CMD_PKGS; do
  DIRECT_2A=$(internal_imports "$pkg" | grep -v -E "internal/(service|model|config)$" || true)
  if [[ -n "$DIRECT_2A" ]]; then
    fail_check "$(echo "$pkg" | sed "s|${MODULE}/||") imports Layer 2a directly (must go through service/):"
    echo "$DIRECT_2A" | sed 's/^/    /'
  fi
done

# 2. Compile-time interface checks
#    Every key interface should have a var _ Interface = (*Concrete)(nil)
header "Compile-time interface checks"

check_interface_assertion() {
  local iface="$1"
  local dir="$2"
  if grep -rq "var _ ${iface}" "$dir" 2>/dev/null; then
    pass_check "var _ ${iface} found in ${dir}"
  else
    fail_check "missing compile-time check: var _ ${iface} in ${dir}"
  fi
}

check_interface_assertion "Traverser" "internal/graph/"
check_interface_assertion "Renderer" "internal/report/"
check_interface_assertion "DataStore" "internal/store/"
check_interface_assertion "Aggregator" "internal/benchmark/"
check_interface_assertion "Runner" "internal/benchmark/"
check_interface_assertion "Parser" "internal/parser/"
check_interface_assertion "BlastRadiusAnalyzer" "internal/analyzer/"


# 3. MetricFloat enforcement
#    Float fields in benchmark/analysis model structs should use MetricFloat,
#    not raw float64. Check model/benchmark.go and model/attack_path.go.
header "MetricFloat enforcement"

# Look for raw float64 fields in model structs that should use MetricFloat.
# Exclude the MetricFloat type definition itself.
RAW_FLOATS=$(grep -n 'float64' internal/model/benchmark.go internal/model/attack_path.go 2>/dev/null \
  | grep -v 'MetricFloat' \
  | grep -v 'type.*float64' \
  | grep -v 'float64(m)' \
  | grep -v '//' \
  || true)
if [[ -n "$RAW_FLOATS" ]]; then
  fail_check "Raw float64 fields found in model structs (should use MetricFloat):"
  echo "$RAW_FLOATS" | sed 's/^/    /'
else
  pass_check "All metric float fields use MetricFloat"
fi

# 4. Sensitive data patterns
#    No hardcoded AWS account IDs (12-digit numbers) outside fixtures/ and
#    docs/. No ARN patterns in log/print statements in internal/.
header "Sensitive data patterns"

# 4a. Hardcoded 12-digit account IDs (excluding test fixtures, docs, samples)
ACCT_IDS=$(grep -rn '\b[0-9]\{12\}\b' --include='*.go' internal/ cmd/ 2>/dev/null \
  | grep -v '_test\.go' \
  | grep -v '123456789012' \
  | grep -v 'timeout\|latency\|timestamp\|nano\|milli\|1000000\|Sprintf' \
  || true)
if [[ -n "$ACCT_IDS" ]]; then
  fail_check "Possible hardcoded AWS account IDs in source (review manually):"
  echo "$ACCT_IDS" | head -10 | sed 's/^/    /'
else
  pass_check "No hardcoded account IDs in source"
fi

# 4b. ARN patterns in fmt.Print/log statements inside internal/
ARN_LOGS=$(grep -rn 'fmt\.Print\|log\.\(Info\|Debug\|Warn\|Error\)' --include='*.go' internal/ 2>/dev/null \
  | grep -i 'arn:' \
  || true)
if [[ -n "$ARN_LOGS" ]]; then
  fail_check "ARN patterns in log/print statements inside internal/:"
  echo "$ARN_LOGS" | sed 's/^/    /'
else
  pass_check "No ARN patterns in internal/ log statements"
fi

# 5. JSON tag completeness
#    Every exported field in model/ structs should have a json tag.
#    This is a heuristic check — it looks for exported fields without json:.
header "JSON tag completeness in model/"

# Find exported struct fields (capital letter after whitespace) without json tag
MISSING_TAGS=$(grep -n '^\s\+[A-Z][a-zA-Z]*\s\+' internal/model/*.go 2>/dev/null \
  | grep -v 'json:' \
  | grep -v '//' \
  | grep -v '^\s*//' \
  | grep -v 'func\|type\|interface\|const\|var\|import\|package\|return' \
  | grep -v '=' \
  || true)
if [[ -n "$MISSING_TAGS" ]]; then
  fail_check "Exported fields in model/ missing json tags (review manually):"
  echo "$MISSING_TAGS" | head -10 | sed 's/^/    /'
else
  pass_check "All exported model fields have json tags"
fi

# Summary
echo ""
if [[ $FAIL -eq 0 ]]; then
  green "All audit checks passed."
  exit 0
else
  red "One or more audit checks failed. Fix violations before committing."
  exit 1
fi