#!/usr/bin/env bash
# run_iamvulnerable.sh — Ingest all IAMVulnerable scenario exports into AccessGraph.
#
# Usage:
#   ./scripts/run_iamvulnerable.sh <scenarios-root-dir>
#
# Each subdirectory of <scenarios-root-dir> that contains a manifest.json and at
# least one *.json policy file is treated as one IAMVulnerable scenario.
#
# Prerequisites:
#   - accessgraph binary must be built: make build
#   - Scenario JSON exports must exist (run IAMVulnerable's own export scripts first)
#
# Output:
#   - Each scenario is ingested into the default SQLite database (accessgraph.db)
#   - A summary table of ingested scenarios is printed at the end

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BINARY="${REPO_ROOT}/bin/accessgraph"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <scenarios-root-dir>" >&2
    exit 1
fi

SCENARIOS_DIR="$1"

if [[ ! -d "${SCENARIOS_DIR}" ]]; then
    echo "Error: scenarios directory '${SCENARIOS_DIR}' does not exist." >&2
    exit 1
fi

if [[ ! -x "${BINARY}" ]]; then
    echo "Error: binary not found at '${BINARY}'. Run 'make build' first." >&2
    exit 1
fi

echo "Ingesting IAMVulnerable scenarios from: ${SCENARIOS_DIR}"
echo "---"

count=0
failed=0

for scenario_dir in "${SCENARIOS_DIR}"/*/; do
    [[ -d "${scenario_dir}" ]] || continue

    scenario_name="$(basename "${scenario_dir}")"
    policy_file="${scenario_dir}/iam_export.json"

    # Fall back to any .json file that is not the manifest.
    if [[ ! -f "${policy_file}" ]]; then
        policy_file="$(find "${scenario_dir}" -maxdepth 1 -name "*.json" ! -name "manifest.json" | head -1)"
    fi

    if [[ -z "${policy_file}" || ! -f "${policy_file}" ]]; then
        echo "  SKIP ${scenario_name}: no IAM export JSON found"
        continue
    fi

    if "${BINARY}" ingest \
        --source "${policy_file}" \
        --label "iamvulnerable-${scenario_name}" \
        2>&1; then
        count=$((count + 1))
    else
        echo "  FAIL ${scenario_name}"
        failed=$((failed + 1))
    fi
done

echo "---"
echo "Ingested: ${count}  Failed: ${failed}"

if [[ ${failed} -gt 0 ]]; then
    exit 1
fi
