# AccessGraph

Graph-based AWS IAM privilege escalation path detection and blast-radius quantification.

## Overview

AccessGraph models an AWS IAM environment as a directed graph and uses
breadth-first search to enumerate privilege escalation paths from any
compromised principal. For each starting identity, it computes blast-radius
metrics: how many sensitive resources are reachable, by what paths, and at
what depth. Policy violations are evaluated using embedded OPA rules against
four Rego rulesets covering wildcard actions, cross-account trust, escalation
primitives, and sensitivity classification.

The five open-source tools benchmarked alongside AccessGraph span a range of
approaches. PMapper (NCC Group) is itself graph-based: it models IAM principals
as a directed graph and performs multi-hop path traversal to find privilege
escalation routes. Prowler has introduced attack path visualization that links
resources, findings, and permissions into a knowledge graph, though its
individual checks have historically evaluated per-policy conditions. Checkov
performs static analysis of infrastructure-as-code templates, evaluating each
policy document independently without cross-principal graph traversal.
Steampipe executes SQL-based queries against cloud APIs with per-check
benchmarks. CloudSploit evaluates individual resource configurations against
fixed rule patterns. None of these tools, however, combine graph-based
escalation path discovery with quantitative blast-radius metrics (reachable
resource counts, percentage of environment reachable, minimum hop depth to
admin) or provide a systematic benchmark comparison with precision, recall, and
F1 scores across all tools on a common dataset.

AccessGraph contributes a benchmark harness that evaluates detection coverage
across all six tools on the 31 privilege escalation scenarios in the
[IAMVulnerable](https://github.com/BishopFox/iam-vulnerable) dataset (Seth Art,
Bishop Fox, 2021). The benchmark produces per-tool precision, recall, and F1
scores broken down by chain-length class (simple, two-hop, multi-hop), with
Wilson score 95% confidence intervals. AccessGraph also integrates graph
traversal with blast-radius quantification and embedded OPA policy evaluation
in a single offline pipeline. All analysis is offline -- no live AWS API calls
are made during graph construction or traversal.

## Getting Started

### Prerequisites

- Go 1.26.1 or later ([download](https://go.dev/dl/))
- Linux or macOS; any Go-supported platform
- No Docker, no AWS account, no external services required for basic usage
- golangci-lint v2.11+ (for `make lint` only; not required to build or test)

OPA is embedded via the Go library; no separate OPA installation is needed.

### Clone, build, verify

```
git clone https://github.com/JamesOlaitan/accessgraph.git
cd accessgraph
make build
make test
```

`make build` compiles the binary to `bin/accessgraph`. `make test` runs the
unit test suite with race detection enabled. Both commands require only Go.

### Run the demo

```
make demo
```

This runs a self-contained end-to-end demonstration against bundled sample
data (`sample/aws/demo_policy.json`). It performs three steps:

1. Ingests the sample IAM snapshot and persists it to a local SQLite database.
2. Runs blast-radius analysis from a sample compromised principal
   (`arn:aws:iam::123456789012:user/dev-user`) with terminal output.
3. Re-runs the same analysis with `--output json` to show the structured
   JSON report format.

No environment variables or external data are required. The demo works from a
clean clone immediately after `make build`.

**Success indicators.** Step 1 prints a one-line summary to stdout:
`Snapshot ingested: id=<uuid> label=demo principals=N policies=N resources=N edges=N`.
Step 2 prints an "AccessGraph Analysis Report" header followed by a
blast-radius table, discovered attack paths, and any OPA findings. Step 3
prints a JSON object to stdout. All three steps exit with code 0.

## Usage

### Ingest an IAM snapshot

```
./bin/accessgraph ingest --source <path-to-iam-export.json> --label <name>
```

Parses an AWS IAM environment export, classifies sensitive resources, and
persists the snapshot to a local SQLite database (`accessgraph.db` by default).

```
./bin/accessgraph ingest --source sample/aws/demo_policy.json --label demo
```

### Analyze blast radius

```
./bin/accessgraph analyze --label <name> --from <principal-arn> [--output terminal|json|dot]
```

Builds the permission graph, synthesizes escalation edges, runs BFS from the
specified principal, computes blast-radius metrics, evaluates OPA policy rules,
and renders the report.

| Flag | Default | Description |
|------|---------|-------------|
| `--label` | required | Snapshot label to analyze |
| `--from` | required | ARN of the compromised starting principal |
| `--max-hops` | 8 | Maximum BFS traversal depth |
| `--output` | terminal | Output format: `terminal`, `json`, or `dot` |
| `--db` | accessgraph.db | SQLite database path |
| `--policy-dir` | policy | Directory containing OPA Rego rules |

Example with JSON output:

```
./bin/accessgraph analyze \
  --label demo \
  --from arn:aws:iam::123456789012:user/dev-user \
  --output json
```

**Output formats:**

| Format | Flag | Description |
|--------|------|-------------|
| Terminal | `--output terminal` (default) | Colored report: blast-radius table, attack paths, severity-tagged OPA findings |
| JSON | `--output json` | Structured JSON object conforming to `docs/findings_schema.md` |
| Graphviz DOT | `--output dot` | DOT graph of the reachable subgraph for use with `dot -Tsvg` |

> **Security note.** The SQLite database (`accessgraph.db` by default) contains
> IAM principal, policy, and resource data. Do not point `--db` at a shared or
> world-readable path.

### Render a stored report

```
./bin/accessgraph report --snapshot <snapshot-id> [--output terminal|json|dot]
```

Loads a previously computed snapshot, its attack paths, and its findings from
the store, and renders the report in the requested format. No re-analysis is
performed; this command renders only data stored by a prior `analyze` run.

| Flag | Default | Description |
|------|---------|-------------|
| `--snapshot` | required | Snapshot ID to load and render |
| `--output` | terminal | Output format: `terminal`, `json`, or `dot` |

### Run benchmark comparison

```
./bin/accessgraph benchmark \
  --scenarios <path-to-iamvulnerable-dir> \
  --tools prowler,pmapper,checkov,steampipe,cloudsploit \
  --output json
```

This requires the `integration` build tag and external tools installed on
`$PATH`. See [Benchmark Reproduction](#benchmark-reproduction) for details.

## Benchmark Reproduction

The primary quantitative claim is a precision/recall comparison of AccessGraph
against five open-source tools on all 31 IAMVulnerable scenarios. Two
reproduction paths are planned:

### Offline reproduction (no AWS account required)

**Status: deferred -- not yet implemented.**

`make reproduce-fixtures` will validate the analysis pipeline against golden
fixture files derived from IAMVulnerable scenario exports. This path allows
reviewers to verify the detection logic and metric computation without
deploying infrastructure. Fixture generation and checksums are pending.

### Live AWS reproduction

**Status: deferred -- not yet implemented.**

`make reproduce` will automate the full benchmark: deploy IAMVulnerable to an
AWS account, export IAM state, run all six tools, and produce the comparison
report. This requires an AWS account and the external tools listed in
[Prerequisites](#prerequisites). Estimated cost per run is under $5 USD.

See `docs/benchmark_methodology.md` for the full methodology specification,
including detection matching rules, confidence interval computation, timeout
handling, and tool version pinning.

## Project Structure

```
accessgraph/
├── cmd/accessgraph/       CLI entry point and Cobra commands (ingest, analyze, report, benchmark)
├── internal/              Domain logic organized by responsibility
│   ├── model/             Domain types: Snapshot, Principal, Edge, Finding, AttackPath
│   ├── graph/             Graph construction, BFS traversal, escalation edge synthesis
│   ├── analyzer/          Blast-radius metric computation
│   ├── parser/            AWS IAM JSON ingestion
│   ├── store/             DataStore interface (SQLite and in-memory implementations)
│   ├── policy/            Embedded OPA evaluator with graceful degradation
│   ├── benchmark/         Tool adapter harness and IAMVulnerable scenario loader
│   ├── report/            Output renderers: terminal, JSON, Graphviz DOT
│   ├── service/           Facade orchestration (AnalysisFacade, BenchmarkFacade)
│   ├── config/            Environment-variable-based configuration
│   └── transport/         Offline HTTP enforcement
├── tests/                 Unit and integration tests (mirrors internal/ structure)
├── policy/                OPA Rego rules (4 files)
├── sample/                Sample IAM data for demo and tests
├── docs/                  Specification documents
└── scripts/               Automation and audit scripts
```

The codebase follows a three-layer architecture with strictly unidirectional
dependencies. Layer 1 (model, store, config, transport) has no upward imports.
Layer 2a (graph, analyzer, parser, policy, benchmark, report) may import
Layer 1 and other Layer 2a packages; it must not import Layer 3. Layer 2b
(service) orchestrates Layer 2a via facades. Layer 3 (cmd) wires dependencies
and handles I/O. See `docs/ARCHITECTURE.md` for the full specification.

## Testing

```
make test                  # Unit tests (-race, no external dependencies)
make test-integration      # Full benchmark suite (requires external tools on PATH)
make lint                  # golangci-lint v2
make audit                 # Architectural fitness checks (layer deps, interfaces, JSON tags)
```

Run a single test:

```
go test -race -run TestName ./tests/graph/...
```

Run tests with coverage (mirrors CI):

```
go test -race -count=1 -timeout 120s -coverprofile=coverage.txt \
  -coverpkg=./internal/... ./tests/...
```

CI requires 75% total coverage. `internal/graph` and `internal/analyzer` must
individually exceed 80%. Tests live in `tests/` mirroring the `internal/`
package structure, not alongside source files. Integration tests require the
`integration` build tag.

## Documentation

| Document | Description |
|----------|-------------|
| `docs/ARCHITECTURE.md` | System architecture, layer contracts, interface specifications, and data flow |
| `docs/benchmark_methodology.md` | Benchmark design, detection matching rules, statistical methodology, and reproduction procedures |
| `docs/findings_schema.md` | JSON output schema, field types, invariants, and float serialization contract |

## Limitations

The following limitations apply to the benchmark evaluation. See
`docs/benchmark_methodology.md` Section 8 for full discussion.

- **Sample size.** The benchmark covers n=31 privilege escalation scenarios.
  Differences in recall below 0.2 within a single chain-length class should
  not be interpreted as meaningful without additional data.
- **Tool version sensitivity.** External tool output formats and detection
  logic change across versions. The benchmark results are valid only for the
  pinned versions specified in the methodology document.
- **Checkov methodological asymmetry.** Checkov is evaluated against Terraform
  source; all other tools are evaluated against the live deployed environment.
  Results are comparable on the "same scenario" axis, not the "same input"
  axis.
- **IAMVulnerable coverage.** The 31 scenarios are a curated subset of known
  escalation paths. AccessGraph's detection capability on paths not present in
  IAMVulnerable is not measured.
- **External tool FPR not measured.** Only AccessGraph's FPR is measured
  against true negative environments. External tools' dispatch paths return
  `LabelFN` on TN scenarios unconditionally, so no FPR entry is emitted for
  them in benchmark output. Consumers can check the `fpr_measured` field on
  each `false_positive_rate` entry: `fpr_measured: false` means the value was
  not measured; `fpr_measured: true` means it was computed from actual TN
  evaluations.
- **Static analysis only.** IAM condition keys are parsed but not evaluated
  during traversal. Permission boundaries are detected as findings but do not
  constrain BFS. Service control policies (SCPs) are not modeled.

## Citation

Paper forthcoming. This section will be updated with citation details upon publication.

## License

Apache License 2.0. See [LICENSE](LICENSE).
