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

The three open-source tools benchmarked alongside AccessGraph span a range of
approaches. PMapper (NCC Group) is itself graph-based: it models IAM principals
as a directed graph and performs multi-hop path traversal to find privilege
escalation routes. Prowler has introduced attack path visualization that links
resources, findings, and permissions into a knowledge graph, though its
individual checks have historically evaluated per-policy conditions. Checkov
performs static analysis of infrastructure-as-code templates, evaluating each
policy document independently without cross-principal graph traversal.
None of these tools, however, combine graph-based escalation path discovery
with quantitative blast-radius metrics (reachable resource counts, percentage
of environment reachable, minimum hop depth to admin) or provide a systematic
benchmark comparison with precision, recall, and F1 scores across all tools on
a common dataset. See `docs/benchmark_methodology.md` Section 1.3 for the
tool selection rationale.

AccessGraph contributes a benchmark harness that evaluates detection coverage
across all four tools on the 31 privilege escalation scenarios in the
[IAMVulnerable](https://github.com/BishopFox/iam-vulnerable) dataset (Seth Art,
Bishop Fox, 2021). The benchmark produces per-tool precision, recall, and F1
scores broken down by chain-length class (simple, two-hop, multi-hop), with
Wilson score 95% confidence intervals. AccessGraph also integrates graph
traversal with blast-radius quantification and embedded OPA policy evaluation
in a single offline pipeline. All analysis is offline -- no live AWS API calls
are made during graph construction or traversal.

## Getting Started

### Prerequisites

- Go 1.25 or later ([download](https://go.dev/dl/))
- Python 3.8 or later (for `make reproduce-fixtures` benchmark summary)
- Linux or macOS; any Go-supported platform
- Approximately 80 MB disk space (repository clone)
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

### Exporting IAM from an AWS account

Use `export-iam` to produce the IAM JSON snapshot that `accessgraph ingest`
and `accessgraph analyze` consume. This is the bridge between a live AWS
account and AccessGraph's offline analysis pipeline.

```
./bin/accessgraph export-iam --output iam-export.json
```

Required AWS permissions: the `ReadOnlyAccess` or `SecurityAudit` managed
policy is sufficient (specifically `iam:GetAccountAuthorizationDetails` and
`sts:GetCallerIdentity`).

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | (default chain) | AWS profile name from `~/.aws/config` |
| `--output` | stdout | Output file path |
| `--region` | us-east-1 | AWS region for STS (IAM is global but STS needs a region) |
| `--endpoint-url` | (none) | Custom AWS endpoint URL for LocalStack development |

Examples:

```
# Default credential chain, output to stdout
./bin/accessgraph export-iam > iam-export.json

# Named profile, output to file
./bin/accessgraph export-iam --profile prod --output iam-export.json

# LocalStack development
./bin/accessgraph export-iam --endpoint-url http://localhost:4566 --output iam-export.json
```

The output is a single JSON file in the same format the existing parser
consumes (lowercase top-level keys: `users`, `roles`, `groups`, `policies`,
`account_id`; PascalCase nested fields matching the AWS API). Feed it
directly into the analysis pipeline:

```
./bin/accessgraph export-iam --output iam-export.json
./bin/accessgraph ingest --source iam-export.json --label prod-2026-04
./bin/accessgraph analyze --label prod-2026-04 --from arn:aws:iam::123456789012:user/dev-user
```

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
  --scenarios <path-to-scenario-fixtures-dir> \
  --tools prowler,pmapper,checkov \
  --account-id <aws-account-id> \
  --output json
```

This requires the `integration` build tag and external tools installed on
`$PATH`. See [Benchmark Reproduction](#benchmark-reproduction) for details.

| Flag | Default | Description |
|------|---------|-------------|
| `--scenarios` | required | Directory containing scenario subdirectories, each with a `manifest.json` and IAM export JSON |
| `--tools` | `accessgraph` | Comma-separated list: `accessgraph`, `prowler`, `pmapper`, `checkov` |
| `--output` | `terminal` | Output format: `terminal` or `json` |
| `--account-id` | (empty) | AWS account ID of the test account; used by live-AWS fixture capture |

## Reproducing the benchmark

The benchmark comparison table can be reproduced from a fresh clone with
one command. No AWS credentials, Docker, LocalStack, or external tools
(Prowler, PMapper, Checkov) are required.

**Prerequisites:** Go 1.25+ and Python 3.8+.

```
git clone https://github.com/JamesOlaitan/accessgraph.git
cd accessgraph
make reproduce-fixtures
```

This builds the integration binary, runs the four-tool benchmark against the
committed fixtures in `fixtures/iamvulnerable/`, and prints a per-tool recall
summary. Expected output (as of the most recent benchmark run committed to
this repository):

```
Per-tool recall on vulnerable scenarios (tn-clean excluded):
Tool              TP   FN   Recall
-----------------------------------
accessgraph        9    1      90%
checkov           10    0     100%
pmapper            7    3      70%
prowler           10    0     100%

Full JSON output: build/reproduction-result.json
```

Expected wall-clock time: under one minute on a modern laptop (compilation
dominates; the benchmark itself completes in seconds).

The full structured JSON result (per-scenario labels, confidence intervals,
chain-length class breakdowns) is written to `build/reproduction-result.json`.
See `docs/benchmark_methodology.md` Section 4.5 for interpretation of the
per-tool numbers, including why Prowler and Checkov achieve 100% and why
PMapper's 70% reflects both architectural coverage gaps and a capture-environment
limitation (LocalStack does not support SageMaker).

The fixtures in `fixtures/iamvulnerable/` are committed artifacts captured
against LocalStack. Each scenario directory contains `iam_export.json`
(AccessGraph input), `checkov.json`, `prowler.ocsf.json`, PMapper graph
storage, and `pmapper_findings.json`. The reproduction replays these
fixtures offline without invoking any external tool binary.

### Live AWS reproduction

Full live-AWS reproduction (deploy IAMVulnerable, capture fresh fixtures,
run all tools) is tracked as future work. The live capture workflow requires
Docker and LocalStack (or AWS credentials with deploy permissions for an
actual account); the offline reproduction described above does not. See
`docs/benchmark_methodology.md` Section 7.1 for the planned workflow.

### Capturing benchmark fixtures against LocalStack

For development and integration testing without AWS spend,
`scripts/capture_scenario.sh` deploys a single scenario against LocalStack,
captures all four tool fixtures (AccessGraph IAM export, PMapper graph storage,
Prowler json-ocsf output, Checkov Terraform scan), and tears down the
deployment. The script handles two modes: IAMVulnerable privilege escalation
scenarios (privesc*) and true-negative environments (tn-clean-NNN).

```
./scripts/capture_scenario.sh privesc1-CreateNewPolicyVersion
./scripts/capture_scenario.sh tn-clean-001
make capture-scenario SCENARIO=privesc1-CreateNewPolicyVersion
```

Captured fixtures are written to `fixtures/iamvulnerable/<scenario>/` or
`fixtures/tn-environments/<tn-name>/`. Requires Docker, Terraform, a built
binary (`make build`), and the benchmark Docker image (`make docker-build`).
LocalStack fixtures are suitable for development iteration but are not
canonical; see `docs/benchmark_methodology.md` Section 7.1 for the canonical
live-AWS capture workflow.

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
├── terraform/             Terraform infrastructure (scanner role, 10 TN environments)
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

CI enforces a 55% total coverage gate, set conservatively below the current
~60% to allow ongoing development. The target coverage for the project is
75% total and 80% for core packages (`internal/graph`, `internal/analyzer`),
and the gate is raised as coverage improves. Tests live in `tests/` mirroring
the `internal/` package structure, not alongside source files. Integration
tests require the `integration` build tag.

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
