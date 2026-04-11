# Changelog

All notable changes to AccessGraph are documented in this file.
The format is based on Keep a Changelog
(https://keepachangelog.com/en/1.1.0/), and this project adheres
to Semantic Versioning (https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `scripts/capture_scenario.sh`: single-scenario capture orchestration for
  the IAMVulnerable benchmark. Clones the IAMVulnerable repository at the
  pinned commit, copies a single scenario's `.tf` file plus `sre.tf` (always
  included per `docs/benchmark_methodology.md` §2.3) and `variables.tf` to a
  temporary working directory, overrides the AWS provider with LocalStack
  endpoints, runs `terraform apply`, captures four per-tool fixtures
  (AccessGraph IAM export, PMapper graph storage, Prowler json-ocsf output,
  Checkov Terraform scan), writes them to
  `fixtures/iamvulnerable/<scenario>/`, then runs `terraform destroy` and
  removes the LocalStack container. A second mode handles true-negative
  environments (`tn-clean-NNN`) from `terraform/tn-environments/`, writing
  fixtures to `fixtures/iamvulnerable/<tn-name>/`. Invoked by
  `make capture-scenario SCENARIO=<name>`. Real AWS capture and
  multi-scenario orchestration are tracked as future work in
  `docs/benchmark_methodology.md` §7.1.
- New `accessgraph export-iam` subcommand that exports an AWS account's
  IAM configuration as JSON using the AWS SDK's
  GetAccountAuthorizationDetails API. The command paginates across all
  result pages and emits the boto3-compatible JSON format that
  AccessGraph's existing parser consumes. Supports `--profile` for AWS
  credential selection, `--endpoint-url` for LocalStack development,
  `--region` for STS (IAM is global but STS requires a region), and
  `--output` for writing to a file instead of stdout. Unit-tested with
  a mocked IAM client; a smoke test against LocalStack is available
  through `scripts/smoke_export_iam.sh` and `make smoke-export-iam`.
  This command is used by the benchmark's reproduction workflow
  described in `docs/benchmark_methodology.md` to produce AccessGraph
  fixtures from deployed IAMVulnerable scenarios, and is also suitable
  for production users running AccessGraph against their own AWS
  accounts.
- `github.com/aws/aws-sdk-go-v2` dependency (root package, config,
  service/iam, service/sts) for live AWS IAM API access.
- `terraform/tn-environments/`: 10 true-negative environment modules
  (`tn-clean-001` through `tn-clean-010`) per
  `docs/benchmark_methodology.md §5.1`. Each module deploys least-privilege
  IAM users (read-only managed policies only) and one lambda-trust IAM role
  with no dangerous permissions. Modules vary in user count (3-5), specific
  managed policies attached, side resources (Lambda functions, S3 buckets),
  and lambda role trust conditions. All 10 modules have unique
  (user_count, side_resource, trust_type) combinations: 3 modules with 3
  users (001, 007, 010), 4 with 4 users (002, 004, 008, 009), 3 with 5
  users (003, 005, 006). The variation exists to provide independent
  observations for Wilson score CI computation, not as casual diversity --
  identical modules would be pseudoreplication and would invalidate the CI
  assumption of independent Bernoulli trials. No escalation-taxonomy action
  from IAMVulnerable is present in any module (verified by grep at commit
  time). Each module has its own `.terraform.lock.hcl` with cross-platform
  hashes.
- `terraform/scanner-role/` module: Terraform infrastructure for the
  `AccessGraphBenchmarkScanner` IAM role per
  `docs/benchmark_methodology.md §2.2`. Attaches AWS managed policies
  `ReadOnlyAccess` and `SecurityAudit`. Trust policy is parameterized via
  `trust_principal_arn` variable (default: deploying principal via
  `aws_caller_identity`). `max_session_duration` is set to 28800 seconds
  (8 hours) to accommodate the 4-6 hour wall-clock benchmark runs documented
  in `docs/benchmark_methodology.md §7.1` with a 2-hour buffer.
- `terraform/scanner-role/.terraform.lock.hcl`: dependency lock file with
  cross-platform hashes (linux_amd64, darwin_arm64, darwin_amd64) for
  reproducible provider installation across reviewer environments.
- `terraform/README.md`: top-level orientation for the Terraform
  infrastructure directory.
- `fpr_measured` boolean field on `FalsePositiveRate` in benchmark
  output. Distinguishes measured FPR (currently only AccessGraph)
  from unmeasured FPR on external tools whose output adapters do
  not process true-negative environments. Consumers of benchmark
  JSON should check this field before interpreting FPR values; an
  `fpr_measured: false` row with `fpr: 0` means "not measured,"
  not "confirmed zero."
- `Dockerfile`: single benchmark image co-installing Go, two isolated
  Python 3.11 virtual environments (`/opt/venv-prowler` for
  Prowler + PMapper, `/opt/venv-checkov` for Checkov), the AccessGraph
  binary built from source, and IAMVulnerable cloned at the pinned
  commit `0f298666f9b7cfa01488b86912afdb211773188a`. Built from
  `golang:1.26-bookworm@sha256:4f4ab2c90005e7e63cb631f0b4427f05422f241622ee3ec4727cc5febbf83e34`
  with a pinned digest. Entrypoint sets the four `ACCESSGRAPH_*`
  environment variables. The image is fully self-contained:
  `docker run accessgraph-benchmark` produces the canonical benchmark
  execution environment with no additional setup required. Includes a
  one-line mechanical patch to PMapper 1.1.5's
  `principalmapper/util/case_insensitive_dict.py` to fix a Python 3.10+
  incompatibility (the `collections.Mapping` alias was removed in
  Python 3.10 and PMapper has not shipped a fix); the patch rewrites
  the broken import to use `collections.abc` and is verified at build
  time by re-importing the affected module. See
  `docs/benchmark_methodology.md §3.1` for the methodology-level
  documentation.
- `requirements-prowler.txt`: pinned Python dependencies for the
  Prowler venv (`prowler==5.20.0`, `principalmapper==1.1.5`).
- `requirements-checkov.txt`: pinned Python dependencies for the
  Checkov venv (`checkov==3.2.509`).
- `docker-compose.yml`: local development convenience wrapper for the
  benchmark image. Per `docs/ARCHITECTURE.md`, this file is NOT the
  canonical benchmark execution environment.
- `.dockerignore`: build context exclusions to keep image builds
  reproducible and avoid copying local state, secrets, fixtures, or
  terraform state into the image.
- Makefile targets: `docker-build`, `docker-up`, `docker-down`.

### Changed
- `internal/service/benchmark.go` `benchmarkFacade.Run` updated to include
  the AccessGraph self-evaluation step specified in
  `docs/ARCHITECTURE.md` §12 step 5c. Previously the facade iterated
  external-tool runners and stopped; the call graph in the architecture
  document has the facade also invoking `RunAccessGraphOnScenario` for
  each scenario after the external-tool loop. The function existed in
  `internal/benchmark/pipeline.go` and was unit-tested but was not
  reachable from the CLI path. `internal/benchmark/pipeline.go`
  `loadScenarioIAMData` updated to read the IAM export fixture by its
  canonical filename (`iam_export.json`) per
  `docs/benchmark_methodology.md` §7.1. The previous implementation
  searched for "one non-manifest JSON file" in the scenario directory,
  which produced an ambiguous-file error in directories containing
  multiple tool fixtures. The canonical filename is shared through
  `benchmark.IAMExportFilename`. `tests/service/benchmark_test.go`
  added, exercising the full CLI-to-aggregator chain with `--tools
  accessgraph` against a self-contained multi-file fixture directory.
- `internal/benchmark/iamvulnerable.go` `ScenarioManifest` struct updated
  to match the SCENARIO schema defined in `docs/ARCHITECTURE.md` (lines
  285-296). The struct previously omitted `starting_principal_arn` and
  `is_true_negative`, and the `chainLengthClass` / `scenarioCategory`
  helper functions did not recognize the `none` values used by
  true-negative environments. The manifest loader and the helper functions
  now populate and recognize them.
- `scripts/capture_scenario.sh` true-negative output path updated to match
  the scenario root layout expected by
  `internal/benchmark/pipeline.go` `LoadScenarios`. The previous path
  `fixtures/tn-environments/<tn-name>/` placed TN fixtures outside the
  scenario root, so the benchmark loader did not discover them. Fixtures
  now land at `fixtures/iamvulnerable/<tn-name>/` alongside the vulnerable
  scenarios. The LocalStack capture workflow now uses `AWS_ENDPOINT_URL`
  for single-endpoint routing and pins the Terraform AWS provider to
  `~> 6.22.0` for TN modules as a workaround for LocalStack issue #13426,
  where provider v6.23+ sends an S3 Control API request that LocalStack
  community edition does not handle.
- `docs/benchmark_methodology.md` §4.2 fixture location reference updated
  to resolve an internal inconsistency with §7.1. The previous text
  described scenario fixtures as living in
  `fixtures/iamvulnerable/vulnerable/` or `clean/` subdirectories; §7.1
  and the reproduction workflow it specifies use the flat layout
  `fixtures/iamvulnerable/<scenario-id>/` for both vulnerable scenarios
  and true-negative environments. The JSON schema block itself is
  unchanged.
- `docs/ARCHITECTURE.md` TN fixture path reference updated from
  `fixtures/iamvulnerable/clean/tn-clean-001.json` to
  `fixtures/iamvulnerable/tn-clean-001/` to match the flat layout that
  `LoadScenarios` reads.
- External tool adapters in `internal/benchmark/` updated to match the
  actual command-line contracts of the underlying binaries. The PMapper
  adapter now invokes
  `pmapper --account <id> analysis --output-type json` against a captured
  graph storage directory (the live `pmapper graph create` step is
  performed by the orchestration layer at capture time, not by the
  adapter). The PMapper parser now handles the real analysis output
  schema (`findings[]` with principal references in description text)
  instead of the previously assumed `paths[].nodes[].arn` structure.
  The Prowler adapter now reads captured `json-ocsf` output directly
  from the scenario fixture rather than invoking the prowler binary.
  The Prowler parser now handles the OCSF schema (`status_code` for
  FAIL/PASS, `resources[].uid` for resource ARNs) instead of the
  previously assumed plain JSON schema (`status`, `resource_arn`).
  The Checkov adapter framework selector changed from `cloudformation`
  to `terraform` to match the IAMVulnerable repository structure.
  Parser unit tests added against captured tool output samples in
  `tests/benchmark/testdata/`. The `--account-id` flag on the benchmark
  command was removed; the account ID is now discovered from the PMapper
  fixture directory structure by the adapter.
- `docs/ARCHITECTURE.md` Dependency Pinning section: replaced the
  `<digest>` placeholder for `golang:1.26-bookworm` with the actual
  sha256 digest pinned in `Dockerfile`.
- `docs/benchmark_methodology.md` §3.1 (PMapper): added Python 3.10+
  compatibility patch documentation describing the one-line mechanical
  `sed` patch, the upstream issue references (nccgroup/PMapper#130,
  #131, #140), the full codebase audit results, and the rationale for
  choosing the patch over a Python 3.9 downgrade.
- `docs/benchmark_methodology.md` §5.2 ("Count") rationale
  strengthened. The previous prose justified n=10 as
  "sufficient... though the small n limits statistical
  precision." The new prose explains that n=10 is driven by
  three converging constraints: it is the statistical floor
  for Wilson CI nominal coverage, the cost-benefit curve in
  the 10-30 range yields only marginal precision improvement
  (materially tighter bounds require n≥60), and FPR is scoped
  as supporting evidence for non-trivial detection rather than
  as a primary metric. The n=10 number itself is unchanged.
- README limitations note on external tool FPR now references the
  `fpr_measured` schema field instead of describing the gap in
  prose only.
- Updated stale doc comment on `TestAggregateClassificationOverride`
  in the aggregator test. The comment described `classification_override`
  as a boolean flag and referenced a planned-but-never-implemented
  asterisk display in the terminal renderer. The test code already used
  the correct string `DetectionLabel` semantics; only the comment was
  out of date.

### Removed
- `requirements-benchmark.txt`: orphan dependency manifest from a prior
  iteration, removed because it is no longer referenced by the Dockerfile
  after the introduction of split `requirements-prowler.txt` and
  `requirements-checkov.txt` files in this commit. The
  `docs/ARCHITECTURE.md` file tree was also updated to reference the new
  split files.
- Steampipe and CloudSploit dropped from the benchmark.
  Both adapters were authored with the assumption that the tools support offline-evaluation
  contracts: Steampipe v2 has no `--input` flag for offline IAM JSON
  evaluation and the `aws_iam` benchmark name does not exist in the
  steampipe-mod-aws-compliance v0.x or v1.x mod; CloudSploit's per-scenario
  `config.js` configures AWS credentials and region, not data inputs. Both
  tools require live AWS API access by design and are architecturally
  incompatible with the offline fixture-replay reproducibility model
  documented in Section 7.3.1. Removed: `internal/benchmark/steampipe.go`,
  `internal/benchmark/cloudsploit.go`, corresponding adapter test cases,
  `SteampipePath` and `CloudSploitPath` fields from `ToolConfig`, the
  `--tools` flag entries, and the `docs/benchmark_methodology.md` Section 3.4
  and Section 3.5 subsections plus their corresponding Section 4 detection-matching
  subsections. The benchmark now covers three external tools (Prowler, PMapper,
  Checkov) representing three distinct detection paradigms (per-policy
  compliance scanning, graph-based principal traversal, and static IaC
  analysis). See `docs/benchmark_methodology.md` Section 1.3 (Tool selection
  rationale) for the full scoping rationale.

### Fixed
- `internal/benchmark/pmapper.go` parser: restricted principal reference
  extraction to findings with title "IAM Principal Can Escalate Privileges".
  The previous implementation extracted principal references from every
  finding in PMapper's analysis output, including circular access,
  overprivileged instance profile, and IAM MFA findings that mention
  principals incidentally without indicating a detected privilege
  escalation path. This conflation could cause the parser to record a
  match when PMapper had not actually detected the expected escalation,
  inflating measured recall. The filter matches the exact title produced
  by PMapper's `gen_privesc_findings()` in
  `principalmapper/analysis/find_risks.py`. Parser unit tests added to
  lock in the filter behavior. Methodology §4.3 PMapper updated to
  document the filter and a known limitation regarding pathed IAM names.
- `docs/benchmark_methodology.md` Section 3.4, Section 3.5, and Section 4.1
  footnote: the pre-existing claim that the Steampipe and CloudSploit
  adapters used `CombinedOutput()` was incorrect. Both adapters actually
  captured stdout and stderr into separate `bytes.Buffer` variables, the
  same pattern used by the remaining three adapters (Prowler, PMapper,
  Checkov). The incorrect prose has been removed along with the dropped
  tool sections.
- `docs/ARCHITECTURE.md` Benchmark Execution Model section had several factual errors corrected: Checkov was incorrectly documented as targeting Python 3.14 (Checkov supports Python 3.9-3.13 inclusive); the rationale for the two-venv split was incorrectly attributed to Python 3.14 runtime incompatibility (the actual cause is the pydantic v1/v2 dependency conflict between Prowler and Checkov); both venvs now correctly target Python 3.11. The Docker base image recommendation was changed from `golang:1.26-alpine` to `golang:1.26-bookworm` because Checkov's official docs warn against Alpine for C extension reasons. The Dockerfile was added to the file tree and to the Planned Extensions section (it was previously missing entirely). A Prowler version pinning rationale paragraph was added explaining why this work pins 5.20.0 and does not bump to 5.21+ despite their availability. No code, test, or other doc changed.
- `docs/benchmark_methodology.md` §7.1 reproduction example
  referenced `--account-id` (which did not exist) and a
  `--scenarios` path that did not match the actual flag contract.
  Both corrected.
- `docs/benchmark_methodology.md` §4.2 was internally inconsistent
  with `docs/findings_schema.md` §2.1 on the `classification_override`
  field type and semantics. The methodology doc carried boolean /
  taxonomy-override prose; the schema doc had been rewritten to
  string DetectionLabel reviewer-override semantics. Synced the
  methodology doc to match the schema doc as the canonical source.
- `docs/ARCHITECTURE.md` "Python environment note" paragraph in the
  Benchmark Execution Model section: corrected the rationale for the
  two-venv design. The previously committed text claimed the two venvs
  were isolated because Prowler pins pydantic v1 and Checkov pulls in
  pydantic v2 transitively. This claim was incorrect for the pinned
  versions. Prowler 5.20.0 uses pydantic v2 (the v1 dependency was a
  Prowler 4.x property, confirmed by upstream issue
  prowler-cloud/prowler#5518). Both Prowler 5.20.0 and Checkov 3.2.509
  use pydantic v2. The actual reason the two venvs cannot be merged is
  that Prowler 5.20.0 pins `boto3==1.40.61` and Checkov 3.2.509 pins
  `boto3==1.35.49`, and these exact pins are irreconcilable. Empirically
  verified by a single-venv `pip install` resolution attempt that fails
  with the conflicting-dependencies error. The rationale has been
  corrected in `docs/ARCHITECTURE.md`, the `Dockerfile` comments,
  `requirements-prowler.txt`, and `requirements-checkov.txt`.
- `docs/benchmark_methodology.md` §3.1 (PMapper) and §3.2 (Prowler) tool
  invocation contracts: corrected the documented command-line flags
  after empirical verification against the Docker image. The
  previously committed §3.1 documented
  `pmapper --input-dir <scenarioDir>` and §3.2 documented
  `prowler aws --input-file <scenarioDir>`. Verification revealed
  that PMapper's `--input-dir` flag is not part of the PMapper CLI;
  graph creation requires live AWS API calls via boto3 (with
  `--localstack-endpoint` available for development). Prowler's `aws`
  provider similarly requires live AWS (with `AWS_ENDPOINT_URL`
  honored for LocalStack development). The corrected §3.1 documents
  PMapper's two-step contract (live `graph create` followed by
  offline `analysis --output-type json` against captured graph
  storage). The corrected §3.2 documents Prowler's live-only contract
  with `--output-formats json-ocsf` and explains the
  captured-output-as-fixture reproducibility model. Two additional
  flag mismatches were caught and corrected in the same review:
  (1) PMapper analysis flag is `--output-type` not `--output`;
  (2) Prowler `--output-formats` accepts `json-ocsf` not plain
  `json`. §3.3 (Checkov) corrected `--framework cloudformation` to
  `--framework terraform` because IAMVulnerable is a Terraform-based
  project. The Go adapters in `internal/benchmark/pmapper.go` and
  `internal/benchmark/prowler.go` will be rewritten in a follow-up
  commit (adapter rewrite). §7.0 reproduction paths rewritten to
  document per-tool fixture types and reproducibility properties.
  §7.1 reproduction-from-scratch script replaced with a workflow
  description stating that the orchestration glue is not yet
  implemented.
- `docs/ARCHITECTURE.md` §14 deferred Makefile targets table: removed
  `docker-build`, `docker-up`, and `docker-down` from the deferred
  list (they were added in commit 694ef29 but the doc was not
  updated). Corrected the `make capture-tool-outputs` description
  from "all six tools" (stale after Steampipe and CloudSploit were
  dropped) and "one representative scenario" (incorrect) to "all
  four tools" and "each IAMVulnerable scenario."
- `docs/ARCHITECTURE.md` §15 planned extensions: marked Dockerfile
  (item 4) and docker-compose configuration (item 5) as DONE.
  Reduced the deferred Makefile target count in item 7 from eleven
  to eight.
