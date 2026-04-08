# Changelog

All notable changes to AccessGraph are documented in this file.
The format is based on Keep a Changelog
(https://keepachangelog.com/en/1.1.0/), and this project adheres
to Semantic Versioning (https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `terraform/tn-environments/`: 10 true-negative environment modules
  (`tn-clean-001` through `tn-clean-010`) per
  `docs/benchmark_methodology.md §5.1`. Each module deploys least-privilege
  IAM users (read-only managed policies only) and one lambda-trust IAM role
  with no dangerous permissions. Modules vary in user count (3-5), specific
  managed policies attached, side resources (Lambda functions, S3 buckets),
  and lambda role trust conditions. All 10 modules have unique
  (user_count, side_resource, trust_type) combinations: 3 modules with 3
  users (001, 007, 010), 3 with 4 users (002, 004, 008), 4 with 5 users
  (003, 005, 006). The variation exists to provide independent
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
- `--account-id` flag on the `benchmark` subcommand. Required for
  live-AWS fixture capture; allows the benchmark binary
  to be invoked against any AWS test account without relying on
  ambient credentials' caller identity.

### Changed
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
