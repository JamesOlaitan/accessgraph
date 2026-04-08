# Changelog

All notable changes to AccessGraph are documented in this file.
The format is based on Keep a Changelog
(https://keepachangelog.com/en/1.1.0/), and this project adheres
to Semantic Versioning (https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
- README limitations note on external tool FPR now references the
  `fpr_measured` schema field instead of describing the gap in
  prose only.
- Updated stale doc comment on `TestAggregateClassificationOverride`
  in the aggregator test. The comment described `classification_override`
  as a boolean flag and referenced a planned-but-never-implemented
  asterisk display in the terminal renderer. The test code already used
  the correct string `DetectionLabel` semantics; only the comment was
  out of date.

### Fixed
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
