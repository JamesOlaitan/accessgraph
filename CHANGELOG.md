# Changelog

All notable changes to AccessGraph are documented in this file.
The format is based on Keep a Changelog
(https://keepachangelog.com/en/1.1.0/), and this project adheres
to Semantic Versioning (https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
