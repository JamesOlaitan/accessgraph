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

### Changed
- README limitations note on external tool FPR now references the
  `fpr_measured` schema field instead of describing the gap in
  prose only.
