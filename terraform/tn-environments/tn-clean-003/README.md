# tn-clean-003

True-negative environment 3 of 10. Per `docs/benchmark_methodology.md §5.1`,
this environment contains no IAM privilege escalation path.

## Configuration

| Dimension | Value |
|-----------|-------|
| Users | 5 |
| Lambda role trust | Bare (`lambda.amazonaws.com`, no Condition) |
| Side resource | None |

## Users and policies

| User | Attached managed policies |
|------|--------------------------|
| `tn-clean-003-user-1` | `IAMReadOnlyAccess` |
| `tn-clean-003-user-2` | `AmazonS3ReadOnlyAccess` |
| `tn-clean-003-user-3` | `IAMReadOnlyAccess` |
| `tn-clean-003-user-4` | `AmazonS3ReadOnlyAccess` |
| `tn-clean-003-user-5` | `IAMReadOnlyAccess`, `AmazonS3ReadOnlyAccess` |

## Variation intent

This module varies on user count (5) and policy set (IAM + S3 read-only, no
non-IAM side resources). `IAMReadOnlyAccess` grants `iam:Get*` and `iam:List*`
operations only. None of these actions appear in the IAMVulnerable escalation
taxonomy. Including `IAMReadOnlyAccess` tests whether tools incorrectly treat
read-only IAM visibility as an escalation signal.
