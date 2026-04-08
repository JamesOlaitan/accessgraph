# tn-clean-008

True-negative environment 8 of 10. Per `docs/benchmark_methodology.md §5.1`,
this environment contains no IAM privilege escalation path.

## Configuration

| Dimension | Value |
|-----------|-------|
| Users | 4 |
| Lambda role trust | Conditional (`aws:SourceAccount` restricts to deploying account) |
| Side resource | S3 bucket |

## Users and policies

| User | Attached managed policies |
|------|--------------------------|
| `tn-clean-008-user-1` | `CloudWatchReadOnlyAccess` |
| `tn-clean-008-user-2` | `AmazonRDSReadOnlyAccess` |
| `tn-clean-008-user-3` | `CloudWatchReadOnlyAccess`, `AmazonRDSReadOnlyAccess` |
| `tn-clean-008-user-4` | `AmazonEC2ReadOnlyAccess` |

## Variation intent

This module combines conditional trust with an S3 bucket side resource and
four users. It is the only module in the conditional-trust half with both an
S3 bucket and four users. The CloudWatch + RDS policy combination is unique to
this module among conditional-trust modules. The fourth user's EC2-only
attachment produces a three-policy-type environment, increasing the diversity
of the IAM attachment graph relative to tn-clean-006 and tn-clean-007.
