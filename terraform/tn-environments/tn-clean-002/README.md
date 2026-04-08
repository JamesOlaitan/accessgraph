# tn-clean-002

True-negative environment 2 of 10. Per `docs/benchmark_methodology.md §5.1`,
this environment contains no IAM privilege escalation path.

## Configuration

| Dimension | Value |
|-----------|-------|
| Users | 4 |
| Lambda role trust | Bare (`lambda.amazonaws.com`, no Condition) |
| Side resource | S3 bucket |

## Users and policies

| User | Attached managed policies |
|------|--------------------------|
| `tn-clean-002-user-1` | `AmazonEC2ReadOnlyAccess` |
| `tn-clean-002-user-2` | `AmazonRDSReadOnlyAccess` |
| `tn-clean-002-user-3` | `AmazonEC2ReadOnlyAccess` |
| `tn-clean-002-user-4` | `AmazonRDSReadOnlyAccess` |

## Variation intent

This module varies on user count (4), policy set (EC2 + RDS), and side
resource (S3 bucket with public-access blocked). The EC2 and RDS read-only
policies exercise the tool's classification of read-only compute and database
permissions, which are distinct from the S3/CloudWatch set used in tn-clean-001.
The S3 bucket side resource tests whether tools flag non-public buckets as
escalation vectors.
