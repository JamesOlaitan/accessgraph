# tn-clean-005

True-negative environment 5 of 10. Per `docs/benchmark_methodology.md §5.1`,
this environment contains no IAM privilege escalation path.

## Configuration

| Dimension | Value |
|-----------|-------|
| Users | 5 |
| Lambda role trust | Bare (`lambda.amazonaws.com`, no Condition) |
| Side resource | S3 bucket |

## Users and policies

| User | Attached managed policies |
|------|--------------------------|
| `tn-clean-005-user-1` | `AmazonRDSReadOnlyAccess` |
| `tn-clean-005-user-2` | `AmazonS3ReadOnlyAccess` |
| `tn-clean-005-user-3` | `AmazonRDSReadOnlyAccess`, `AmazonS3ReadOnlyAccess` |
| `tn-clean-005-user-4` | `CloudWatchReadOnlyAccess` |
| `tn-clean-005-user-5` | `AmazonEC2ReadOnlyAccess` |

## Variation intent

tn-clean-005 differs from tn-clean-002 (which has 4 users) on the user count
dimension, while sharing the S3 bucket side resource and bare trust policy.
The fifth user's EC2 read-only attachment introduces a fourth policy type
(RDS, S3, CloudWatch, EC2) not present in tn-clean-002's two-type set
(EC2, RDS). This gives the module a unique (user_count, side_resource,
trust_type) triple -- (5, S3, bare) -- across all 10 environments.
