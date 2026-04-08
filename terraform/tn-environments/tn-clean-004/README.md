# tn-clean-004

True-negative environment 4 of 10. Per `docs/benchmark_methodology.md §5.1`,
this environment contains no IAM privilege escalation path.

## Configuration

| Dimension | Value |
|-----------|-------|
| Users | 4 |
| Lambda role trust | Bare (`lambda.amazonaws.com`, no Condition) |
| Side resource | Lambda function |

## Users and policies

| User | Attached managed policies |
|------|--------------------------|
| `tn-clean-004-user-1` | `CloudWatchReadOnlyAccess` |
| `tn-clean-004-user-2` | `AmazonEC2ReadOnlyAccess` |
| `tn-clean-004-user-3` | `CloudWatchReadOnlyAccess`, `AmazonEC2ReadOnlyAccess` |
| `tn-clean-004-user-4` | `AmazonRDSReadOnlyAccess` |

## Variation intent

tn-clean-004 differs from tn-clean-001 (which has 3 users) on the user count
dimension, while sharing the Lambda function side resource and bare trust
policy. The fourth user's RDS read-only attachment introduces a third policy
type (CloudWatch, EC2, RDS) not present in tn-clean-001's two-type set
(S3, CloudWatch). This gives the module a unique (user_count, side_resource,
trust_type) triple -- (4, Lambda, bare) -- across all 10 environments.
