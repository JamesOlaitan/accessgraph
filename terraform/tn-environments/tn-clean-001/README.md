# tn-clean-001

True-negative environment 1 of 10. Per `docs/benchmark_methodology.md §5.1`,
this environment contains no IAM privilege escalation path.

## Configuration

| Dimension | Value |
|-----------|-------|
| Users | 3 |
| Lambda role trust | Bare (`lambda.amazonaws.com`, no Condition) |
| Side resource | Lambda function |

## Users and policies

| User | Attached managed policies |
|------|--------------------------|
| `tn-clean-001-user-1` | `AmazonS3ReadOnlyAccess` |
| `tn-clean-001-user-2` | `CloudWatchReadOnlyAccess` |
| `tn-clean-001-user-3` | `AmazonS3ReadOnlyAccess`, `CloudWatchReadOnlyAccess` |

## Variation intent

This module varies on user count (3), policy set (S3 + CloudWatch), side
resource (Lambda function), and trust shape (bare). It establishes the
baseline configuration against which other modules are differentiated.
The Lambda function adds a non-IAM resource to the environment, testing
whether tools correctly ignore Lambda-associated roles when those roles
carry no escalation-taxonomy permissions.
