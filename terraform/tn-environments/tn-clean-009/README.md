# tn-clean-009

True-negative environment 9 of 10. Per `docs/benchmark_methodology.md §5.1`,
this environment contains no IAM privilege escalation path.

## Configuration

| Dimension | Value |
|-----------|-------|
| Users | 4 |
| Lambda role trust | Conditional (`aws:SourceAccount` restricts to deploying account) |
| Side resource | None |

## Users and policies

| User | Attached managed policies |
|------|--------------------------|
| `tn-clean-009-user-1` | `AmazonS3ReadOnlyAccess` |
| `tn-clean-009-user-2` | `CloudWatchReadOnlyAccess` |
| `tn-clean-009-user-3` | `AmazonEC2ReadOnlyAccess` |
| `tn-clean-009-user-4` | `AmazonS3ReadOnlyAccess`, `CloudWatchReadOnlyAccess` |

## Variation intent

tn-clean-009 differs from tn-clean-006 (which has 5 users) on the user count
dimension, while sharing the no-side-resource configuration and conditional
lambda trust policy. This gives the module a unique (user_count,
side_resource, trust_type) triple -- (4, None, conditional) -- across all 10
environments. The S3 + CloudWatch + EC2 policy set, with one user holding two
policies, produces a moderately dense IAM attachment graph without introducing
any escalation-taxonomy action.
