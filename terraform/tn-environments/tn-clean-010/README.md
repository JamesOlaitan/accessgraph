# tn-clean-010

True-negative environment 10 of 10. Per `docs/benchmark_methodology.md §5.1`,
this environment contains no IAM privilege escalation path.

## Configuration

| Dimension | Value |
|-----------|-------|
| Users | 3 |
| Lambda role trust | Conditional (`aws:SourceAccount` restricts to deploying account) |
| Side resource | None |

## Users and policies

| User | Attached managed policies |
|------|--------------------------|
| `tn-clean-010-user-1` | `AmazonRDSReadOnlyAccess` |
| `tn-clean-010-user-2` | `IAMReadOnlyAccess` |
| `tn-clean-010-user-3` | `AmazonRDSReadOnlyAccess`, `IAMReadOnlyAccess` |

## Variation intent

The minimal conditional-trust configuration: three users, RDS + IAM read-only
policies, no side resources. The RDS + IAM combination with conditional trust
has not appeared in any prior module. The three-user count with no side
resource contrasts with tn-clean-007 (same user count, conditional trust, but
Lambda side resource) and tn-clean-006 (conditional trust, no side resource,
five users). This module completes the set of 10 independent observations
required by `docs/benchmark_methodology.md §5.2`.
