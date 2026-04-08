# tn-clean-007

True-negative environment 7 of 10. Per `docs/benchmark_methodology.md §5.1`,
this environment contains no IAM privilege escalation path.

## Configuration

| Dimension | Value |
|-----------|-------|
| Users | 3 |
| Lambda role trust | Conditional (`aws:SourceAccount` restricts to deploying account) |
| Side resource | Lambda function |

## Users and policies

| User | Attached managed policies |
|------|--------------------------|
| `tn-clean-007-user-1` | `IAMReadOnlyAccess` |
| `tn-clean-007-user-2` | `AmazonRDSReadOnlyAccess` |
| `tn-clean-007-user-3` | `IAMReadOnlyAccess`, `AmazonRDSReadOnlyAccess` |

## Variation intent

This module combines conditional trust (from tn-clean-006 onward) with a
Lambda side resource and a smaller user count (3). The IAM + RDS read-only
policy set has not appeared in any prior module. A Lambda function is attached
to the role, meaning there is a real Lambda-role association in the account.
This distinguishes it from tn-clean-006 (conditional trust, no Lambda) and
tn-clean-001 (Lambda, bare trust).
