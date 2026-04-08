# tn-clean-006

True-negative environment 6 of 10. Per `docs/benchmark_methodology.md §5.1`,
this environment contains no IAM privilege escalation path.

## Configuration

| Dimension | Value |
|-----------|-------|
| Users | 5 |
| Lambda role trust | Conditional (`aws:SourceAccount` restricts to deploying account) |
| Side resource | None |

## Users and policies

| User | Attached managed policies |
|------|--------------------------|
| `tn-clean-006-user-1` | `AmazonEC2ReadOnlyAccess` |
| `tn-clean-006-user-2` | `IAMReadOnlyAccess` |
| `tn-clean-006-user-3` | `AmazonEC2ReadOnlyAccess`, `IAMReadOnlyAccess` |
| `tn-clean-006-user-4` | `AmazonEC2ReadOnlyAccess` |
| `tn-clean-006-user-5` | `IAMReadOnlyAccess` |

## Variation intent

This is the first module with a conditional trust policy. The lambda role's
trust statement includes an `aws:SourceAccount` condition restricting
assumption to the deploying account, which is AWS's recommended confused-deputy
mitigation for service principals. This tests whether tools correctly parse
conditional trust policies on the read path and do not misclassify a
source-account-scoped lambda trust as an escalation vector. Policy set is
EC2 + IAM read-only; no side resources.
