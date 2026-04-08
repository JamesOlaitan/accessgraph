# scanner-role

Terraform module that creates the `AccessGraphBenchmarkScanner` IAM role per
`docs/benchmark_methodology.md §2.2`. The role is used by all six detection
tools during benchmark runs against live AWS environments.

## What this creates

- `aws_iam_role.scanner` — IAM role named `AccessGraphBenchmarkScanner` with
  an 8-hour maximum session duration and a parameterized trust policy.
- `aws_iam_role_policy_attachment.read_only` — attaches `ReadOnlyAccess`
  (AWS managed).
- `aws_iam_role_policy_attachment.security_audit` — attaches `SecurityAudit`
  (AWS managed).

## Variables

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `trust_principal_arn` | `string` | `null` | ARN of the IAM principal allowed to assume this role. When `null`, defaults to the ARN of the principal running Terraform. |
| `aws_region` | `string` | `"us-east-1"` | AWS region for the provider. IAM is global; this only affects regional API endpoints. |

## Outputs

| Name | Description |
|------|-------------|
| `role_arn` | ARN of the created scanner role. |
| `role_name` | Literal name `AccessGraphBenchmarkScanner`. |
| `max_session_duration` | `28800` (exposed for documentation). |

## Example usage

```hcl
module "scanner_role" {
  source = "./scanner-role"

  # Allow a specific CI principal to assume the scanner role.
  trust_principal_arn = "arn:aws:iam::123456789012:role/ci-runner"
}

output "scanner_role_arn" {
  value = module.scanner_role.role_arn
}
```

When `trust_principal_arn` is omitted, the trust policy automatically grants
access to whatever principal is running `terraform apply`. This is the
intended workflow for a researcher running the benchmark from their own AWS
session.

## Rationale for max_session_duration = 28800

`docs/benchmark_methodology.md §7.1` documents expected wall-clock time of
4-6 hours for a full benchmark run (31 scenarios plus 10 true-negative
environments, including Terraform deploy/destroy cycles). An 8-hour
(28800 second) session duration gives a 2-hour buffer over the 6-hour
worst case -- a 33% margin -- without reaching the AWS maximum of 43200
seconds. AWS recommends setting the session duration to no longer than
needed to perform the role. Eight hours is the minimum that accommodates
the full benchmark runtime without requiring a mid-run credential refresh.

## Known limitation: AWS managed policy versions

`ReadOnlyAccess` and `SecurityAudit` are AWS-managed policies that AWS
maintains and updates independently. Terraform can attach these policies
by ARN but cannot pin them to a specific version. The role's effective
permissions may change over time as AWS revises the managed policy
documents. This is a documented limitation of the benchmark scanning
role, not a defect. Researchers reproducing the benchmark at a later
date should verify that `ReadOnlyAccess` and `SecurityAudit` still
provide sufficient permissions for the tools under evaluation.

## Offline validation gate

`terraform validate` is the canonical offline check. It requires no AWS
credentials and validates configuration syntax against the provider schema.

```bash
cd terraform/scanner-role
terraform init -backend=false
terraform validate
```

`terraform plan` requires valid AWS credentials and will fail with a
credential error in an offline environment. This is expected behavior;
use `terraform validate` for CI and pre-commit checks that run without
AWS access.
