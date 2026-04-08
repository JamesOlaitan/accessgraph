# terraform/

Terraform infrastructure for the AccessGraph benchmark. Two subdirectories:

- `scanner-role/` — the `AccessGraphBenchmarkScanner` IAM role used by all
  detection tools during live-AWS benchmark runs.
- `tn-environments/` — ten true-negative IAM environments against which tools
  are evaluated for false positive rate.

## Requirements

| Tool | Minimum version |
|------|----------------|
| Terraform | 1.14.0 |
| AWS provider (`hashicorp/aws`) | ~> 6.39 |

## Offline validation (no AWS account required)

`terraform validate` checks configuration syntax against the provider schema
and requires no credentials:

```bash
cd terraform/scanner-role
terraform init -backend=false
terraform validate

cd ../tn-environments/tn-clean-001
terraform init -backend=false
terraform validate
# repeat for tn-clean-002 through tn-clean-010
```

## Planning (placeholder credentials)

`terraform plan` resolves data sources (including `aws_caller_identity`) and
therefore requires valid AWS credentials. With placeholder credentials the
plan will fail at the credential-validation stage. Use `terraform validate`
as the offline gate; reserve `terraform plan` for pre-apply checks against
a real account.

## Applying (real AWS account required)

```bash
cd terraform/scanner-role
terraform init
terraform apply
```

Applying to a real account requires:

1. Valid AWS credentials with sufficient permissions to create IAM roles and
   attach managed policies.
2. A principal that satisfies the trust policy. By default this is the
   principal running Terraform; set `trust_principal_arn` to override.

**`terraform apply` provisions real AWS resources and may incur costs.**
Use a dedicated test account per `docs/benchmark_methodology.md §2.1`.

## Lock file convention

Every subdirectory with a `versions.tf` has a committed `.terraform.lock.hcl`
with cross-platform hashes for `linux_amd64`, `darwin_arm64`, and
`darwin_amd64`. Committed lock files follow the HashiCorp recommendation for
reproducible provider installation. Reviewers on any of the three platforms
get byte-identical provider binaries without needing internet access to the
registry at `terraform init` time.

Lock files are generated and regenerated via:

```bash
cd <module-dir>
terraform init
terraform providers lock \
  -platform=linux_amd64 \
  -platform=darwin_arm64 \
  -platform=darwin_amd64
```

Regenerating is necessary after bumping a provider version constraint.

## Specification references

- `docs/benchmark_methodology.md §2.2` — scanning credentials spec (scanner
  role name, attached policies, no write permissions).
- `docs/benchmark_methodology.md §5.1` — true-negative environment
  construction spec (user count, policy constraints, no escalation actions).
- `docs/benchmark_methodology.md §5.2` — minimum count of 10 TN environments.
