# tn-environments/

Ten true-negative IAM environments per `docs/benchmark_methodology.md §5.1`
and `§5.2`. Each module deploys a clean AWS account configuration with no
IAM privilege escalation path, against which detection tools are evaluated
for false positive rate.

## Module index

| Module | Users | Policies | Side resource | Lambda trust |
|--------|-------|----------|---------------|--------------|
| [tn-clean-001](tn-clean-001/) | 3 | S3RO, CWRO | Lambda function | Bare |
| [tn-clean-002](tn-clean-002/) | 4 | EC2RO, RDSRO | S3 bucket | Bare |
| [tn-clean-003](tn-clean-003/) | 5 | IAMRO, S3RO | None | Bare |
| [tn-clean-004](tn-clean-004/) | 4 | CWRO, EC2RO, RDSRO | Lambda function | Bare |
| [tn-clean-005](tn-clean-005/) | 5 | RDSRO, S3RO, CWRO, EC2RO | S3 bucket | Bare |
| [tn-clean-006](tn-clean-006/) | 5 | EC2RO, IAMRO | None | Conditional |
| [tn-clean-007](tn-clean-007/) | 3 | IAMRO, RDSRO | Lambda function | Conditional |
| [tn-clean-008](tn-clean-008/) | 4 | CWRO, RDSRO, EC2RO | S3 bucket | Conditional |
| [tn-clean-009](tn-clean-009/) | 4 | S3RO, CWRO, EC2RO | None | Conditional |
| [tn-clean-010](tn-clean-010/) | 3 | RDSRO, IAMRO | None | Conditional |

Policy abbreviations: S3RO = `AmazonS3ReadOnlyAccess`,
CWRO = `CloudWatchReadOnlyAccess`, EC2RO = `AmazonEC2ReadOnlyAccess`,
IAMRO = `IAMReadOnlyAccess`, RDSRO = `AmazonRDSReadOnlyAccess`.

"Conditional" trust = `aws:SourceAccount` condition on the
`lambda.amazonaws.com` service principal. "Bare" trust = no Condition block.

## Why the modules are not identical

The 10 modules are intentionally varied, not copies. The reason is
statistical, not cosmetic.

`docs/benchmark_methodology.md §6.1` uses a Wilson score confidence interval
to bound per-tool false positive rate. The Wilson CI assumes independent
Bernoulli trials: each (tool, environment) evaluation is a draw from a
Bernoulli distribution with unknown parameter `p` (the tool's true FPR).
The CI is valid only if the trials are independent.

If all 10 modules were identical, the tool's classification logic would
produce the same output for the same input, deterministically. Ten runs of
an identical environment are not 10 independent observations -- they are one
observation repeated. Treating them as 10 independent samples would be
pseudoreplication (Hurlbert 1984), which inflates apparent statistical
precision without adding real information. The resulting CI would be
artificially narrow and would not bound the actual uncertainty.

The variation across modules -- in user count, attached managed policies,
side resources, and lambda trust conditions -- ensures that each environment
presents a structurally distinct IAM graph to the tool under test. The tool
must classify a different input each time, making each classification an
independent Bernoulli trial. This makes the Wilson CI interpretation valid.

## Variation dimensions

Four dimensions are varied across the 10 modules:

1. **User count** -- rotates through 3, 4, and 5. Distribution: 3 modules
   with 3 users (001, 007, 010), 4 with 4 users (002, 004, 008, 009), 3 with
   5 users (003, 005, 006). All 10 modules have unique
   (user_count, side_resource, trust_type) combinations, providing structural
   independence for the Wilson CI computation.

2. **Managed policies** -- five non-mutating AWS-managed policies are rotated
   across users and modules. Each user has 1 or 2 attached policies. No policy
   grants any action from the IAMVulnerable escalation taxonomy.

3. **Side resources** -- three modules include a Lambda function (001, 004,
   007), three include an S3 bucket with public access blocked (002, 005, 008),
   and four include no non-IAM resources (003, 006, 009, 010). Side resources
   test whether tools generate false positives on non-IAM infrastructure
   associated with a lambda-trust role.

4. **Lambda role trust conditions** -- modules 001 through 005 use a bare
   `lambda.amazonaws.com` trust (no Condition block). Modules 006 through 010
   add an `aws:SourceAccount` condition, which is AWS's recommended
   confused-deputy mitigation for service principals. This tests whether tools
   correctly parse conditional trust policies rather than treating any
   lambda-trust role as a potential escalation target.

## Structural validity

TN validity is established structurally per `docs/benchmark_methodology.md
§5.1`. Each module was audited by inspection to confirm that no IAM action
from the IAMVulnerable escalation taxonomy is present. The audit grep command
run at commit time:

```bash
grep -rE \
  'iam:CreatePolicyVersion|iam:SetDefaultPolicyVersion|iam:AttachUserPolicy|iam:AttachGroupPolicy|iam:AttachRolePolicy|iam:PutUserPolicy|iam:PutGroupPolicy|iam:PutRolePolicy|iam:CreateAccessKey|iam:CreateLoginProfile|iam:UpdateLoginProfile|iam:AddUserToGroup|iam:UpdateAssumeRolePolicy|iam:PassRole|lambda:UpdateFunctionCode|glue:UpdateDevEndpoint|ec2:RunInstances|cloudformation:CreateStack|datapipeline:CreatePipeline|glue:CreateDevEndpoint|codebuild:CreateProject|ssm:SendCommand|ssm:StartSession' \
  --include='*.tf' \
  terraform/tn-environments/
```

This grep returned zero matches at commit time.

Note: `sts:AssumeRole` is intentionally excluded from this grep. It appears
in every module's `assume_role_policy` block as the action granting
`lambda.amazonaws.com` the ability to assume the lambda role -- a required
part of any valid lambda trust policy. The escalation-taxonomy risk is
`sts:AssumeRole` in a user identity policy enabling lateral role assumption,
which is structurally distinct. No identity policy in any module grants
`sts:AssumeRole` to any user.
