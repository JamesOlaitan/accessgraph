# Benchmark Methodology

This document is the formal specification that governs how AccessGraph is evaluated against Prowler, PMapper, and Checkov on the IAMVulnerable dataset.

The `outputAdapter.parse()` implementation for each tool in `internal/benchmark/`
matches this specification. Any deviation between code and this document
is a defect in the code, not in this document.

---

## 1. Dataset

**IAMVulnerable** (Seth Art, Bishop Fox, 2021) deploys over 250 AWS IAM resources
via Terraform to create 31 unique privilege escalation paths, each granting a
distinct IAM principal a route to administrative access.

**Pinned commit:** `0f298666f9b7cfa01488b86912afdb211773188a`

All reproduction attempts must use this SHA. Results produced from a
different commit are not comparable. The SHA is recorded in
`fixtures/iamvulnerable/COMMIT` and embedded in every benchmark report as
`iamvulnerable_commit`.

Each scenario includes:

- A set of IAM principals (users, roles, groups) deployed by Terraform
- IAM policies with a specific misconfiguration enabling privilege escalation
- A designated **starting principal**: the IAM user or role an attacker is assumed
  to initially compromise
- A ground-truth attack path: the minimal ordered sequence of IAM actions and
  principals traversed to reach full administrative access

Source: https://github.com/BishopFox/iam-vulnerable

### 1.1 Scenario taxonomy

IAMVulnerable's 31 paths fall into five categories. The `chain_length_class` for
each scenario is derived from this taxonomy, not assigned arbitrarily.

> **Implementation note:** The table below gives the default `chain_length_class`
> for each category. Several individual scenarios deviate from the category default
> due to how their specific Terraform configuration chains permissions. Always
> check Section 1.2 for per-scenario overrides before assigning `chain_length_class` to
> a scenario fixture. When a Section 1.2 Decision line exists for a scenario, it takes
> precedence over the category default in this table.

| Category | `category` value | `chain_length_class` | Mechanism |
|----------|-----------------|---------------------|-----------|
| Direct IAM policy manipulation | `direct_policy` | `simple` | `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:AttachUserPolicy/GroupPolicy/RolePolicy`, `iam:PutUserPolicy/GroupPolicy/RolePolicy` |
| User and credential manipulation | `credential_manipulation` | `simple` | `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:AddUserToGroup` |
| Role trust manipulation | `role_trust` | `two_hop` | `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` |
| PassRole combinations | `passrole_chain` | `multi_hop` | `iam:PassRole` + `ec2:RunInstances`, `lambda:CreateFunction` + `lambda:InvokeFunction`, `lambda:CreateFunction` + `lambda:CreateEventSourceMapping`, `cloudformation:CreateStack`, `datapipeline:CreatePipeline`, `glue:CreateDevEndpoint` |
| Service abuse | `service_abuse` | `multi_hop` | `lambda:UpdateFunctionCode`, `glue:UpdateDevEndpoint`, transitive multi-hop role assumption chains |

**Per-class counts:**

Derived from direct inspection of the IAMVulnerable Terraform source at pinned commit `0f298666`. Each scenario's `.tf` file was read to identify the starting principal's permissions and trace the escalation path. Edge case classifications are documented in Section 1.2.

| Class | Hop count | Count | Scenario IDs |
|-------|-----------|-------|---|
| `simple` | 1 | 11 | privesc1, privesc4, privesc5, privesc6, privesc7, privesc8, privesc9, privesc10, privesc11, privesc12, privesc13 |
| `two_hop` | 2 | 2 | privesc2, privesc14 |
| `multi_hop` | 3+ | 18 | privesc3, privesc15, privesc16, privesc17, privesc18, privesc19, privesc20, privesc21, privesc-AssumeRole, privesc-cloudFormationUpdateStack, privesc-codeBuildCreateProjectPassRole, privesc-ec2InstanceConnect, privesc-sageMakerCreateNotebookPassRole, privesc-sageMakerCreatePresignedNotebookURL, privesc-sageMakerCreateProcessingJob, privesc-sageMakerCreateTrainingJob, privesc-ssmSendCommand, privesc-ssmStartSession |

**Total: 31**

IAMVulnerable cloned at commit `0f298666f9b7cfa01488b86912afdb211773188a`. Terraform resource naming convention confirmed across all 31 scenarios: every `aws_iam_*` resource label in a scenario's `.tf` file contains the scenario directory name as a substring.

Two naming conventions exist in the dataset:
  - Numeric prefix style: `privesc[N]-[ActionName]` (e.g. `privesc4-CreateAccessKey`)
  - Hyphenated style: `privesc-[service]-[action]` (e.g. `privesc-sageMakerCreateNotebookPassRole`)

The Checkov adapter's exact match on `resource` field against `ExpectedAttackPath` elements is used for detection (see Section 4.3).

Complete scenario list (31 scenarios, all in `modules/free-resources/privesc-paths/`):
  - `privesc1-CreateNewPolicyVersion`
  - `privesc2-SetExistingDefaultPolicyVersion`
  - `privesc3-CreateEC2WithExistingIP`
  - `privesc4-CreateAccessKey`
  - `privesc5-CreateLoginProfile`
  - `privesc6-UpdateLoginProfile`
  - `privesc7-AttachUserPolicy`
  - `privesc8-AttachGroupPolicy`
  - `privesc9-AttachRolePolicy`
  - `privesc10-PutUserPolicy`
  - `privesc11-PutGroupPolicy`
  - `privesc12-PutRolePolicy`
  - `privesc13-AddUserToGroup`
  - `privesc14-UpdatingAssumeRolePolicy`
  - `privesc15-PassExistingRoleToNewLambdaThenInvoke`
  - `privesc16-PassRoleToNewLambdaThenTriggerWithNewDynamo`
  - `privesc17-EditExistingLambdaFunctionWithRole`
  - `privesc18-PassExistingRoleToNewGlueDevEndpoint`
  - `privesc19-UpdateExistingGlueDevEndpoint`
  - `privesc20-PassExistingRoleToCloudFormation`
  - `privesc21-PassExistingRoleToNewDataPipeline`
  - `privesc-AssumeRole`
  - `privesc-cloudFormationUpdateStack`
  - `privesc-codeBuildCreateProjectPassRole`
  - `privesc-ec2InstanceConnect`
  - `privesc-sageMakerCreateNotebookPassRole`
  - `privesc-sageMakerCreatePresignedNotebookURL`
  - `privesc-sageMakerCreateProcessingJob`
  - `privesc-sageMakerCreateTrainingJob`
  - `privesc-ssmSendCommand`
  - `privesc-ssmStartSession`

### 1.2 Edge cases in chain_length_class assignment

Several scenarios require explicit classification decisions because the hop count
is not obvious from the category alone.

The following edge cases must be resolved and documented here before
`iamvulnerable.go` is implemented:

- **`iam:SetDefaultPolicyVersion`**: Requires the attacker to have previously
  created a policy version via `iam:CreatePolicyVersion`. Whether this constitutes
  one hop (CreatePolicyVersion precondition is implicit) or two hops
  (CreatePolicyVersion is a required prior action) affects classification.
  **Decision**: Classify as `simple` if the IAMVulnerable scenario grants both
  permissions to the starting principal; classify as `two_hop` if
  `iam:CreatePolicyVersion` requires a separate action by a different principal.
  Record the final classification per scenario in the scenario fixture metadata.
  **Decision for `privesc2-SetExistingDefaultPolicyVersion`**: Classified as
  `two_hop`. The `.tf` file at the pinned commit grants only `iam:SetDefaultPolicyVersion`
  to the starting user — `iam:CreatePolicyVersion` is absent entirely, so a pre-existing
  high-privilege policy version must be created by a separate principal before the
  starting user can exploit it. (The Terraform source comment explicitly notes the
  scenario is not exploitable in isolation for this reason.)

- **`iam:AddUserToGroup` chains**: Adding a user to a group that holds a
  dangerous managed policy is a two-action sequence. Classify as `two_hop` if
  group membership is not already established in the scenario baseline.
  **Decision for `privesc13-AddUserToGroup`**: Classified as `simple`. At the
  pinned commit, the starting user (`privesc13-AddUserToGroup-user`) has
  `iam:AddUserToGroup` on `*` directly attached. The `privesc-sre-group` (deployed
  by `sre.tf` in the same `privesc-paths` module) already exists in the baseline
  with `privesc-sre-admin-policy` (`iam:*`, `ec2:*`, `s3:*`) attached. The starting
  user needs exactly one action — `iam:AddUserToGroup` to add themselves to
  `privesc-sre-group` — to inherit admin-equivalent permissions. No second principal
  and no second IAM action are required.

Any scenario whose classification is disputed must be listed here with its
final classification and a one-sentence justification.

**Additional per-scenario classifications (verified at pinned commit `0f298666`):**

- **`privesc-AssumeRole`**: `multi_hop`. The Terraform source creates a three-role
  chain (`starting-role` → `intermediate-role` → `ending-role`); reaching the
  ending role (which holds `Action: "*"` on `*`) requires three sequential
  `sts:AssumeRole` calls, satisfying the 3+ hop definition. **Deployment
  prerequisite:** `privesc-AssumeRole-start-user` has no IAM policy attached —
  the trust policy on `privesc-AssumeRole-starting-role` allows only
  `var.aws_assume_role_arn`. For the benchmark, `var.aws_assume_role_arn` must
  be set to the start-user's Amazon Resource Name (ARN) in `terraform.tfvars` at deploy time. The
  scenario fixture's `starting_principal_arn` is `privesc-AssumeRole-start-user`.

- **`privesc-ec2InstanceConnect`**: `multi_hop`. The scenario grants
  `ec2-instance-connect:SendSSHPublicKey` to push a temporary SSH key to an EC2
  instance, then requires external SSH access to reach the instance's attached
  `privesc-high-priv-service-role` (`Action: "*"`). The escalation path spans an
  IAM action, a network layer, and a service role — consistent with the
  `service_abuse` / `multi_hop` category in Section 1.1.

- **`privesc-ssmSendCommand`**: `multi_hop`. The scenario grants `ssm:sendCommand`
  to execute arbitrary commands on any SSM-managed EC2 instance; escalation requires
  targeting an instance with `privesc-high-priv-service-role` attached and running
  AWS CLI commands from within that session — consistent with `service_abuse` /
  `multi_hop`.

- **`privesc-ssmStartSession`**: `multi_hop`. Grants `ssm:StartSession` to open an
  interactive shell on a managed EC2 instance; same service-role-abuse pattern as
  `privesc-ssmSendCommand` — `service_abuse` / `multi_hop`.

- **`privesc-sageMakerCreateNotebookPassRole`**: `multi_hop`. The scenario grants
  `iam:PassRole` + `sagemaker:CreateNotebookInstance` + `sagemaker:CreatePresignedNotebookInstanceUrl`;
  full escalation requires three sequential IAM-level actions — `iam:PassRole`,
  notebook creation, and presigned-URL generation — before code can be executed
  under the passed role. Consistent with `passrole_chain` / `multi_hop` in Section 1.1.

- **`privesc-sageMakerCreatePresignedNotebookURL`**: `multi_hop`. The scenario grants
  only `sagemaker:CreatePresignedNotebookInstanceUrl` (plus recon-only
  `sagemaker:ListNotebookInstances`) with no `iam:PassRole`. Escalation requires an
  already-running notebook instance with a privileged role attached (provided by the
  co-deployed `privesc-sageMakerCreateNotebookPassRole` scenario in full-module
  deployments). Classified `multi_hop` per the Section 1.1 `service_abuse` taxonomy;
  classification is by mechanism, not hop count. The single-permission nature of
  this scenario is noted as a limitation in Section 8. The `BenchmarkResult.chain_length_class`
  for this scenario is `multi_hop` regardless of what hop count AccessGraph's breadth-first search (BFS)
  reports at runtime — this is expected behavior per ARCHITECTURE.md §6, which
  states that `chain_length_class` in `BenchmarkResult` is always copied from the
  scenario fixture ground-truth, never derived from `hop_count` at runtime.
  This scenario is an exception to the hop-count-based default: the `multi_hop`
  label reflects the classification taxonomy in Section 1.1 (which groups by mechanism
  category), not the hop-count definition in ARCHITECTURE.md §6 (which applies
  to `AttackPath` objects in analysis reports, not benchmark scenario fixtures).
  The distinction between these two derivation rules is specified in
  ARCHITECTURE.md §6 paragraph 5.

- **`privesc-sageMakerCreateProcessingJob`** (Terraform resource name
  `privesc-sageMakerCreateProcessingJobPassRole`): `multi_hop`. Grants
  `sagemaker:CreateProcessingJob` + `iam:PassRole`; the `passrole_chain` +
  SageMaker service action combination requires multiple steps to reach code
  execution under the passed role. Consistent with `passrole_chain` / `multi_hop`.

- **`privesc-sageMakerCreateTrainingJob`** (Terraform resource name
  `privesc-sageMakerCreateTrainingJobPassRole`): `multi_hop`. Grants
  `sagemaker:CreateTrainingJob` + `iam:PassRole`; identical classification
  rationale as `privesc-sageMakerCreateProcessingJob`.

- **`privesc3-CreateEC2WithExistingIP`**: `multi_hop`, category `passrole_chain`.
  The name is misleading — "IP" abbreviates "Instance Profile", not "IP address".
  Full Terraform resource name: `privesc3-CreateEC2WithExistingInstanceProfile`.
  The starting principal holds `iam:PassRole`, `ec2:RunInstances`,
  `ec2:CreateKeyPair`, `ec2:DescribeInstances`, and
  `ec2:AssociateIamInstanceProfile`. Escalation: (1) `iam:PassRole` to pass
  `privesc-high-priv-service-role`, (2) `ec2:RunInstances` launching an instance
  with that role's instance profile, (3) SSH into the instance via the created
  key pair, (4) retrieve temporary credentials from instance metadata. Three
  IAM-level actions plus an EC2 service boundary — definitively `multi_hop`.

- **`privesc9-AttachRolePolicy` and `privesc12-PutRolePolicy`**: `simple`,
  category `direct_policy`. Both scenarios grant a single role-targeting policy
  manipulation permission (`iam:AttachRolePolicy` or `iam:PutRolePolicy` on `*`)
  with no explicit `sts:AssumeRole`. The subsequent `sts:AssumeRole` step needed
  to use the modified role is operationalization of the result, not a separate
  escalation step. The benchmark measures whether tools detect the vulnerability
  (the unrestricted policy manipulation permission), not whether tools model the
  full exploitation chain. Bishop Fox's IAMVulnerable taxonomy lists both under
  `direct_policy` → `simple`.

### 1.3 Tool selection rationale

This work benchmarks AccessGraph against three external open-source tools: Prowler, PMapper, and Checkov. These three were selected because they represent three meaningfully distinct detection paradigms relevant to the research claim:

- **PMapper** (NCC Group): graph-based principal traversal. The most direct comparison for AccessGraph's BFS-based approach.
- **Prowler**: per-policy compliance scanning. Represents the dominant CSPM detection paradigm.
- **Checkov**: static analysis of Infrastructure-as-Code templates. Represents the shift-left IaC scanning paradigm.

Two additional tools were initially considered but excluded after investigation: Steampipe and CloudSploit. Both tools require live AWS API access by design. Steampipe is a SQL data platform whose AWS plugin queries live cloud APIs through a connection layer; it does not support evaluation against offline IAM JSON files. CloudSploit's per-scenario `config.js` configures AWS credentials and region rather than data inputs. Neither tool supports the offline fixture-replay reproducibility model that this work commits to in Section 7.3.1, and both would require live AWS execution at every reproduction attempt by an artifact reviewer. They are therefore out of scope for this benchmark and may be revisited as a separate contribution under a live-AWS-only methodology.

This scoping is a deliberate methodological choice: three well-validated tools that share AccessGraph's offline-evaluable property are preferred over a larger comparison set that mixes offline and live-only tools and complicates reproducibility.

---

## 2. Execution environment

All tools are run against **live AWS environments** deployed from the IAMVulnerable
Terraform configuration at the pinned commit. No offline JSON export is used as
a substitute for live execution.

**Rationale:** PMapper and Prowler require live AWS API access to function
correctly. Running them against static exports either produces zero output
(Prowler) or partial output that does not reflect their actual detection
capability. Using live environments ensures each tool is evaluated under the
conditions it was designed for, making the comparison fair and the results
reproducible by any researcher with AWS access.

### 2.1 AWS account setup

Each scenario is deployed in a **dedicated AWS test account** with no production
resources. The account must:

- Contain no IAM resources other than those deployed by IAMVulnerable and the
  read-only scanning role (see Section 2.2)
- Have CloudTrail disabled during benchmark runs to avoid confounding any
  tool that reads CloudTrail for detection (none of the six do, but this is
  precautionary)
- Have GuardDuty disabled — GuardDuty detection is outside the scope of this benchmark
- Be destroyed and rebuilt from scratch for each benchmark run to eliminate
  state accumulation between scenarios

### 2.2 Scanning credentials

Each tool runs under a dedicated IAM role (`AccessGraphBenchmarkScanner`) with
the following managed policies attached:

- `ReadOnlyAccess` (AWS managed)
- `SecurityAudit` (AWS managed)

No write permissions are granted to the scanning role. Tools that require
additional permissions beyond these (e.g., to create IAM resources as part of
exploitation simulation) are not granted those permissions — they are evaluated
only on their detection capability, not exploitation.

### 2.3 Scenario isolation

Each of the 31 IAMVulnerable scenarios is deployed and evaluated independently.
The deployment sequence for each scenario:

1. Run `terraform apply` for the scenario's Terraform module
2. Wait for all IAM resources to propagate (60-second sleep; IAM changes can
   take up to 60 seconds to be globally consistent)
3. Run all four tools against the live account
4. Record all raw outputs
5. Run `terraform destroy` for the scenario's module
6. Verify the account returns to baseline (no scenario IAM resources remain)

**IAM propagation failure detection:** If a scenario produces a false negative (FN) for **all four tools** (including PMapper and AccessGraph), this likely indicates IAM propagation was incomplete at the 60-second mark. In this case, re-run the scenario with a 120-second propagation delay. If the second run produces the expected true positives (TPs), use the second-run results and record the propagation delay in the benchmark notes. If the second run also produces all-FN, the scenario ground truth should be investigated.

**Do not deploy multiple scenarios simultaneously.** Concurrent IAM resources
from different scenarios create cross-scenario detection opportunities that
invalidate per-scenario scoring.

**`sre.tf` shared infrastructure:** `sre.tf` resides in the same
`modules/free-resources/privesc-paths/` module as all 31 numbered scenarios. `sre.tf` is
not an isolated sub-module; a full `terraform apply` of `privesc-paths` always
deploys `privesc-sre-user`, `privesc-sre-role`, and `privesc-sre-group` alongside
every scenario's resources. These shared resources carry admin-equivalent permissions
(`iam:*`, `ec2:*`, `s3:*`) and will generate findings in all four tools during every
scenario run. Under the matching criterion (Section 4.1), findings on
`privesc-sre-*` principals do not score as TP for scenarios whose
`ExpectedAttackPath` does not contain `privesc-sre-*` ARNs — they are irrelevant noise
and are excluded by the exact/substring match on `ExpectedAttackPath` elements.
The `privesc-sre-group` IS the escalation target for `privesc13-AddUserToGroup` and
its presence in the shared baseline is required for that scenario to be valid.

---

## 3. Tool invocations

The exact command for each tool is the authoritative specification for its
`outputAdapter` implementation. Any invocation that differs from what is listed
here is a benchmark defect.

**`detection_latency_ms` measurement boundary:** The latency measurement covers tool invocation time only. The clock starts before `adapter.Invoke()` is called and stops when `adapter.Invoke()` returns. Output parsing time (`adapter.Parse()`) is excluded. For Prowler, latency covers only the file-read time of the captured `.ocsf.json` fixture (Prowler is not re-invoked at benchmark replay time). For PMapper, latency covers the `pmapper analysis` subprocess execution against the captured graph storage. This definition is implemented in `dispatch()` in `dispatch_integration.go`.

**Cross-tool latency comparisons:** `detection_latency_ms` is not directly comparable across tools. External tool latency includes process startup overhead; AccessGraph latency covers the in-process pipeline (parse, build, BFS, score). Latency analysis in the paper is therefore reported per-tool only, not as a cross-tool ranking.

### 3.1 PMapper

PMapper is a graph-based IAM principal-traversal tool. Unlike the other external tools, PMapper has a two-step contract: graph creation requires live AWS API calls, but graph analysis can run offline against the locally-stored graph. This split is load-bearing for the benchmark's offline reproducibility model.

**Step 1 -- graph creation (live AWS, capture-time only):**

```bash
pmapper --profile <profile> graph create
```

- Calls live AWS IAM APIs via boto3 to enumerate users, roles, groups, policies, and trust relationships
- Stores the resulting graph in `$PMAPPER_STORAGE/<account-id>/` where `PMAPPER_STORAGE` defaults to `/root/.local/share/principalmapper` on Linux
- Must be re-run for every scenario; PMapper does not have a per-scenario graph isolation mechanism, so the benchmark orchestration must set a unique `PMAPPER_STORAGE` per scenario or rotate the storage directory between scenarios
- For development against LocalStack, use the `--localstack-endpoint http://localhost:4566` flag instead of `--profile`
- For canonical capture, use a real AWS profile with `ReadOnlyAccess` and `SecurityAudit` permissions (the `AccessGraphBenchmarkScanner` IAM role from `terraform/scanner-role/`)
- PMapper logs benign "Unable to search region" warnings for regions that LocalStack does not serve; these can be suppressed with `--include-regions us-east-1` when running against LocalStack but should not be used against live AWS

**Step 2 -- graph analysis (offline):**

```bash
pmapper --account <account-id> analysis --output-type json
```

- Reads the previously-created graph from `$PMAPPER_STORAGE/<account-id>/`
- No network access required
- The analysis output flag is `--output-type` (NOT `--output`)
- Output is JSON to stdout
- The `--account` flag is REQUIRED in this step and selects which previously-created graph to analyze; it is NOT a live AWS account ID (live operations use `--profile` instead)

**Fixture format:** PMapper's fixture is the entire `$PMAPPER_STORAGE/<account-id>/` directory tree containing the graph metadata, edge data, and policy cache. This directory is captured after a successful `pmapper graph create` against the deployed scenario and replayed at reproduction time by setting `PMAPPER_STORAGE` to point at the captured directory. The captured directory contains binary serialized graph data that PMapper writes via its own storage layer; the reproduction step does not parse it directly but instead invokes `pmapper analysis` against the loaded graph.

**Reproducibility properties:** PMapper graph creation cannot be re-executed offline because it requires live AWS API calls. The reproduction model for PMapper is therefore: capture once against live AWS, replay `pmapper analysis` against the captured graph storage indefinitely. Reviewers running `make reproduce-fixtures` re-execute the analysis step against the committed graph storage fixtures; they do not re-execute graph creation.

**Python 3.10+ compatibility patch:** PMapper 1.1.5 (released January 2022, the latest published version on PyPI) is incompatible with Python 3.10 and later because `principalmapper/util/case_insensitive_dict.py:34` imports `Mapping` and `MutableMapping` from the `collections` module rather than `collections.abc`. The `collections` aliases for these abstract base classes were deprecated in Python 3.3 and removed in Python 3.10. The PMapper maintainer has not shipped a fix; upstream issues nccgroup/PMapper#130, #131, and #140 (the latter from November 2023) all document the same problem and remain open. PMapper's PyPI classifiers list Python 3.5 through 3.9 only.

This benchmark applies a one-line mechanical patch to the installed PMapper source inside the Docker image, rewriting the broken import to source `Mapping` and `MutableMapping` from `collections.abc` (the canonical Python 3.10+ form). The patch is applied via `sed` in the Dockerfile during the Prowler venv build step and is verified post-application by re-importing `CaseInsensitiveDict` in a Python sub-process. The patch does not modify PMapper's analysis logic, graph construction, BFS traversal, query interface, or any detection-relevant code path. `CaseInsensitiveDict` is an internal helper class used for IAM condition key case-insensitive matching; the patch only changes where the abstract base classes are imported from, not their behavior.

An audit of the entire PMapper 1.1.5 codebase confirmed this is the only Python 3.10+ incompatibility present. The audit searched for: removed `collections` aliases (3.10), removed `inspect.getargspec` (3.11), removed `asyncio.coroutine` decorator (3.11), removed `imp` module (3.12), removed `distutils` (3.12), and deprecated `datetime.utcnow` (3.12). Only the single `case_insensitive_dict.py` import was found. No other patches are required for PMapper 1.1.5 to function correctly under Python 3.11.

This patch is documented as a known modification to the system under test for artifact-evaluation. The alternative considered was downgrading the Prowler venv to Python 3.9 (the highest version PMapper officially supports), which would have required either a separate Python 3.9 installation in the Docker image or the use of `uv` to provision Python 3.9 alongside the system Python 3.11. The one-line patch was chosen because it is smaller in scope, fully audited, and does not introduce additional Python runtime version variation across the benchmark image.

### 3.2 Prowler

Prowler is a per-policy compliance scanner. Its `aws` provider performs live IAM evaluations via boto3 and has no offline input mode. Unlike PMapper, Prowler has no intermediate state that can be captured for offline replay of the binary itself.

**Live invocation (capture-time only):**

```bash
prowler aws \
  --profile <profile> \
  --output-formats json-ocsf \
  --output-directory <tmpdir>
```

- Calls live AWS IAM APIs via boto3 to evaluate IAM configurations against Prowler's check suite
- Output format is `json-ocsf` (NOT plain `json`); Prowler 5.20.0's `--output-formats` flag accepts `csv`, `json-asff`, `json-ocsf`, or `html`. The benchmark uses `json-ocsf` because it is the standard machine-readable output that contains finding structure with resource ARNs
- `<tmpdir>` is created dynamically via `os.MkdirTemp` per invocation
- For development against LocalStack, set the standard boto3 environment variable `AWS_ENDPOINT_URL=http://localhost:4566` and use placeholder credentials (`AWS_ACCESS_KEY_ID=test`, `AWS_SECRET_ACCESS_KEY=test`); Prowler honors `AWS_ENDPOINT_URL` natively because boto3 does
- For canonical capture, use a real AWS profile with the `AccessGraphBenchmarkScanner` role's permissions (`ReadOnlyAccess` + `SecurityAudit`)
- No `--checks` filter is applied; Prowler runs its full check suite
- Prowler exit code 3 indicates findings were detected (success); exit code 0 indicates no findings (also success); any other non-zero exit code is a tool failure (`ErrToolFailed`)
- Output reading at capture time: Prowler writes its output to `<tmpdir>/prowler-output-<account-id>-<timestamp>.ocsf.json`. At benchmark replay time, the adapter reads the first `*.ocsf.json` file from the scenario fixture directory via `readProwlerFixture()` and does not re-invoke Prowler

**Fixture format:** Prowler's fixture is the captured `json-ocsf` output file from a successful live run. The file is named `prowler-output-<account-id>-<timestamp>.ocsf.json` by Prowler. This file is committed as the Prowler fixture for that scenario.

**Reproducibility properties:** Prowler cannot be re-executed offline. There is no `--input-file` flag, no `--input-dir` flag, and no other mechanism for feeding pre-exported IAM JSON to Prowler's AWS provider. The reproduction model for Prowler is therefore: capture Prowler's `json-ocsf` output once against live AWS, then re-parse that captured output through the benchmark's adapter at reproduction time without re-invoking Prowler. The captured output IS the canonical fixture; the adapter and metric-computation pipeline are what get exercised during reproduction, not Prowler itself.

Many academic benchmarks separate "tool execution" from "results processing" exactly this way, and the AE Functional badge requires that the pipeline reproduces metrics from captured inputs, not that upstream tools are re-executable. But the methodology must be explicit about this property because it differs from AccessGraph and Checkov (which re-execute end-to-end during reproduction) and PMapper (which re-executes only its analysis step).

**Prowler iac provider not used:** Prowler also has an `iac` subcommand that scans Terraform/CloudFormation source files locally. This subcommand IS offline-capable, but it performs static IaC misconfiguration scanning, not runtime IAM privilege evaluation. Using `prowler iac` would mean benchmarking a different code path than the `aws` provider that this work claims to benchmark, and would also collapse the "three distinct detection paradigms" framing in §1.3 because it would put Prowler in the same paradigm as Checkov. The benchmark therefore uses `prowler aws` exclusively.

### 3.3 Checkov

```bash
checkov -d <scenarioDir> --framework terraform --output json
```

- `-d` specifies the scenario directory containing the input files to scan
- `--framework terraform` is used for scanning Terraform modules from the IAMVulnerable repo
- No `--check` filter is applied; Checkov runs all checks for the specified framework
- No `--compact` or `--quiet` flags are used
- Output format: JSON written to stdout
- Exit code: 1 indicates check failures were found (treated as success, not error); any other non-zero exit code is treated as a tool failure (`ErrToolFailed`)

**Reproducibility properties:** Checkov scans local source files and requires no AWS access at any point. Its fixture is the IAMVulnerable repository pinned at commit `0f298666f9b7cfa01488b86912afdb211773188a`. The pinned IAMVulnerable source IS the fixture; no separate capture step is needed.

---

## 4. Detection matching specification

This section defines exactly what constitutes a TP, false positive (FP), FN, and true negative (TN) for each
tool. The `parse()` method in each tool's `outputAdapter` implements exactly
this specification. Any ambiguity here is resolved in favor of the stricter
interpretation.

### 4.1 Matching framework

The benchmark measures whether each tool **detects any element of the expected attack path** — that is, whether the tool's output contains any ARN (or matching identifier) from the scenario's `ExpectedAttackPath` array.

**What TP means:** A tool receives TP for a scenario if its output contains any element of `ExpectedAttackPath` (the array of all path node ARNs for the scenario). The tool does not need to identify the specific ground-truth mechanism or the complete path. A match on any single node in the expected path is sufficient.

**Rationale:** The research claim is that tools differ in multi-hop escalation detection and that no prior work has systematically measured this across tools on a common dataset. The TP criterion tests whether the tool recognizes any element of the attack path, which is the operationally meaningful question. Requiring full path matching would penalize tools that discover valid alternate paths and is not uniformly enforceable across all four tools (most do not emit action-level detail).

**What TP does not mean:** A detection is not valid if the tool merely flags some other IAM entity in the environment that does not appear in `ExpectedAttackPath`. A tool that flags an unrelated resource does not receive TP.

**Per-tool observable proxy for detection:** Tools differ in how they represent detected entities. The following table defines the field inspected and matching rule for each tool. The fields listed in this table are the only fields inspected for TP/FN classification:

| Tool | Observable field | Match type | Justification |
|------|-----------------|------------|---------------|
| PMapper | Principal references (`user/<name>`, `role/<name>`) in `findings[].description`, reconstructed to full ARNs using `account` field | Exact ARN match against `ExpectedAttackPath` elements | PMapper emits principal names in finding descriptions; ARNs are reconstructed as `arn:aws:iam::<account>:<ref>` |
| Prowler | `resources[].uid` in json-ocsf output array | Exact ARN match against `ExpectedAttackPath` elements (where `status_code="FAIL"`) | Prowler OCSF findings carry resource ARNs in `resources[].uid` with FAIL/PASS in `status_code` |
| Checkov | `resource` in `results.failed_checks` JSON | Exact match against `ExpectedAttackPath` elements (where severity is HIGH/CRITICAL/empty) | Checkov emits resource labels in failed checks |
| AccessGraph | `path.ToResourceID` → ARN via `snapshot.Resources` | Exact ARN match against terminal (last) element of `ExpectedAttackPath` | In-process; maps internal resource IDs to ARNs |

**Role of `expected_escalation_actions`:** This field is not used in TP/FN classification for any tool. It is preserved in the scenario fixture for post-hoc analysis: researchers can inspect which mechanisms each tool actually detects versus the ground-truth mechanism. The field does not affect any metric computation.

### 4.2 Ground-truth fields per scenario

**Canonical scenario identity table:** The `scenario_id` is the primary key for all cross-document joins, fixture lookups, `result_id` hashing, and reproduction diffs. For vulnerable scenarios, it equals the full Terraform directory name. For true negative environments, it uses the format `tn-clean-NNN`.

Each scenario fixture in `fixtures/iamvulnerable/<scenario-id>/` contains:

```json
{
  "scenario_id": "privesc1-CreateNewPolicyVersion",
  "name": "privesc1-CreateNewPolicyVersion",
  "source": "modules/free-resources/privesc-paths/privesc1-CreateNewPolicyVersion",
  "category": "direct_policy",
  "chain_length_class": "simple",
  "classification_override": "",
  "is_true_negative": false,
  "starting_principal_arn": "arn:aws:iam::ACCOUNT_ID:user/privesc1-CreateNewPolicyVersion-user",
  "expected_escalation_actions": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
  "expected_path_nodes": [
    "arn:aws:iam::ACCOUNT_ID:user/privesc1-CreateNewPolicyVersion-user",
    "arn:aws:iam::aws:policy/AdministratorAccess"
  ]
}
```

True negative example:
```json
{
  "scenario_id": "tn-clean-001",
  "name": "tn-clean-001",
  "source": "",
  "category": "none",
  "chain_length_class": "none",
  "classification_override": "",
  "is_true_negative": true,
  "starting_principal_arn": "",
  "expected_escalation_actions": [],
  "expected_path_nodes": []
}
```

`expected_path_nodes` (mapped to `ExpectedPathNodes` in the `Scenario` struct) provides internal node IDs of the expected path. The canonical match target for all tools (via the per-tool proxy in Section 4.1) is the `expected_attack_path` field (mapped to `ExpectedAttackPath` in code).
`expected_escalation_actions` is retained for post-hoc mechanism analysis only; it does not affect TP/FN scoring.
`classification_override` is a string field containing a `DetectionLabel` value. It is non-empty when a human reviewer has overridden the auto-assigned detection label for a result. It is empty string when no override exists. It is not related to the taxonomy vs. hop-count classification mechanism.

### 4.3 Per-tool detection criteria

---

**PMapper**

Output field inspected: JSON output from `pmapper --account <account-id> analysis --output-type json`.

The output is parsed into a `pmapperAnalysis` struct containing `Account string` (`json:"account"`) and `Findings []pmapperFinding` (`json:"findings"`). Each `pmapperFinding` has `Title string`, `Severity string`, and `Description string` fields. PMapper's analysis output is a high-level findings report, not structured graph paths. Principal references appear in the `Description` field as type/name pairs (e.g., `user/escalation-user`, `role/admin-role`).

The adapter filters the findings array to only those with title `"IAM Principal Can Escalate Privileges"` -- the exact title that PMapper's `gen_privesc_findings()` function produces for privilege escalation detections. Other finding types that `pmapper analysis` may emit (circular access, overprivileged instance profile, IAM users without MFA, and others) are excluded from the extraction loop because they may mention principals incidentally without indicating a detected escalation path.

From each retained finding, the adapter extracts principal references matching the pattern `(user|role|group)/[\w.+=,@-]+`, reconstructs full ARNs as `arn:aws:iam::<account>:<ref>` using the top-level `account` field from the analysis output, and checks for intersection with `ExpectedAttackPath` elements.

**TP:** Any reconstructed principal ARN exactly matches any element of `ExpectedAttackPath`.

**FN:** No reconstructed principal ARN matches any element of `ExpectedAttackPath`.

**FP:** Not classified by the external tool dispatch logic. See Section 5.3 for false positive rate (FPR) limitations.

**Known limitation:** PMapper's `Node.searchable_name()` method collapses pathed IAM names (e.g., `arn:aws:iam::acct:user/path/to/name`) to the first/last component form (`user/name`), dropping intermediate path segments. The IAMVulnerable scenarios do not use pathed IAM names, so this does not affect benchmark results, but users running AccessGraph against production AWS accounts with pathed IAM names should be aware that the PMapper-analysis-based detection criterion may miss matches where the expected path ARN contains intermediate path segments.

---

**Prowler**

Output field inspected: captured json-ocsf output from `prowler aws --output-formats json-ocsf`. The adapter reads the captured `.ocsf.json` file directly from the scenario fixture directory rather than re-invoking Prowler.

The output is parsed as `[]prowlerOCSFFinding`, where each `prowlerOCSFFinding` has `StatusCode string` (`json:"status_code"`) and `Resources []prowlerOCSFResource` (`json:"resources"`). Each `prowlerOCSFResource` has `UID string` (`json:"uid"`) containing the resource ARN. In Prowler's OCSF output, `status_code` holds `"FAIL"` or `"PASS"` (the `status` field holds an OCSF lifecycle value like `"New"` and is not used for detection matching).

**TP:** A finding exists where both conditions hold:
1. `status_code` equals `"FAIL"` (case-insensitive comparison via `strings.EqualFold`)
2. Any `resources[].uid` exactly matches any element of `ExpectedAttackPath`

The adapter collects resource UIDs from all FAIL findings into a set and checks for intersection with the expected attack path elements. No `event_code` or check ID filtering is applied.

**FN:** No FAIL finding has a `resources[].uid` matching any element of `ExpectedAttackPath`.

**FP:** Not classified by the external tool dispatch logic. See Section 5.3 for FPR limitations.

**Known limitation:** The benchmark evaluates Prowler's individual check output,
not its newer attack path visualization feature. Prowler's checks evaluate
per-policy conditions and may produce a TP for `simple` scenarios where a single
dangerous permission is directly attached to the starting principal, but will
generally produce FN for `multi_hop` scenarios where no individual policy
statement is dangerous in isolation. This reflects the scope of Prowler's check
framework as evaluated; Prowler's attack path visualization capability is not
exercised by this benchmark's invocation method.

---

**Checkov**

Output field inspected: JSON stdout from `checkov -d <scenarioDir> --framework terraform --output json`.

The output is parsed as a `checkovResult` struct containing `Results.FailedChecks`, where each failed check has `Resource string` and `Severity string` fields.

**TP:** A failed check exists where both conditions hold:
1. `severity` is `"HIGH"`, `"CRITICAL"`, or empty (empty severity is accepted for compatibility with older Checkov versions that do not populate this field)
2. `resource` exactly matches any element of `ExpectedAttackPath`

The adapter collects resource IDs from severity-filtered failed checks into a set and checks for intersection with the expected attack path elements. No `check_id` filtering is applied.

**FN:** No severity-filtered failed check has a `resource` matching any element of `ExpectedAttackPath`.

**FP:** Not classified by the external tool dispatch logic. See Section 5.3 for FPR limitations.

**Known limitation:** Checkov checks the presence of dangerous individual
permissions in policy documents. Checkov does not model whether those permissions
are reachable from the designated starting principal. A policy attached to a
role that is not reachable from the starting principal may still produce a TP
under this criterion. This behavior is a known weakness of per-policy scanning and is
discussed in the paper.

---

**AccessGraph**

Detection is performed in-process by `classifyDetectionInternal()` in `pipeline.go`, which receives the blast-radius analysis results from `runAccessGraphOnScenario()`.

**Classification logic:**

1. **TN scenario with no paths found:** If `expected.IsTrueNegative` is true and no escalation paths were discovered, the result is `LabelTN` (true negative).
2. **TN scenario with paths found:** If `expected.IsTrueNegative` is true but escalation paths were discovered, the result is `LabelFP` (false positive).
3. **TP:** For non-TN scenarios, each discovered `path.ToResourceID` is resolved to an ARN via the snapshot's resource map. If any resolved ARN exactly matches the **last (terminal) element** of `ExpectedAttackPath`, the result is `LabelTP`. The `from_principal_id` is not checked — only the terminal destination matters.
4. **FN:** If no path's terminal ARN matches the last element of `ExpectedAttackPath`, the result is `LabelFN`.

**Why terminal element only:** AccessGraph matches against the last element of `ExpectedAttackPath` (the escalation destination), not against all path elements. This behavior differs from the external tool adapters, which match against any element. The distinction reflects that AccessGraph produces structured paths with explicit endpoints, while external tools produce unstructured findings.

**`detection_latency_ms` boundary:** For AccessGraph, `detection_latency_ms` covers the full in-process pipeline executed by `runAccessGraphOnScenario()` (parse → build → synthesize edges → BFS → score → classify). The in-process latency measurement is not comparable to external tool latency, which includes process startup overhead. See Section 3 cross-tool latency caveat.

---

### 4.4 Handling tool failures and timeouts

Two distinct failure modes are both labeled `LabelTimeout` in `DetectionLabel`:

1. **True deadline exceeded** (`TimeoutKind = "deadline"`): the tool did not exit within the 5-minute per-scenario deadline. The subprocess was killed via SIGKILL.
2. **Infrastructure failure** (`TimeoutKind = "infrastructure"`): the tool exited non-zero due to a network error, credential expiry, or AWS API throttle before it could complete detection.

Both are excluded from precision and recall computation identically. The structural distinction is preserved in the `timeout_kind` field on each `BenchmarkResult` (see ARCHITECTURE.md §10.9 `TimeoutKind` and findings_schema.md §2.1). Post-hoc analysis can thereby distinguish tool slowness from environmental flakiness without parsing `RawStderr`. Both `RawStdout` and `RawStderr` are also always populated for manual triage.

`LabelTimeout` results (regardless of `timeout_kind`) are:

- Excluded from precision and recall computation
- Reported separately in the comparison table as a failure count per tool, with `deadline` and `infrastructure` sub-counts
- Investigated and re-run if the count exceeds 3 for any tool across the full 31-scenario suite; re-runs that also fail are kept as `LabelTimeout` and noted in the paper. Infrastructure failures are re-run with higher priority than deadline failures, since they indicate environmental issues rather than tool limitations.

---

## 5. True negative environments

To compute false positive rate and prevent tools from achieving 100% recall by
flagging everything, the benchmark includes clean IAM environments — AWS accounts
with no privilege escalation path — against which tool output is scored as FP
or TN.

### 5.1 Construction

Each true negative environment contains:

- Three IAM users with least-privilege policies (read-only S3, read-only
  CloudWatch, no IAM permissions)
- One IAM role with a trust policy restricted to a single service principal
  (`lambda.amazonaws.com`) and no dangerous permissions
- No `iam:PassRole`, `iam:CreateAccessKey`, `iam:CreatePolicyVersion`, or any
  other action from the IAMVulnerable escalation taxonomy

**TN validity is established structurally, not by tool output.** Each TN environment is accepted as valid based on manual audit of its Terraform source confirming that no IAM action from the escalation taxonomy is present. The structural validity of each TN environment is documented in the fixture metadata with the specific IAM actions present and absent (e.g., `"actions_present": ["s3:GetObject", "cloudwatch:GetMetricData"], "escalation_actions_absent": true"`).

**Sanity check (not acceptance criterion):** After structural evaluation, both AccessGraph and PMapper (`pmapper --account <account-id> analysis --output-type json`) are run against each TN environment as a sanity check. If either tool reports an escalation path in a structurally evaluated TN environment, the discrepancy is investigated — the structural definition takes precedence, and the tool's false positive is documented. The tool check does not serve as the acceptance criterion because using evaluated tools to define their own ground truth creates circular reasoning.

### 5.2 Count

A minimum of **10 true negative environments** are used. The
choice of n=10 is driven by three constraints that converge
on the same value:

1. **Statistical floor.** n=10 is the minimum sample size at
   which the Wilson score confidence interval (used in §6 for
   FPR computation) provides reliable nominal coverage.
   Below n=10, Wilson coverage degrades and the interval
   loses its claimed 95% guarantee. n=10 is therefore the
   smallest value at which the §6 metric is statistically
   valid.

2. **Cost-benefit curve.** For 0 observed false positives, the
   resulting 95% upper bound is approximately 0.309 (Wilson)
   or 0.30 (rule-of-three approximation). This bound is
   acknowledged as wide. Tightening it materially would
   require n ≥ 60, which would push the per-run wall-clock
   past the budget specified in §7.1 (4-6 hours). Intermediate
   values of n in the 10-30 range yield only marginal precision
   improvement (n=20 gives an upper bound of ~0.17; n=30 gives
   ~0.12) at substantial wall-clock cost. There is no sweet
   spot between "minimum viable" and "much larger" — the
   practical choices are n=10 (floor) or n≥60 (materially
   tight). This work commits to the floor.

3. **Metric scoping.** FPR is treated in this work as
   supporting evidence for non-trivial detection — that is,
   evidence that AccessGraph does not achieve high recall by
   flagging everything — rather than as a primary metric.
   The headline finding is per-class recall variation across
   tools (§6); FPR's role is to confirm that AccessGraph's
   recall is not produced by an over-permissive classifier.
   A wide-but-honest upper bound is sufficient for this
   supporting role. The wide bound reflects this scoping
   choice, not a measurement gap.

AccessGraph's measured FPR is reported with its full Wilson
95% confidence interval, and any claim about FPR magnitude
is qualified by the upper bound rather than by the point
estimate.

### 5.3 Scoring

For each (tool, TN environment) pair:

- **TN:** The tool produces no finding matching the criteria in Section 4.3
- **FP:** The tool produces one or more findings matching the criteria in Section 4.3

False Positive Rate per tool:

$$FPR(T) = \frac{FP(T)}{FP(T) + TN(T)}$$

where the denominator is the number of true negative environments evaluated.

**External tool FPR limitation:** In the current implementation, FPR is computed only for AccessGraph. External tools (Prowler, PMapper, Checkov) are evaluated via `dispatch()`, which classifies results as TP or FN based on whether `ExpectedAttackPath` elements appear in the output. On TN environments where `ExpectedAttackPath` is empty, `Parse()` always returns false, producing `LabelFN` regardless of whether the tool flagged the environment. The result is that external tool FPR is not measured by this benchmark. The `false_positive_rate` table in benchmark JSON output contains zero values for external tools — these represent unmeasured FPR, not confirmed zero FPR.

---

## 6. Metrics

For each tool $T$ and chain-length class $C$:

- $TP(T, C)$ = scenarios in class $C$ where $T$ produced a TP
- $FP(T, C)$ = findings on TN environments (not class-specific; reported at tool level)
- $FN(T, C)$ = scenarios in class $C$ where $T$ produced a FN
- $TN(T)$ = TN environments where $T$ produced no findings

**Recall** (per tool per class) — primary reported metric:

$$R(T, C) = \frac{TP(T, C)}{TP(T, C) + FN(T, C)}$$

Defined as 0 when $TP + FN = 0$. TIMEOUT rows are excluded from both numerator and denominator.

**Recall** (per tool, across all classes) — micro-average:

$$R(T) = \frac{\sum_C TP(T, C)}{\sum_C (TP(T, C) + FN(T, C))}$$

Tool-level recall is the micro-average: each vulnerable scenario contributes equally regardless of which class it belongs to. The micro-average is used in the $F_1(T)$ formula below and stored in `ToolMetrics.Recall`. Macro-average (mean of per-class recalls) is not used because class sizes differ substantially (11 simple, 2 two_hop, 18 multi_hop), and macro-average would overweight the two_hop class. TIMEOUT rows are excluded from both numerator and denominator.

**Precision** (per tool, not per class):

$$P(T) = \frac{TP(T)}{TP(T) + FP(T)}$$

where $TP(T)$ and $FP(T)$ are totals across all scenarios and TN environments respectively.

Per-class precision is not reported. $FP$ is computed from true negative environments, which are not organized by `chain_length_class`. Combining a class-scoped $TP(T, C)$ numerator with a tool-level $FP(T)$ denominator produces a ratio without a clean frequentist interpretation. The resulting ratio cannot be read as "of the tool's detections in class $C$, what fraction were correct," because the denominator counts false positives against TN environments that belong to no class at all.

Defined as 0 when $TP + FP = 0$.



**F1 score** (per tool, not per class):

$$F_1(T) = \frac{2 \cdot P(T) \cdot R(T)}{P(T) + R(T)}$$

where $P(T)$ and $R(T)$ are both tool-level values. Defined as 0 when both are 0.

Per-class F1 is not reported. The same reason that prevents per-class precision (FP denominator is not class-scoped) applies identically to per-class F1: $F_1(T, C)$ would require $P(T, C)$, which requires a class-scoped FP denominator that does not exist. Computing $F_1$ from tool-level $P(T)$ and per-class $R(T, C)$ would produce a metric without a standard name or interpretation. The `ClassMetrics` struct therefore omits any F1 field — F1 is stored only in `ToolMetrics`.

**False Positive Rate** (per tool, across TN environments):

$$FPR(T) = \frac{FP(T)}{FP(T) + TN(T)}$$

The primary reported metrics are Recall by chain-length class and F1 overall.
FPR is reported as a secondary metric to characterize precision behavior.

### 6.1 Confidence intervals

Given $n = 31$ scenarios, point estimates of precision and recall have high
variance. The Wilson score interval at 95% confidence is reported alongside
all precision and recall values.

For a proportion $\hat{p}$ with $n$ observations and $z = 1.96$ (95% confidence):

$$CI_{Wilson} = \frac{\hat{p} + \frac{z^2}{2n} \pm z\sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$

The Wilson score interval is implemented in `benchmark/aggregator.go` as `wilsonCI`.

**Clamping:** Floating-point arithmetic can produce bounds outside [0, 1] when $\hat{p}$ is near 0 or 1 with small $n$. After computing the ± variants, clamp: `low = max(0.0, low)`, `high = min(1.0, high)`. Then round both to six decimal places. After clamping and rounding, if `0 <= low <= p_hat <= high <= 1` is violated, the implementation must panic — this indicates a formula bug, not a data condition.

**`n` for each CI application:**

| Metric | $\hat{p}$ | $n$ | Notes |
|--------|-----------|-----|-------|
| Per-class recall $R(T,C)$ | $TP(T,C) / (TP(T,C) + FN(T,C))$ | $TP(T,C) + FN(T,C)$ | Observations are vulnerable scenarios in class $C$ |
| Tool-level recall $R(T)$ | $\sum_C TP / \sum_C (TP + FN)$ | $\sum_C (TP(T,C) + FN(T,C))$ | Observations are all vulnerable scenarios |
| Tool-level precision $P(T)$ | $TP(T) / (TP(T) + FP(T))$ | $TP(T) + FP(T)$ | **Mixed population:** TP comes from vulnerable scenarios and FP comes from TN environments. These are different sampling frames. The CI is reported as a descriptive summary, not as a formal frequentist interval with a single well-defined population. |
| FPR | $FP(T) / (FP(T) + TN(T))$ | $FP(T) + TN(T)$ | Observations are TN environments only |

**Small-n acknowledgment:** With 31 scenarios and class sizes of fewer than 20
each, confidence intervals are wide. A difference in recall of 0.1 between two
tools may not be statistically distinguishable. The paper does not claim
statistical significance for differences below 0.2 in recall within any class.
The primary claim is that tools vary substantially in multi-hop detection
capability and that this variation has not been systematically measured on a
common dataset. Supporting this claim requires demonstrable recall differences
on `multi_hop` scenarios across the tool set, a difference large enough to be
meaningful at n=9.

**Precision prevalence-dependence:** Reported precision is computed from 31 vulnerable scenarios (contributing TP) and 10 true negative environments (contributing FP). The resulting precision value depends on this 31:10 ratio, which is a benchmark design choice, not a reflection of real-world prevalence. Precision should not be interpreted as the tool's expected precision in production environments where the base rate of IAM misconfiguration differs. The primary metric for this study is recall by chain-length class; precision is reported as a secondary characterization of tool behavior.

---

## 7. Reproducibility

### 7.0 Reproduction paths

The benchmark supports two reproduction targets, each with different requirements and AE-badge implications:

| Target | What it verifies | Requires | Wall-clock | AE badge |
|--------|-----------------|----------|------------|----------|
| `make reproduce-fixtures` | Pipeline correctness against captured fixtures | Go + Docker (no AWS) | ~10 minutes | Artifacts Evaluated — Functional |
| `make reproduce` | External validity via fresh live capture | Go + Docker + AWS credentials | 4-6 hours | Results Reproduced |

**For artifact-evaluation reviewers:** Start with `make reproduce-fixtures`. It runs each tool's reproduction step against the committed fixtures and verifies the metric pipeline produces the expected output (per §7.3.1). No AWS account is needed.

**Per-tool reproducibility properties:** The four tools have different fixture types and different reproduction semantics. This is a property of the upstream tools, not a design choice -- the benchmark cannot make Prowler re-executable offline because Prowler's AWS provider has no offline input mode.

| Tool | Fixture type | Reproduction step |
|------|--------------|-------------------|
| AccessGraph | IAM JSON snapshot per scenario | Re-runs full pipeline (parse, graph, BFS, blast radius, OPA, score) end-to-end against the fixture |
| Checkov | IAMVulnerable Terraform source pinned to commit `0f298666...` | Re-runs `checkov -d <fixture_dir> --framework terraform --output json` end-to-end against the pinned source |
| PMapper | `$PMAPPER_STORAGE/<account-id>/` directory tree captured after live `graph create` | Re-runs `pmapper --account <id> analysis --output-type json` against the captured graph storage; does NOT re-run `graph create` |
| Prowler | `json-ocsf` output file captured from live `prowler aws` run | Re-parses the captured `json-ocsf` file through the benchmark adapter and runs the metric pipeline; does NOT re-invoke Prowler |

**The "captured-output-as-fixture" pattern (Prowler):** Some external tools cannot be re-executed offline because their evaluation logic requires live cloud APIs. For these tools, the canonical fixture is the captured tool output from a single live run, and reproduction verifies that the benchmark's adapter and metric computation produce the same numbers from the same captured input. This pattern is standard in academic benchmarks that incorporate tools whose execution is environment-bound. The trade-off is that the reviewer cannot independently verify Prowler would still produce the same output if re-run against the same scenario; they verify the pipeline correctness, not the tool determinism. Tool determinism is verified separately by `make reproduce`, which re-runs the live capture against fresh AWS deployments and confirms the new captures match the old captures within tolerance.

### 7.1 Reproduction from scratch (live AWS)

Full live-AWS reproduction is the responsibility of the `make reproduce` target. The target wraps the orchestration workflow described below and is the recommended entry point for reviewers seeking the "Results Reproduced" AE badge.

**Workflow per scenario** (executed by `make reproduce` for each of the 31 IAMVulnerable scenarios + 10 TN environments):

1. `terraform apply` the scenario's Terraform module against a dedicated AWS test account, using the `AccessGraphBenchmarkScanner` role from `terraform/scanner-role/`
2. Wait for IAM eventual consistency (Terraform's internal waits handle this)
3. Export the resulting IAM state using `./bin/accessgraph export-iam --profile accessgraph-benchmark --output fixtures/iamvulnerable/<scenario>/iam_export.json` for use as the AccessGraph and Checkov fixtures
4. Run `pmapper graph create` against the deployed scenario; the resulting `$PMAPPER_STORAGE/<account-id>/` directory becomes the PMapper fixture for this scenario
5. Run `prowler aws --output-formats json-ocsf` against the deployed scenario; the resulting `.ocsf.json` file becomes the Prowler fixture for this scenario
6. Run `checkov -d <iamvulnerable_terraform_dir> --framework terraform` against the IAMVulnerable Terraform source (no live AWS interaction)
7. `terraform destroy` the scenario
8. Save all captured fixtures and tool outputs to `fixtures/iamvulnerable/<scenario-name>/`

**Wall-clock estimate:** 4-6 hours total for the full 31 scenarios + 10 TN environments. Sequential Terraform `apply`/`destroy` cycles dominate (~3 minutes each x 41 environments = ~2 hours). PMapper graph creation adds 1-3 minutes per scenario. Prowler adds 2-5 minutes per scenario. AccessGraph and Checkov complete in seconds.

**AWS cost estimate:** Under $10 for a full run. IAMVulnerable scenarios deploy IAM resources only (no EC2, no S3, no compute). IAM has no per-resource hourly cost; the only AWS cost is API call volume which is well within the free tier for a single run.

**Development environment (LocalStack):** For apparatus development and integration testing without AWS spend, LocalStack 3.8 (the last free community edition) is sufficient for all three live-AWS-requiring tools. PMapper accepts `--localstack-endpoint`; Prowler honors `AWS_ENDPOINT_URL`; Terraform's AWS provider accepts explicit `endpoints { iam = "..." }` blocks. LocalStack is the recommended development environment but is NOT suitable for a canonical capture because LocalStack's IAM fidelity is approximate: complex trust conditions, permission boundaries, and SCP interactions can behave subtly differently than real AWS. The canonical `make reproduce` target requires real AWS credentials.

The `scripts/capture_scenario.sh <scenario-name>` script implements steps 1-8 of this workflow for a single scenario against LocalStack for development. It handles two modes: IAMVulnerable privilege escalation scenarios (dispatched by the `privesc*` name prefix) and true-negative environments (dispatched by the `tn-clean-*` prefix). For vulnerable scenarios, each deployment includes the scenario's `.tf` file plus `sre.tf` per Section 2.3. For canonical capture against real AWS, set `AWS_ENDPOINT_URL` to empty and provide real credentials through `--profile`. The orchestration layer for running all 31 privilege escalation scenarios and 10 TN environments in sequence is tracked as future work.

**Implementation status:** As of this commit, the full `make reproduce` target is not yet implemented. Single-scenario capture is available through `scripts/capture_scenario.sh` and `make capture-scenario SCENARIO=<name>`. Multi-scenario orchestration and the `make reproduce` target are tracked in §15 of ARCHITECTURE.md.

### 7.2 Verifying fixture integrity

Golden fixtures in `fixtures/iamvulnerable/` are checksummed at generation
time. To verify:

```bash
sha256sum -c fixtures/iamvulnerable/CHECKSUMS
```

Any mismatch indicates fixture corruption or tampering and invalidates
benchmark results derived from those fixtures.

### 7.3 Expected output for a known-good run

This section has two sub-sections: Section 7.3.1 for offline fixture-based reproduction and Section 7.3.2 for live-AWS reproduction. Section 7.3.1 must be populated before `make reproduce-fixtures` can be implemented (it is the oracle for that target). Section 7.3.2 must be populated before paper submission.

#### 7.3.1 Fixture-level expected metrics (offline oracle)

**Fixture type heterogeneity:** The four tools have different fixture types (see §7.0). The §7.3.1 oracle must specify expected metrics per tool, not as a single cross-tool comparison. AccessGraph and Checkov re-run end-to-end and produce deterministic metrics; PMapper re-runs analysis against captured graph storage and produces deterministic metrics; Prowler re-parses captured output and produces deterministic metrics (because the captured output is static). All four reproduction paths are deterministic; tolerance is +/-0 on counts and exact-match on float metrics.

> To be populated after the first successful run of `make reproduce-fixtures`.
> These values are **deterministic** — golden fixtures are static, so the same
> pipeline must produce identical results every time. Tolerance is ±0 on all
> counts and exact match (to 6 decimal places) on all float metrics.
>
> Record here:
> - Per-tool total TP/FN counts against golden fixtures
> - Per-tool per-class recall values (6 decimal places)
> - Per-tool FPR from TN fixtures
> - Total timeout count (expected: 0 for offline fixtures)
>
> Format: a JSON object matching the `by_tool_and_class` + `by_tool` +
> `false_positive_rate` structure from findings_schema.md §2, so that
> `make reproduce-fixtures` can diff programmatically.

This sub-section is the acceptance oracle for `make reproduce-fixtures`. When empty, `make reproduce-fixtures` runs in capture mode (prints results, exits 0, operator reviews and populates this section). When populated, it runs in verify mode (diffs output against these values, exits non-zero on any divergence).

**Reproduction diff scope:** Because `run_id` is a random UUIDv4 and `result_id` is derived from it, these fields differ between runs. The diff compares only metric values, not identifiers or timestamps. Specifically:

- **Included in diff:** all fields in `by_tool_and_class` (counts and floats), all fields in `by_tool` (counts and floats), all fields in `false_positive_rate` (counts and floats).
- **Excluded from diff:** `run_id`, `label`, `generated_at`, all `result_id` values, all `run_at` values, `raw_stdout`, `raw_stderr`.
- **For the `results` array:** match rows by `(scenario_id, tool_name)` composite key and compare only `detection_label`, `timeout_kind`, `chain_length_class`, `category`, `classification_override`, and `is_true_negative`.

The `make reproduce-fixtures` implementation must apply this diff scope; a naive full-JSON diff will always fail due to `run_id`/`result_id` differences.

#### 7.3.2 Live-AWS expected metrics

> To be populated after the first complete live-AWS benchmark run. Record here:
> - Total TP/FP/FN counts per tool
> - Recall by class for each tool
> - Any scenarios where AccessGraph produced unexpected results
> - Any tool invocations that timed out

This section must be populated before the paper is submitted. A reviewer running the
reproduction instructions must be able to verify their output matches these
values.

**`make reproduce` operating modes:**

`make reproduce` must support two modes to handle the bootstrapping problem (Section 7.3.2 is empty until the first run completes):

1. **Capture mode** (before Section 7.3.2 is populated): Runs the full benchmark and writes results to `results/reproduction_$(date +%Y%m%d).json`. Prints a summary table to stdout. The operator manually reviews the results, and if correct, copies the summary values into Section 7.3.2. Triggered automatically when Section 7.3.2 is empty (detected by checking whether `docs/benchmark_methodology.md` contains the `> To be populated after the first complete live-AWS` marker above).

2. **Verify mode** (after Section 7.3.2 is populated): Runs the full benchmark, writes results to the same output path, then diffs the key metrics (per-tool TP/FP/FN counts and per-class recall values) against the expected values recorded in Section 7.3.2. Exits non-zero if any metric diverges beyond a tolerance of ±1 count (to allow for Terraform/IAM non-determinism on edge cases). This mode is exercised by artifact evaluators.

Both modes share the same pipeline; only the post-run validation step differs.

---

## 8. Limitations

1. **Live AWS account required.** Reproducing results requires access to an
   AWS account where IAMVulnerable can be deployed. Estimated cost for one full
   benchmark run is under $5 USD at AWS on-demand pricing for the IAM and
   lightweight compute resources IAMVulnerable creates.

2. **Tool version sensitivity.** All four tools change output formats and
   detection logic across versions. The `parse()` implementations in
   `internal/benchmark/` are valid only for the pinned versions listed in
   Section 3. Results on newer versions may differ without being wrong.

3. **Checkov methodological asymmetry.** Checkov is evaluated against
   Terraform source; all other tools are evaluated against the live deployed
   environment. The asymmetry is inherent to Checkov's design and is not corrected.
   The asymmetry means Checkov results are not directly comparable on the
   "same input" axis; they are comparable on the "same scenario" axis, which
   is the axis the paper uses.

4. **n = 31 limits statistical power.** See Section 6.1. Differences in recall
   below 0.2 within a single chain-length class should not be interpreted as
   meaningful without additional data.

5. **IAMVulnerable covers a curated subset of known escalation paths.** Datadog
   Security Labs documented 65 escalation paths in pathfinding.cloud (December
   2025), of which 42% were undetected by all evaluated open-source tools. The
   31 IAMVulnerable paths are a subset of the known landscape. AccessGraph's
   detection capability on paths not present in IAMVulnerable is not measured
   by this benchmark.

6. **PMapper requires live credentials and may time out on large accounts.**
   IAMVulnerable creates a relatively small IAM environment; PMapper should
   complete within 3 minutes per scenario. If the test account accumulates
   IAM resources between scenarios (e.g., due to failed teardown), PMapper
   runtime will increase. Section 2.3 step 6 is the mitigation.

7. **External tool false positive rate is not measured.** The dispatch logic
   for external tools (Prowler, PMapper, Checkov)
   classifies results as TP (detected) or FN (not detected) only. On true
   negative environments, `ExpectedAttackPath` is empty and `Parse()` always
   returns false, producing `LabelFN` regardless of actual tool output. Only
   AccessGraph's `classifyDetectionInternal()` distinguishes `LabelFP` from
   `LabelTN`. The `false_positive_rate` entries for external tools in benchmark
   JSON output are zeros representing unmeasured FPR, not confirmed zero FPR.
   Measuring external tool FPR would require `dispatch()` to inspect
   `IsTrueNegative` and reclassify detected/not-detected as FP/TN accordingly.

---

## Document version

Version: 1.0 (2026-03-20). Specification sections 3–5 and 8 are aligned
with the implementation in `internal/benchmark/`.
