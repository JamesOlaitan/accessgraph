# Findings Schema

This document specifies the JSON output schema for all AccessGraph report types.
It is referenced by the artifact appendix and governs downstream tooling that
consumes AccessGraph output.

All timestamps are RFC 3339 UTC. All ARNs are full AWS ARN strings unless noted
otherwise. All float fields are serialized with exactly six decimal places using
`fmt.Sprintf("%.6f", v)` via a custom `MetricFloat` marshaler (e.g., `1.000000`,
`0.909091`, `0.000000`). Go's default `json.Marshal` for float64 uses minimal
representation, which would produce `1` instead of `1.000000` and violate the
byte-identical JSON contract across implementations. Wilson score confidence interval (CI) bounds are clamped to [0, 1] before rounding: set `low = max(0.0, low)` and `high = min(1.0, high)`, then round each to six decimal places. After clamping and rounding, the invariant `0 <= low <= p_hat <= high <= 1`
must hold; a violation indicates a formula bug and must panic.

---

## 1. Analysis report (`accessgraph analyze`)

Produced by `accessgraph analyze --output json`. Contains blast radius metrics,
attack paths, and Open Policy Agent (OPA) findings for a single principal in a single snapshot.

```json
{
  "schema_version": "1.0.0",
  "snapshot_id": "snap-123456789012-1700000000000000000",
  "label": "staging-2024-11",
  "generated_at": "2024-11-15T14:23:00Z",
  "policy_eval_skipped": false,
  "blast_radius": { ... },
  "findings": [ ... ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Schema version in semver format; always `"1.0.0"` for this release. Consumers must reject reports whose major version does not match. |
| `snapshot_id` | string | Unique snapshot identifier |
| `label` | string | Human-readable label assigned at ingest time |
| `generated_at` | string (RFC3339) | UTC timestamp of report generation |
| `policy_eval_skipped` | boolean | `true` when OPA was unreachable; `findings` will be empty |
| `blast_radius` | object | Blast-radius metrics for the queried principal |
| `findings` | array | OPA policy findings; empty array when `policy_eval_skipped` is true |

### 1.1 `blast_radius` object

```json
{
  "principal_id": "arn:aws:iam::123456789012:user/dev-user",
  "reachable_resource_count": 3,
  "pct_environment_reachable": 27.300000,
  "min_hop_to_admin": 2,
  "distinct_path_count": 5,
  "paths": [ ... ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `principal_id` | string | Full ARN of the compromised starting principal |
| `reachable_resource_count` | integer | Sensitive resources reachable via breadth-first search (BFS) from this principal |
| `pct_environment_reachable` | float | Reachable resources / total resources in snapshot × 100 |
| `min_hop_to_admin` | integer | Minimum hop count to an admin-equivalent resource; `-1` if no path exists. **Admin-equivalence definition (authoritative):** A resource is admin-equivalent if it has `arn:aws:iam::aws:policy/AdministratorAccess` attached, or any inline or managed policy granting `iam:*` on `*`, or `*:*` (equivalently bare `"Action": "*"`) on `*`. This is the single canonical definition for the project; `ARCHITECTURE.md §6` and `benchmark_methodology.md` cross-reference this field rather than restating the definition. `ARCHITECTURE.md §6` also describes how admin-equivalent policies are modeled as Resource nodes in the permission graph, which is the mechanism by which the matcher in `classifyDetectionInternal` treats them as terminal targets of attack paths. |
| `distinct_path_count` | integer | Total distinct attack paths discovered |
| `paths` | array | Attack path objects sorted by `hop_count` ascending, then by `path_id` ascending (lexicographic) as a tiebreaker (see Section 1.2) |

### 1.2 Attack path object

```json
{
  "path_id": "path-a3f8c1d2e4b5f6a7b8c9d0e1f2a3b4c5",
  "from_principal_id": "arn:aws:iam::123456789012:user/dev-user",
  "to_resource_id": "arn:aws:iam::123456789012:role/AdminRole",
  "hop_count": 2,
  "chain_length_class": "two_hop",
  "is_privilege_escalation": true,
  "path_nodes": [
    "arn:aws:iam::123456789012:user/dev-user",
    "arn:aws:iam::123456789012:role/DataRole",
    "arn:aws:iam::123456789012:role/AdminRole"
  ],
  "path_edges": [
    "edge-a1b2c3d4e5f6",
    "edge-b2c3d4e5f6a1"
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `path_id` | string | `"path-"` prefix followed by SHA-256 (truncated to 32 hex chars) of `json.Marshal([]any{from_principal_id, to_resource_id, hop_count, path_nodes})`. Structured serialization prevents field-boundary collisions that bare string concatenation would allow. |
| `from_principal_id` | string | Full ARN of the starting compromised principal |
| `to_resource_id` | string | Full ARN of the destination sensitive resource |
| `hop_count` | integer | Number of edges on this path |
| `chain_length_class` | string | `simple`, `two_hop`, or `multi_hop` derived from `hop_count` |
| `is_privilege_escalation` | boolean | `true` if any edge on the path is a known escalation primitive |
| `path_nodes` | array of string | Ordered full ARNs from source to destination, inclusive |
| `path_edges` | array of string | Edge IDs corresponding to each hop; length is always `hop_count` |

`chain_length_class` derivation:

| Value | Condition |
|-------|-----------|
| `simple` | `hop_count <= 1` (a principal that already holds admin-equivalent access has hop_count 0) |
| `two_hop` | `hop_count == 2` |
| `multi_hop` | `hop_count >= 3` |

### 1.3 Finding object

```json
{
  "finding_id": "c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
  "snapshot_id": "snap-123456789012-1700000000000000000",
  "rule_id": "IAM.WildcardAction",
  "severity": "HIGH",
  "entity_ref": "arn:aws:iam::123456789012:policy/DeveloperPolicy",
  "reason": "Policy 'DeveloperPolicy' grants wildcard action 's3:*' on resource '*'.",
  "remediation": "Replace the wildcard action with the specific IAM actions required by each workload."
}
```

| Field | Type | Allowed values / format |
|-------|------|------------------------|
| `finding_id` | string | SHA-256 (truncated to 32 hex chars) of `json.Marshal([]any{snapshot_id, rule_id, entity_ref})`. Structured serialization prevents field-boundary collisions. |
| `snapshot_id` | string | Snapshot this finding was generated against |
| `rule_id` | string | See rule catalog (Section 1.4) |
| `severity` | string | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `entity_ref` | string | Full ARN of the violating entity |
| `reason` | string | Human-readable violation explanation |
| `remediation` | string | Corrective action |

### 1.4 Rule catalog

| Rule ID | Severity | Trigger |
|---------|----------|---------|
| `IAM.WildcardAction` | MEDIUM / HIGH / CRITICAL | A policy grants a wildcard service action (e.g., `s3:*`). Severity scales with action scope: service-scoped wildcards are MEDIUM; IAM wildcards are CRITICAL. |
| `IAM.CrossAccountTrust` | HIGH | A role trust policy allows assumption from a principal in a different account |
| `IAM.OpenTrustPolicy` | CRITICAL | A role trust policy allows `Principal: "*"` without a condition |
| `IAM.PassRoleEscalation` | HIGH | A principal holds `iam:PassRole` without resource constraints |
| `IAM.CreateAccessKeyEscalation` | HIGH | A principal holds `iam:CreateAccessKey` on other users |
| `IAM.CreateAndAttachRole` | CRITICAL | A principal holds both `iam:CreateRole` and `iam:AttachRolePolicy` |
| `IAM.AdminPolicyAttached` | CRITICAL | A principal has `AdministratorAccess` or an equivalent wildcard policy attached |
| `IAM.SensitiveResourceExposed` | HIGH | A sensitive resource is reachable from a non-admin principal |
| `IAM.MissingPermissionBoundary` | MEDIUM | A role with high-privilege policies has no permission boundary set |

---

## 2. Benchmark comparison report (`accessgraph benchmark`)

Produced by `accessgraph benchmark --output json`. Contains per-scenario results;
per-(tool, chain_length_class) recall and confidence intervals; per-tool precision,
recall, F1, and confidence intervals; and per-tool false positive rate.

```json
{
  "schema_version": "1.0.0",
  "run_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "label": "run-20241115-142300",
  "iamvulnerable_commit": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
  "generated_at": "2024-11-15T14:23:00Z",
  "results": [ ... ],
  "by_tool_and_class": { ... },
  "by_tool": { ... },
  "false_positive_rate": { ... }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Schema version in semver format; always `"1.0.0"` for this release. Consumers must reject reports whose major version does not match. |
| `run_id` | string | Canonical identifier for this benchmark run; a UUIDv4 generated at run start. Used as the database primary key and in `result_id` hashing. |
| `label` | string | Human-readable timestamp label `run-YYYYMMDD-HHMMSS` for display purposes only. The label is not used as a key; two runs within the same second would produce identical labels. |
| `iamvulnerable_commit` | string | Exact git SHA of the IAMVulnerable repository used for this run |
| `generated_at` | string (RFC3339) | UTC timestamp of report generation |
| `results` | array | Individual `BenchmarkResult` objects sorted by `scenario_id` ascending (lexicographic), then by `tool_name` ascending (lexicographic) as a tiebreaker (see Section 2.1). This ordering is mandatory for byte-identical output. |
| `by_tool_and_class` | object | Primary research table: recall per (tool, class) pair (see Section 2.2) |
| `by_tool` | object | Aggregated metrics per tool across all chain-length classes (see Section 2.3) |
| `false_positive_rate` | object | False positive rate (FPR) per tool computed from true negative environments (see Section 2.4) |

### 2.1 `BenchmarkResult` object

One object per (tool, scenario) pair. Each `BenchmarkResult` object is the raw data from which all
aggregated tables are derived.

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "result_id": "d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
  "run_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "scenario_id": "privesc1-CreateNewPolicyVersion",
  "tool_name": "pmapper",
  "detection_label": "TP",
  "timeout_kind": "none",
  "detection_latency_ms": 4821,
  "chain_length_class": "simple",
  "classification_override": "",
  "is_true_negative": false,
  "category": "direct_policy",
  "raw_stdout": "<base64-encoded bytes>",
  "raw_stderr": "<base64-encoded bytes>",
  "run_at": "2024-11-15T14:25:44Z"
}
```

| Field | Type | Allowed values / format |
|-------|------|------------------------|
| `id` | string | UUIDv4 primary key assigned at write time. |
| `result_id` | string | SHA-256 (truncated to 32 hex chars) of `json.Marshal([]any{run_id, scenario_id, tool_name})`. Structured serialization prevents field-boundary collisions. |
| `run_id` | string | UUIDv4 FK to the enclosing benchmark run. Matches `run_id` in the top-level benchmark report object. |
| `scenario_id` | string | Canonical scenario identifier. For vulnerable scenarios: the full Terraform directory name (e.g., `privesc1-CreateNewPolicyVersion`). For true negative environments: `tn-clean-NNN` (e.g., `tn-clean-001`). See `benchmark_methodology.md §4.2` for the authoritative identity table. |
| `tool_name` | string | `accessgraph`, `prowler`, `pmapper`, `checkov` |
| `detection_label` | string | `TP`, `FP`, `FN`, `TN`, or `TIMEOUT` — exactly one per result |
| `timeout_kind` | string | `none`, `deadline`, or `infrastructure`. Always `none` when `detection_label` is not `TIMEOUT`. When `TIMEOUT`: `deadline` means the tool did not exit within the 5-minute per-scenario deadline (subprocess was killed); `infrastructure` means the tool exited non-zero due to an environmental failure classified by the adapter per the per-tool exit code table in ARCHITECTURE.md §11 (External Tool Invocation Contract). Both kinds are excluded from precision/recall identically; the distinction is preserved for post-hoc analysis and rerun decisions. |
| `detection_latency_ms` | integer | Wall-clock milliseconds from tool invocation start to completion. For external tools: from `exec.Command.Start()` to process exit or kill, plus file-read time for Prowler. For AccessGraph: from `parser.ParseAWSIAM()` start to `analyzer.Analyze()` completion. This value is not comparable across tools; see `benchmark_methodology.md §3` for the cross-tool latency caveat. |
| `chain_length_class` | string | `simple`, `two_hop`, `multi_hop`, or `none`. In `BenchmarkResult`, always copied from the scenario fixture ground-truth — never derived from `hop_count` at runtime. The value `none` is used exclusively for true negative environments (`is_true_negative == true`); the aggregator must skip `none` rows when computing per-class recall. The hop-count derivation rule applies only to `AttackPath` objects in the analysis report (Section 1.2). |
| `classification_override` | string (DetectionLabel) | Non-empty when a human reviewer has overridden the auto-assigned detection label. Contains the overriding `DetectionLabel` value (`TP`, `FP`, `FN`, `TN`, or `TIMEOUT`). Empty string (omitted from JSON via `omitempty`) when no override exists. |
| `is_true_negative` | boolean | `true` when this result is from a true negative (clean) environment, `false` for vulnerable scenarios. Copied from the scenario fixture. Enables consumers to determine scenario type without cross-referencing fixture data — especially useful for `TIMEOUT` results where `detection_label` alone is ambiguous. |
| `category` | string | IAMVulnerable category: `direct_policy`, `credential_manipulation`, `role_trust`, `passrole_chain`, `service_abuse`, or `none`. The value `none` is used exclusively for true negative environments (`is_true_negative == true`). |
| `raw_stdout` | string \| null | Base64-encoded raw stdout from the tool invocation. `null` when `--include-raw` is not passed; never omitted entirely from the JSON object. |
| `raw_stderr` | string \| null | Base64-encoded raw stderr from the tool invocation. `null` when `--include-raw` is not passed; never omitted entirely from the JSON object. |
| `run_at` | string (RFC3339) | UTC timestamp when this specific invocation completed |

`detection_label` is a mutually exclusive enum. Three independent booleans
(`true_positive`, `false_positive`, `false_negative`) allow logically invalid
states. A single typed label does not. Valid state transitions:

| Label | Meaning |
|-------|---------|
| `TP` | True positive: tool correctly identified the expected escalation path |
| `FP` | False positive: tool produced an escalation finding on a true negative environment |
| `FN` | False negative: tool failed to identify the expected escalation path |
| `TN` | True negative: tool correctly produced no finding on a true negative environment |
| `TIMEOUT` | Tool did not exit within the 5-minute deadline. Excluded from TP/FN counts and the recall denominator. Reported separately in the `timeouts` field of `ClassMetrics`. |

`raw_stdout` and `raw_stderr` are always present as JSON fields, including for `TIMEOUT` results (capturing whatever partial output was produced before the process was killed). Their value is `null` when `--include-raw` is not passed and base64-encoded bytes when it is. They are never written to terminal output.

### 2.2 `by_tool_and_class` object

The `by_tool_and_class` object is the primary research table, keyed by `tool_name`, then by `chain_length_class`.
The table provides the two-dimensional breakdown required to show how detection
recall varies by chain-length class across tools with different architectures.

```json
{
  "by_tool_and_class": {
    "accessgraph": {
      "simple": {
        "true_positives": 11,
        "false_negatives": 0,
        "timeouts": 0,
        "recall": 1.000000,
        "recall_ci95_low": 0.715221,
        "recall_ci95_high": 1.000000
      },
      "two_hop": { ... },
      "multi_hop": { ... }
    },
    "pmapper": { ... },
    "prowler": { ... },
    "checkov": { ... }
  }
}
```

Each leaf object is a `ClassMetrics` object:

| Field | Type | Description |
|-------|------|-------------|
| `true_positives` | integer | Scenarios in this class where the tool produced a TP |
| `false_negatives` | integer | Scenarios in this class where the tool produced a FN |
| `timeouts` | integer | Scenarios in this class where the tool timed out; excluded from TP/FN counts and the recall denominator |
| `recall` | float | TP / (TP + FN) |
| `recall_ci95_low` | float | Lower bound of Wilson score 95% confidence interval for recall |
| `recall_ci95_high` | float | Upper bound of Wilson score 95% confidence interval for recall |

Per-class precision and per-class F1 are not reported here. FP is computed from true negative environments, which are not class-scoped; combining a class-scoped TP numerator with a tool-level FP denominator produces a metric without a clean frequentist interpretation. The same reasoning applies to F1: per-class F1 would require per-class precision, which does not exist. Both precision and F1 are reported at the tool level only in `by_tool` (Section 2.3), where all denominators are coherent tool-level values.

### 2.3 `by_tool` object

The `by_tool` object contains aggregated metrics per tool across all chain-length classes. It is derived from
`by_tool_and_class` and included for convenience.

```json
/* illustrative values only — not expected results; shown for schema structure */
{
  "by_tool": {
    "accessgraph": {
      "true_positives": 29,
      "false_negatives": 0,
      "timeouts": 2,
      "vulnerable_scenarios_evaluated": 31,
      "precision": 1.000000,
      "precision_ci95_low": 0.879385,
      "precision_ci95_high": 1.000000,
      "recall": 1.000000,
      "recall_ci95_low": 0.879385,
      "recall_ci95_high": 1.000000,
      "f1": 1.000000
    },
    "pmapper": { ... },
    "prowler": { ... },
    "checkov": { ... }
  }
}
```

Additional fields at the tool level:

| Field | Type | Description |
|-------|------|-------------|
| `vulnerable_scenarios_evaluated` | integer | Count of vulnerable scenarios (not TN environments) run for this tool. The invariant `true_positives + false_negatives + timeouts == vulnerable_scenarios_evaluated` holds for each tool, where all three values are summed across chain-length classes. |

### 2.4 `false_positive_rate` object

The `false_positive_rate` object contains FPR computed from true negative environments, keyed by `tool_name`.

```json
/* illustrative values only — do not treat as expected results */
{
  "false_positive_rate": {
    "accessgraph":  { "false_positives": 0, "true_negatives": 10, "tn_timeouts": 0, "fpr": 0.000000, "fpr_ci95_low": 0.000000, "fpr_ci95_high": 0.308677, "fpr_measured": true }
  }
}
```

Only tools that were actually evaluated against true-negative environments (i.e., produced `LabelFP` or `LabelTN` results on TN scenarios) appear in this object. Currently only AccessGraph meets this criterion. External tools whose `dispatch()` path returns `LabelFN` unconditionally on TN environments do not appear here; their FPR is not measured by this benchmark.

| Field | Type | Description |
|-------|------|-------------|
| `false_positives` | integer | True negative environments where the tool produced a finding |
| `true_negatives` | integer | True negative environments where the tool produced no finding |
| `tn_timeouts` | integer | True negative environments where the tool timed out; excluded from the FP+TN denominator. `false_positives + true_negatives + tn_timeouts` equals the total TN environments evaluated. |
| `fpr` | float | `false_positives / (false_positives + true_negatives)` |
| `fpr_ci95_low` | float | Lower bound of Wilson score 95% confidence interval for FPR |
| `fpr_ci95_high` | float | Upper bound of Wilson score 95% confidence interval for FPR |
| `fpr_measured` | boolean | `true` when the tool was actually evaluated against true-negative environments and produced `LabelFP` or `LabelTN` results. `false` (or absent) means the FPR value represents an unmeasured default, not a confirmed measurement. An `fpr_measured: false` entry with `fpr: 0.000000` means "not measured," not "confirmed zero FPR." |

---

## 3. Schema invariants

The following invariants hold for any valid AccessGraph JSON output. Consumers may
assert these invariants as validation rules.

**Analysis report**

- `findings` is an empty array (not null) when `policy_eval_skipped` is `true`
- `blast_radius.min_hop_to_admin` is `-1` if and only if no path in `paths`
  reaches an admin-equivalent resource
- `blast_radius.distinct_path_count` equals `len(blast_radius.paths)`. All discovered paths are included in the `paths` array regardless of severity — no client-side filtering is applied by the renderer. `distinct_path_count` therefore always equals `len(paths)` without exception.
- All `path_nodes` arrays have length `hop_count + 1`
- All `path_edges` arrays have length `hop_count`
- `from_principal_id` in every path matches `blast_radius.principal_id`
- All `path_id` values within a report are unique
- All `finding_id` values within a report are unique

**Benchmark comparison report**

- `len(results)` equals (number of tools) × (number of scenarios evaluated),
  plus (number of tools) × (number of true negative environments)
- `detection_label` for results against true negative environments is `FP`, `TN`, or `TIMEOUT`; never `TP` or `FN`
- `detection_label` for results against vulnerable scenarios is `TP`, `FN`, or `TIMEOUT`; never `FP` or `TN`
- **Determining scenario type:** The `is_true_negative` field on each `BenchmarkResult` directly indicates whether the result came from a true negative environment (`true`) or a vulnerable scenario (`false`). The `is_true_negative` field is the authoritative way to determine scenario type, including for `TIMEOUT` results where `detection_label` alone is ambiguous. The detection_label invariants still hold: `FP` or `TN` labels occur only when `is_true_negative` is `true`; `TP` or `FN` labels occur only when `is_true_negative` is `false`.
- **TN field values:** Results where `is_true_negative == true` always have `chain_length_class == "none"` and `category == "none"`. Results where `is_true_negative == false` never have `chain_length_class == "none"` or `category == "none"`.
- `TIMEOUT` is valid for any scenario type (vulnerable or true negative); it is excluded from all precision, recall, and FPR denominators and reported separately in the `timeouts` field of `ClassMetrics`
- `by_tool[tool].true_positives` equals the count of `results` where
  `tool_name == tool` and `detection_label == "TP"`
- Sum of `true_positives + false_negatives + timeouts` across all classes for
  a given tool equals `by_tool[tool].vulnerable_scenarios_evaluated`
- **Per-class count invariant:** For each tool and each class in `{simple, two_hop, multi_hop}`: `by_tool_and_class[tool][class].true_positives + by_tool_and_class[tool][class].false_negatives + by_tool_and_class[tool][class].timeouts` equals the number of vulnerable scenarios in that class (11 for `simple`, 2 for `two_hop`, 18 for `multi_hop` at the pinned commit). The class `none` never appears in `by_tool_and_class`.
- `iamvulnerable_commit` is a 40-character lowercase hexadecimal string
- `raw_stdout` and `raw_stderr` are present in every `BenchmarkResult` object; their value is `null` when `--include-raw` was not passed and a base64 string when it was
- `schema_version` is present in every report (both analysis and benchmark); consumers must reject reports whose major version does not match the version they were built against
- **Float format invariant:** All float fields in `by_tool_and_class`, `by_tool`, and `false_positive_rate` are serialized with exactly six decimal places (e.g., `1.000000`, not `1` or `1.0`). See preamble for the `MetricFloat` serialization contract.

---

## 4. Versioning

This schema is versioned alongside the AccessGraph codebase. Breaking changes
to field names, types, or required fields increment the major version. Additive
changes (new optional fields) increment the minor version.

The current schema version is embedded in every report as:

```json
{
  "schema_version": "1.0.0",
  ...
}
```

Consumers must reject reports whose `schema_version` major version does not
match the version they were written against.
