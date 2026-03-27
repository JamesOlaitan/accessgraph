package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// ToolName identifies a security analysis tool in the benchmark comparison.
// String values are lowercase and match the --tools flag vocabulary.
type ToolName string

const (
	// ToolAccessGraph identifies this tool as the subject of evaluation.
	ToolAccessGraph ToolName = "accessgraph"

	// ToolProwler identifies the Prowler AWS security scanning tool.
	ToolProwler ToolName = "prowler"

	// ToolPMapper identifies the Principal Mapper (PMapper) tool.
	ToolPMapper ToolName = "pmapper"

	// ToolCheckov identifies the Checkov infrastructure-as-code scanner.
	ToolCheckov ToolName = "checkov"

	// ToolSteampipe identifies the Steampipe cloud query tool.
	ToolSteampipe ToolName = "steampipe"

	// ToolCloudSploit identifies the CloudSploit cloud security scanner.
	ToolCloudSploit ToolName = "cloudsploit"
)

// ChainLengthClass classifies an IAMVulnerable scenario by the number of
// permission hops required to reach the privilege-escalation target.
// The value is always copied from the scenario fixture ground-truth;
// it is NEVER derived from a runtime hop_count.
type ChainLengthClass string

const (
	// ClassSimple classifies a single-hop escalation scenario.
	ClassSimple ChainLengthClass = "simple"

	// ClassTwoHop classifies a two-hop escalation scenario.
	ClassTwoHop ChainLengthClass = "two_hop"

	// ClassMultiHop classifies a three-or-more-hop escalation scenario.
	ClassMultiHop ChainLengthClass = "multi_hop"

	// ClassNone is used exclusively for true-negative environments where no
	// escalation path is expected. It must never appear on a TP/FP/FN result.
	ClassNone ChainLengthClass = "none"
)

// ScenarioCategory classifies an IAMVulnerable scenario by the type of
// privilege-escalation mechanism it exercises.
type ScenarioCategory string

const (
	// CategoryDirectPolicy covers direct IAM policy manipulation.
	// Escalation via: iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion,
	// iam:AttachUserPolicy/GroupPolicy/RolePolicy, iam:PutUserPolicy/GroupPolicy/RolePolicy.
	CategoryDirectPolicy ScenarioCategory = "direct_policy"

	// CategoryCredentialManipulation covers user and credential manipulation.
	// Escalation via: iam:CreateAccessKey, iam:CreateLoginProfile,
	// iam:UpdateLoginProfile, iam:AddUserToGroup.
	CategoryCredentialManipulation ScenarioCategory = "credential_manipulation"

	// CategoryRoleTrust covers role trust manipulation.
	// Escalation via: iam:UpdateAssumeRolePolicy + sts:AssumeRole.
	CategoryRoleTrust ScenarioCategory = "role_trust"

	// CategoryPassRoleChain covers iam:PassRole combination scenarios.
	// Escalation via: iam:PassRole + ec2:RunInstances, lambda:CreateFunction,
	// cloudformation:CreateStack, datapipeline:CreatePipeline, etc.
	CategoryPassRoleChain ScenarioCategory = "passrole_chain"

	// CategoryServiceAbuse covers service abuse escalation.
	// Escalation via: lambda:UpdateFunctionCode, glue:UpdateDevEndpoint,
	// transitive multi-hop role assumption chains.
	CategoryServiceAbuse ScenarioCategory = "service_abuse"

	// CategoryNone is used exclusively for true-negative environments where no
	// escalation scenario category applies.
	CategoryNone ScenarioCategory = "none"
)

// DetectionLabel classifies one tool's detection outcome for one scenario.
// It replaces the three-boolean (TruePositive, FalsePositive, FalseNegative)
// pattern, which cannot represent TN or Timeout outcomes.
type DetectionLabel string

const (
	// LabelTP — tool correctly identified an expected attack path.
	LabelTP DetectionLabel = "TP"

	// LabelFP — tool reported a finding that does not match the expected path.
	LabelFP DetectionLabel = "FP"

	// LabelFN — tool failed to identify an expected attack path.
	LabelFN DetectionLabel = "FN"

	// LabelTN — tool correctly produced no finding for a true-negative scenario.
	LabelTN DetectionLabel = "TN"

	// LabelTimeout — tool exceeded the per-scenario wall-clock limit.
	// Timeout rows are excluded from the TP+FN denominator in recall computation
	// and are reported separately in the ClassMetrics.Timeouts field.
	LabelTimeout DetectionLabel = "TIMEOUT"
)

// TimeoutKind describes the reason a benchmark result was classified as a timeout.
type TimeoutKind string

const (
	// TimeoutNone indicates the result completed within the time limit.
	TimeoutNone TimeoutKind = "none"

	// TimeoutDeadline indicates the tool exceeded the per-scenario deadline.
	TimeoutDeadline TimeoutKind = "deadline"

	// TimeoutInfrastructure indicates the timeout was caused by infrastructure
	// issues unrelated to the tool itself (e.g., AWS API throttling).
	TimeoutInfrastructure TimeoutKind = "infrastructure"
)

// MetricFloat is a float64 that always marshals to exactly 6 decimal places in
// JSON output. All precision, recall, F1, and confidence-interval fields use
// this type to guarantee reproducible floating-point output across platforms.
type MetricFloat float64

// MarshalJSON implements json.Marshaler.
// It formats the value with exactly 6 decimal places.
func (m MetricFloat) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%.6f", float64(m))), nil
}

// ComputeResultID returns the deterministic content hash for a BenchmarkResult.
// The ID is sha256(json.Marshal([]any{runID, scenarioID, toolName})) truncated
// to 32 hex characters, matching the specification in findings_schema.md.
func ComputeResultID(runID, scenarioID string, toolName ToolName) string {
	key, _ := json.Marshal([]any{runID, scenarioID, string(toolName)})
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:16])
}

// Scenario represents one IAMVulnerable test case with a known expected attack path.
//
// Each scenario provides the ground truth against which tool detections are evaluated.
// ExpectedAttackPath encodes the canonical escalation chain as an ordered sequence
// of ARNs from the starting principal to the terminal admin-equivalent resource.
//
// Fields:
//   - ID: unique identifier (e.g., "iamvulnerable-scenario-01").
//   - Name: the IAMVulnerable scenario name as published.
//   - Source: origin of the scenario (always "iamvulnerable" for Phase 1).
//   - ChainLength: chain-length classification, always from the fixture ground-truth.
//   - ExpectedAttackPath: ordered ARNs from starting principal to terminal resource.
//   - StartingPrincipalARN: ARN of the BFS starting principal (first element of ExpectedAttackPath).
//   - ExpectedEscalationActions: IAM actions that drive the escalation (for TP validation).
//   - ExpectedPathNodes: internal node IDs of the expected path nodes (populated post-ingest).
//   - Description: narrative description of the vulnerability demonstrated.
//   - Category: IAMVulnerable escalation category for stratified analysis.
//   - ClassificationOverride: manual DetectionLabel override for ambiguous scenarios.
//   - IsTrueNegative: true if this scenario expects no escalation path (TN ground truth).
type Scenario struct {
	ID                        string           `json:"scenario_id"`
	Name                      string           `json:"name"`
	Source                    string           `json:"source"`
	ChainLength               ChainLengthClass `json:"chain_length_class"`
	ExpectedAttackPath        []string         `json:"expected_attack_path"`
	StartingPrincipalARN      string           `json:"starting_principal_arn"`
	ExpectedEscalationActions []string         `json:"expected_escalation_actions"`
	ExpectedPathNodes         []string         `json:"expected_path_nodes,omitempty"`
	Description               string           `json:"description"`
	Category                  ScenarioCategory `json:"category"`
	ClassificationOverride    DetectionLabel   `json:"classification_override,omitempty"`
	IsTrueNegative            bool             `json:"is_true_negative"`
}

// BenchmarkResult records one tool's detection outcome for one scenario in one run.
//
// All results within a single benchmark run share the same RunID (UUIDv4).
// ResultID is a deterministic content hash: sha256(json.Marshal([run_id, scenario_id, tool_name]))
// truncated to 32 hex characters, ensuring idempotent re-runs produce stable IDs.
//
// Fields:
//   - ID: primary key (UUIDv4 assigned at write time).
//   - RunID: UUIDv4 shared by all results in one benchmark invocation.
//   - ResultID: deterministic 32-char hex content hash.
//   - ScenarioID: the scenario this result evaluates.
//   - ToolName: the tool that produced this result.
//   - DetectionLabel: TP/FP/FN/TN/Timeout classification.
//   - TimeoutKind: reason for timeout; TimeoutNone when DetectionLabel != LabelTimeout.
//   - ClassificationOverride: non-empty when a human reviewer has overridden the auto-label.
//   - IsTrueNegative: true when this scenario was a TN ground-truth environment.
//   - DetectionLatencyMs: wall-clock time in milliseconds.
//   - ChainLengthClass: copied from the scenario fixture; never derived from runtime hop_count.
//   - RunAt: UTC timestamp of this result.
//   - RawStdout: captured stdout; nil when --include-raw was not passed.
//   - RawStderr: captured stderr; nil when --include-raw was not passed.
type BenchmarkResult struct {
	ID                     string           `json:"id"`
	RunID                  string           `json:"run_id"`
	ResultID               string           `json:"result_id"`
	ScenarioID             string           `json:"scenario_id"`
	ToolName               ToolName         `json:"tool_name"`
	DetectionLabel         DetectionLabel   `json:"detection_label"`
	TimeoutKind            TimeoutKind      `json:"timeout_kind"`
	ClassificationOverride DetectionLabel   `json:"classification_override,omitempty"`
	IsTrueNegative         bool             `json:"is_true_negative"`
	DetectionLatencyMs     int64            `json:"detection_latency_ms"`
	ChainLengthClass       ChainLengthClass `json:"chain_length_class"`
	Category               ScenarioCategory `json:"category"`
	RunAt                  time.Time        `json:"run_at"`
	RawStdout              *string          `json:"raw_stdout"`
	RawStderr              *string          `json:"raw_stderr"`
}

// Aggregation output types

// ClassMetrics holds precision, recall, F1 and Wilson-score 95% confidence
// intervals for one (tool, chain_length_class) cell in the aggregation table.
//
// Timeout rows are excluded from the TP+FN denominator for recall; they are
// counted separately in Timeouts and reported in the "timeouts" JSON field.
//
// Wilson-score CIs are clamped to [0, 1]. A panic is raised post-clamp if
// 0 <= Low <= PHat <= High <= 1 is violated, as this indicates a computation bug.
type ClassMetrics struct {
	TP         int         `json:"true_positives"`
	FN         int         `json:"false_negatives"`
	Timeouts   int         `json:"timeouts"`
	Recall     MetricFloat `json:"recall"`
	RecallLow  MetricFloat `json:"recall_ci95_low"`
	RecallHigh MetricFloat `json:"recall_ci95_high"`
}

// ToolMetrics aggregates ClassMetrics across all chain-length classes for a
// single tool, providing a tool-level precision/recall summary.
type ToolMetrics struct {
	TP                           int         `json:"true_positives"`
	FN                           int         `json:"false_negatives"`
	Timeouts                     int         `json:"timeouts"`
	Precision                    MetricFloat `json:"precision"`
	Recall                       MetricFloat `json:"recall"`
	F1                           MetricFloat `json:"f1"`
	PrecisionLow                 MetricFloat `json:"precision_ci95_low"`
	PrecisionHigh                MetricFloat `json:"precision_ci95_high"`
	RecallLow                    MetricFloat `json:"recall_ci95_low"`
	RecallHigh                   MetricFloat `json:"recall_ci95_high"`
	VulnerableScenariosEvaluated int         `json:"vulnerable_scenarios_evaluated"`
}

// FalsePositiveRate holds the FPR (FP / (FP + TN)) and its Wilson-score 95%
// confidence interval for one tool across all true-negative scenarios.
type FalsePositiveRate struct {
	FP         int         `json:"false_positives"`
	TN         int         `json:"true_negatives"`
	TNTimeouts int         `json:"tn_timeouts"`
	FPR        MetricFloat `json:"fpr"`
	FPRLow     MetricFloat `json:"fpr_ci95_low"`
	FPRHigh    MetricFloat `json:"fpr_ci95_high"`
}

// AggregationResult is the output of Aggregator.Aggregate.
//
// The JSON renderer flattens ByToolAndClass, ByTool, and FPRByTool as top-level
// keys — they are NOT nested under an "aggregation_result" wrapper object.
//
// Fields:
//   - RunID: the UUIDv4 that identifies the benchmark run that produced these results.
//   - GeneratedAt: UTC timestamp when aggregation was performed.
//   - ByToolAndClass: precision/recall metrics keyed by (tool, chain_length_class).
//   - ByTool: tool-level aggregate metrics keyed by tool.
//   - FPRByTool: false-positive rate keyed by tool (populated only when TN scenarios exist).
type AggregationResult struct {
	SchemaVersion       string                                          `json:"schema_version"`
	RunID               string                                          `json:"run_id"`
	GeneratedAt         time.Time                                       `json:"generated_at"`
	IAMVulnerableCommit string                                          `json:"iamvulnerable_commit"`
	Label               string                                          `json:"label"`
	ByToolAndClass      map[ToolName]map[ChainLengthClass]*ClassMetrics `json:"by_tool_and_class"`
	ByTool              map[ToolName]*ToolMetrics                       `json:"by_tool"`
	FPRByTool           map[ToolName]*FalsePositiveRate                 `json:"false_positive_rate"`
	Results             []*BenchmarkResult                              `json:"results"`
}
