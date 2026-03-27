// Package model defines the core domain types for AccessGraph.
//
// All types in this package are plain Go structs with no methods that encode
// business logic. They represent the schema documented in the architecture ER
// diagram and form the vocabulary shared across all internal packages.
//
// Dependency rule: model imports nothing from within this module. Every other
// internal package may import model; model imports none of them.
package model

import "time"

// PrincipalKind classifies an IAM principal by its type.
type PrincipalKind string

const (
	// PrincipalKindIAMUser represents an AWS IAM user principal.
	PrincipalKindIAMUser PrincipalKind = "IAMUser"

	// PrincipalKindIAMRole represents an AWS IAM role principal.
	PrincipalKindIAMRole PrincipalKind = "IAMRole"

	// PrincipalKindIAMGroup represents an AWS IAM group principal.
	PrincipalKindIAMGroup PrincipalKind = "IAMGroup"

	// PrincipalKindK8sServiceAccount represents a Kubernetes service account.
	PrincipalKindK8sServiceAccount PrincipalKind = "K8sServiceAccount"
)

// Snapshot is a point-in-time capture of an IAM environment.
//
// All other entities are scoped to a snapshot via their SnapshotID field.
// A snapshot is the unit of analysis: every graph construction, traversal, and
// report is associated with exactly one snapshot.
//
// Fields:
//   - ID: unique identifier, generated at ingest time.
//   - Label: human-readable name for display and lookup (e.g., "prod-2024-01").
//   - Provider: cloud provider identifier (currently only "aws").
//   - SourcePath: filesystem path of the source policy files at ingest time.
//   - CreatedAt: UTC timestamp when the snapshot was ingested.
//   - Principals: all IAM principals discovered in this environment.
//   - Policies: all IAM policies discovered in this environment.
//   - Resources: all resources discovered in this environment.
//   - Edges: all directed permission relationships between entities.
type Snapshot struct {
	ID         string       `json:"id"`
	Label      string       `json:"label"`
	Provider   string       `json:"provider"`
	SourcePath string       `json:"source_path,omitempty"`
	CreatedAt  time.Time    `json:"created_at"`
	Principals []*Principal `json:"principals,omitempty"`
	Policies   []*Policy    `json:"policies,omitempty"`
	Resources  []*Resource  `json:"resources,omitempty"`
	Edges      []*Edge      `json:"edges,omitempty"`
}

// Principal represents an IAM principal: a user, role, group, or service account.
//
// Fields:
//   - ID: unique identifier within the snapshot.
//   - SnapshotID: the snapshot this principal belongs to.
//   - Kind: the principal type (see PrincipalKind constants).
//   - ARN: the AWS ARN or Kubernetes qualified name.
//   - Name: short display name extracted from the ARN.
//   - AccountID: the AWS account ID that owns this principal.
//   - RawProps: additional provider-specific properties, stored as key-value strings.
type Principal struct {
	ID         string            `json:"id"`
	SnapshotID string            `json:"-"`
	Kind       PrincipalKind     `json:"kind"`
	ARN        string            `json:"arn"`
	Name       string            `json:"name"`
	AccountID  string            `json:"account_id"`
	RawProps   map[string]string `json:"raw_props,omitempty"`
}

// Policy represents an AWS IAM policy document.
//
// Fields:
//   - ID: unique identifier within the snapshot.
//   - SnapshotID: the snapshot this policy belongs to.
//   - ARN: the policy ARN; empty for inline policies.
//   - Name: the policy name (used when ARN is unavailable).
//   - IsInline: true if this is an inline policy, false for managed.
//   - JSONRaw: the raw JSON policy document as received from the source.
//   - Permissions: parsed permission statements extracted from JSONRaw.
type Policy struct {
	ID          string        `json:"id"`
	SnapshotID  string        `json:"-"`
	ARN         string        `json:"arn"`
	Name        string        `json:"name"`
	IsInline    bool          `json:"is_inline"`
	JSONRaw     string        `json:"json_raw,omitempty"`
	Permissions []*Permission `json:"permissions,omitempty"`
}

// Permission represents a single (action, resource, effect) triple within a policy.
//
// Fields:
//   - ID: unique identifier within the snapshot.
//   - PolicyID: the policy this permission belongs to.
//   - Action: the IAM action pattern (e.g., "s3:GetObject", "iam:*").
//   - ResourcePattern: the resource ARN pattern this permission applies to.
//   - Effect: either "Allow" or "Deny"; Deny always overrides Allow.
//   - Conditions: key-value condition constraints from the policy statement.
type Permission struct {
	ID              string            `json:"id"`
	PolicyID        string            `json:"policy_id"`
	Action          string            `json:"action"`
	ResourcePattern string            `json:"resource_pattern"`
	Effect          string            `json:"effect"`
	Conditions      map[string]string `json:"conditions,omitempty"`
}

// Resource represents an AWS resource reachable through IAM permissions.
//
// Fields:
//   - ID: unique identifier within the snapshot.
//   - SnapshotID: the snapshot this resource belongs to.
//   - ARN: the resource ARN.
//   - Kind: the service type (e.g., "S3Bucket", "LambdaFunction", "IAMRole").
//   - IsSensitive: true if OPA sensitivity rules classify this as a high-value target.
type Resource struct {
	ID          string `json:"id"`
	SnapshotID  string `json:"-"`
	ARN         string `json:"arn"`
	Kind        string `json:"kind"`
	IsSensitive bool   `json:"is_sensitive"`
}
