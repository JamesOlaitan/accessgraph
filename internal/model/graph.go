package model

// EdgeKind classifies the type of directed relationship between two graph nodes.
// It is the complete vocabulary of the permission graph; every edge must carry
// exactly one of these kinds.
type EdgeKind string

const (
	// EdgeKindAttachedPolicy connects a Principal to a managed Policy it has attached.
	EdgeKindAttachedPolicy EdgeKind = "ATTACHED_POLICY"

	// EdgeKindInlinePolicy connects a Principal to an inline Policy it owns.
	EdgeKindInlinePolicy EdgeKind = "INLINE_POLICY"

	// EdgeKindAssumesRole connects a Principal to another Principal whose role it can assume.
	// This edge exists when the target role's trust policy allows the source principal.
	EdgeKindAssumesRole EdgeKind = "ASSUMES_ROLE"

	// EdgeKindTrustsCrossAccount connects a Principal to a cross-account trust relationship.
	// The target represents an external account principal.
	EdgeKindTrustsCrossAccount EdgeKind = "TRUSTS_CROSS_ACCOUNT"

	// EdgeKindAllowsAction connects a Policy to a Permission it grants.
	EdgeKindAllowsAction EdgeKind = "ALLOWS_ACTION"

	// EdgeKindAppliesTo connects a Permission to the Resource it targets.
	EdgeKindAppliesTo EdgeKind = "APPLIES_TO"

	// EdgeKindMemberOf connects a Principal (IAM User) to its containing Group.
	EdgeKindMemberOf EdgeKind = "MEMBER_OF"

	// EdgeKindCanPassRole connects a Principal to another Principal via iam:PassRole.
	// This edge is synthesized during escalation analysis; it does not appear in raw policy JSON.
	EdgeKindCanPassRole EdgeKind = "CAN_PASS_ROLE"

	// EdgeKindCanCreateKey connects a Principal to another Principal via iam:CreateAccessKey.
	// This edge is synthesized during escalation analysis.
	EdgeKindCanCreateKey EdgeKind = "CAN_CREATE_KEY"
)

// Node represents a vertex in the permission graph.
//
// A node can be a Principal, Policy, Permission, or Resource. The ID field
// matches the ID of the underlying domain entity so callers can look up the
// full entity from the snapshot after graph traversal.
//
// Fields:
//   - ID: unique identifier; matches the ID of the corresponding domain entity.
//   - Kind: the node type, used for display and classification (e.g., "IAMRole").
//   - Label: human-readable display name (ARN, policy name, or action pattern).
type Node struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

// Edge represents a directed relationship between two nodes in the permission graph.
//
// Fields:
//   - ID: unique identifier within the snapshot.
//   - SnapshotID: the snapshot this edge belongs to.
//   - FromNodeID: the source node ID.
//   - ToNodeID: the destination node ID.
//   - Kind: the type of relationship (see EdgeKind constants).
//   - Weight: edge weight for shortest-path computation; defaults to 1.
//   - Metadata: additional edge-specific properties (e.g., condition keys).
type Edge struct {
	ID         string            `json:"id"`
	SnapshotID string            `json:"-"`
	FromNodeID string            `json:"from_node_id"`
	ToNodeID   string            `json:"to_node_id"`
	Kind       EdgeKind          `json:"kind"`
	Weight     int               `json:"weight"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}
