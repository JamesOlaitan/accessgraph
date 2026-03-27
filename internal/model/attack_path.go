package model

import "time"

// AttackPath represents a BFS-discovered path from a compromised principal to a
// sensitive resource within a snapshot.
//
// Paths are discovered by the graph engine's BFS traversal. HopCount is the number
// of edges traversed on the shortest path to the target resource; longer alternative
// paths to the same resource may also be recorded.
//
// Fields:
//   - ID: unique identifier within the snapshot.
//   - SnapshotID: the snapshot this path was discovered in.
//   - FromPrincipalID: the ID of the starting compromised principal.
//   - ToResourceID: the ID of the sensitive resource reached.
//   - HopCount: the number of edges traversed (minimum path length for this entry).
//   - PathNodes: ordered list of node IDs from source to destination, inclusive.
//   - PathEdges: ordered list of edge IDs corresponding to each hop.
//   - IsPrivilegeEscalation: true if any edge on this path is a known escalation primitive.
//   - ChainLengthClass: hop-count classification (simple/two_hop/multi_hop) for stratified analysis.
type AttackPath struct {
	ID                    string           `json:"path_id"`
	SnapshotID            string           `json:"-"`
	FromPrincipalID       string           `json:"from_principal_id"`
	ToResourceID          string           `json:"to_resource_id"`
	HopCount              int              `json:"hop_count"`
	PathNodes             []string         `json:"path_nodes"`
	PathEdges             []string         `json:"path_edges"`
	IsPrivilegeEscalation bool             `json:"is_privilege_escalation"`
	ChainLengthClass      ChainLengthClass `json:"chain_length_class"`
}

// BlastRadiusReport summarizes how far an attacker can reach from a single
// compromised principal within a snapshot.
//
// This is the core research metric produced by AccessGraph. All numeric fields
// are computed by BlastRadiusAnalyzer from the output of a BFS traversal.
//
// Fields:
//   - PrincipalID: the starting compromised identity (ARN or ID).
//   - SnapshotID: the environment this was computed against.
//   - ReachableResourceCount: total sensitive resources reachable from this principal.
//   - PctEnvironmentReachable: ReachableResourceCount as a percentage of all resources in the snapshot.
//   - MinHopToAdmin: minimum BFS depth to an admin-equivalent resource; 0 if the principal is already admin.
//   - DistinctPathCount: number of distinct attack paths found across all reachable sensitive resources.
//   - Paths: all discovered attack paths, sorted by HopCount ascending.
type BlastRadiusReport struct {
	PrincipalID             string        `json:"principal_id"`
	SnapshotID              string        `json:"-"`
	ReachableResourceCount  int           `json:"reachable_resource_count"`
	PctEnvironmentReachable MetricFloat   `json:"pct_environment_reachable"`
	MinHopToAdmin           int           `json:"min_hop_to_admin"`
	DistinctPathCount       int           `json:"distinct_path_count"`
	Paths                   []*AttackPath `json:"paths"`
}

// Report is the composite output type assembled by the analyze command and passed
// to a Reporter for rendering.
//
// It is the single type that crosses the domain-service boundary into the I/O layer.
// The Reporter interface consumes Report exclusively; it never reads from the DataStore
// directly.
//
// Fields:
//   - Snapshot: the environment that was analyzed.
//   - BlastRadius: computed blast-radius metrics for the target principal.
//   - Findings: OPA rule violations discovered in the snapshot.
//   - GeneratedAt: UTC timestamp when the report was assembled.
//   - PolicyEvalSkipped: true when OPA evaluation failed and findings are absent;
//     the analysis result is still valid — only the policy-finding layer is degraded.
type Report struct {
	Snapshot          *Snapshot          `json:"snapshot,omitempty"`
	BlastRadius       *BlastRadiusReport `json:"blast_radius,omitempty"`
	Findings          []*Finding         `json:"findings"`
	PolicyEvalSkipped bool               `json:"policy_eval_skipped"`
	AggregationResult *AggregationResult `json:"-"`
	GeneratedAt       time.Time          `json:"generated_at"`
	SchemaVersion     string             `json:"schema_version"`
}
