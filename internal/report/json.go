package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// jsonReport is the JSON-serializable mirror of model.Report.
//
// It is a separate type so that the encoding can be tuned independently of
// the domain model without coupling the model package to encoding concerns.
type jsonReport struct {
	// SchemaVersion is the schema version of this report format.
	SchemaVersion string `json:"schema_version"`

	// SnapshotID is the unique identifier of the analyzed snapshot.
	SnapshotID string `json:"snapshot_id"`

	// Label is the human-readable snapshot name.
	Label string `json:"label"`

	// GeneratedAt is the UTC timestamp when the report was assembled.
	GeneratedAt time.Time `json:"generated_at"`

	// PolicyEvalSkipped is true when OPA evaluation failed and findings are absent.
	PolicyEvalSkipped bool `json:"policy_eval_skipped"`

	// BlastRadius contains the computed reachability metrics.
	BlastRadius jsonBlastRadius `json:"blast_radius"`

	// Findings lists all OPA rule violations discovered in the snapshot.
	Findings []jsonFinding `json:"findings"`
}

// jsonBlastRadius is the JSON-serializable mirror of model.BlastRadiusReport.
type jsonBlastRadius struct {
	// PrincipalID is the ARN or ID of the compromised starting principal.
	PrincipalID string `json:"principal_id"`

	// ReachableResourceCount is the total number of sensitive resources reachable.
	ReachableResourceCount int `json:"reachable_resource_count"`

	// PctEnvironmentReachable is the percentage of all resources that are reachable.
	PctEnvironmentReachable model.MetricFloat `json:"pct_environment_reachable"`

	// MinHopToAdmin is the minimum BFS depth to an admin-equivalent resource.
	// A value of -1 indicates that no admin resource is reachable.
	MinHopToAdmin int `json:"min_hop_to_admin"`

	// DistinctPathCount is the number of distinct attack paths found.
	DistinctPathCount int `json:"distinct_path_count"`

	// Paths is the list of discovered attack paths.
	Paths []jsonAttackPath `json:"paths"`
}

// jsonAttackPath is the JSON-serializable mirror of model.AttackPath.
type jsonAttackPath struct {
	// ID is the unique path identifier within the snapshot.
	ID string `json:"path_id"`

	// FromPrincipalID is the ID of the starting compromised principal.
	FromPrincipalID string `json:"from_principal_id"`

	// ToResourceID is the ID of the sensitive resource reached.
	ToResourceID string `json:"to_resource_id"`

	// HopCount is the number of edges traversed on the shortest path.
	HopCount int `json:"hop_count"`

	// PathNodes is the ordered list of node IDs from source to destination.
	PathNodes []string `json:"path_nodes"`

	// PathEdges is the ordered list of edge IDs corresponding to each hop.
	PathEdges []string `json:"path_edges"`

	// IsPrivilegeEscalation is true if any edge on this path is a known
	// escalation primitive.
	IsPrivilegeEscalation bool `json:"is_privilege_escalation"`

	// ChainLengthClass classifies the path by hop count.
	ChainLengthClass model.ChainLengthClass `json:"chain_length_class"`
}

// jsonFinding is the JSON-serializable mirror of model.Finding.
type jsonFinding struct {
	// ID is the unique finding identifier within the snapshot.
	ID string `json:"finding_id"`

	// SnapshotID is the snapshot this finding belongs to.
	SnapshotID string `json:"snapshot_id"`

	// RuleID is the OPA rule that generated this finding.
	RuleID string `json:"rule_id"`

	// Severity is the risk classification string (e.g., "HIGH", "CRITICAL").
	Severity string `json:"severity"`

	// EntityRef is the ARN or ID of the entity in violation.
	EntityRef string `json:"entity_ref"`

	// Reason is a human-readable explanation of why this is a violation.
	Reason string `json:"reason"`

	// Remediation is a suggested corrective action.
	Remediation string `json:"remediation"`
}

// RenderJSON writes the report as structured, indented JSON to w.
//
// The output uses two-space indentation. The report is first converted from
// model types into JSON-specific mirror types so that encoding decisions are
// decoupled from the domain model.
//
// Parameters:
//   - w: destination writer; must not be nil.
//   - report: the analysis report to render; must not be nil.
//
// Returns ErrRenderFailed (wrapped) on encoding or I/O error.
func (r *DefaultReporter) RenderJSON(w io.Writer, report *model.Report) error {
	jr, err := toJSONReport(report)
	if err != nil {
		return fmt.Errorf("%w: building JSON structure: %v", ErrRenderFailed, err)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if encErr := enc.Encode(jr); encErr != nil {
		return fmt.Errorf("%w: encoding JSON: %v", ErrRenderFailed, encErr)
	}
	return nil
}

// RenderComparisonReport serialises the benchmark ComparisonReport as indented
// JSON to w.
//
// The method is named RenderComparisonReport to satisfy the Reporter interface,
// which expresses a logical operation (render the comparison table) without
// prescribing an output format. This JSON implementation is selected when the
// caller requests --output json; the terminal implementation in terminal.go
// renders the same data as a plain-text tabwriter table.
//
// Parameters:
//   - w: destination writer; must not be nil.
//   - cr: the comparison report to render; must not be nil.
//
// Returns ErrRenderFailed (wrapped) on any I/O error.
func (r *DefaultReporter) RenderAggregationResult(w io.Writer, ar *model.AggregationResult) error {
	if ar == nil {
		return fmt.Errorf("%w: nil AggregationResult", ErrRenderFailed)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(ar); err != nil {
		return fmt.Errorf("%w: encoding aggregation result: %v", ErrRenderFailed, err)
	}
	return nil
}

// toJSONReport converts a *model.Report into the JSON-serializable jsonReport
// mirror type.
//
// Parameters:
//   - report: the source report; must not be nil.
//
// Returns a populated jsonReport.
//
// Errors: returns a non-nil error only if report is nil.
func toJSONReport(report *model.Report) (jsonReport, error) {
	if report == nil {
		return jsonReport{}, fmt.Errorf("nil report")
	}

	jr := jsonReport{
		SchemaVersion:     report.SchemaVersion,
		PolicyEvalSkipped: report.PolicyEvalSkipped,
		GeneratedAt:       report.GeneratedAt,
	}

	if report.Snapshot != nil {
		jr.SnapshotID = report.Snapshot.ID
		jr.Label = report.Snapshot.Label
	}

	if report.BlastRadius != nil {
		br := report.BlastRadius
		jbr := jsonBlastRadius{
			PrincipalID:             br.PrincipalID,
			ReachableResourceCount:  br.ReachableResourceCount,
			PctEnvironmentReachable: br.PctEnvironmentReachable,
			MinHopToAdmin:           br.MinHopToAdmin,
			DistinctPathCount:       br.DistinctPathCount,
			Paths:                   []jsonAttackPath{},
		}
		for _, p := range br.Paths {
			if p == nil {
				continue
			}
			jbr.Paths = append(jbr.Paths, jsonAttackPath{
				ID:                    p.ID,
				FromPrincipalID:       p.FromPrincipalID,
				ToResourceID:          p.ToResourceID,
				HopCount:              p.HopCount,
				PathNodes:             p.PathNodes,
				PathEdges:             p.PathEdges,
				IsPrivilegeEscalation: p.IsPrivilegeEscalation,
				ChainLengthClass:      p.ChainLengthClass,
			})
		}
		jr.BlastRadius = jbr
	}

	jr.Findings = []jsonFinding{}
	for _, f := range report.Findings {
		if f == nil {
			continue
		}
		jr.Findings = append(jr.Findings, jsonFinding{
			ID:          f.ID,
			SnapshotID:  f.SnapshotID,
			RuleID:      f.RuleID,
			Severity:    string(f.Severity),
			EntityRef:   f.EntityRef,
			Reason:      f.Reason,
			Remediation: f.Remediation,
		})
	}

	return jr, nil
}
