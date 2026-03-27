package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// RenderDOT writes the permission graph in Graphviz DOT format to w.
//
// The output represents the attack paths found in report.BlastRadius.Paths.
// Each unique node that appears in any PathNodes list is rendered as a DOT
// node. Each hop in PathEdges is rendered as a directed edge labeled with
// the EdgeKind looked up from report.Snapshot.Edges.
//
// Node coloring:
//   - The FromPrincipalID of any path is colored red (compromised principal).
//   - All other nodes are colored green (reachable resource or intermediate).
//
// Output is deterministic: node IDs are sorted lexicographically before
// writing. Edge order follows the order of paths and their hops.
//
// Parameters:
//   - w: destination writer; must not be nil.
//   - report: the analysis report to render; must not be nil.
//
// Returns ErrRenderFailed (wrapped) on any I/O error.
func (r *DefaultReporter) RenderDOT(w io.Writer, report *model.Report) error {
	if report == nil {
		return fmt.Errorf("%w: nil report", ErrRenderFailed)
	}

	// Build a lookup map from edge ID to edge for label resolution.
	edgeByID := buildEdgeIndex(report)

	// Collect node labels and identify which nodes are "from" principals.
	nodeLabel := buildNodeLabels(report)
	fromPrincipals := buildFromPrincipalSet(report)

	// Collect all unique node IDs in deterministic order.
	sortedNodeIDs := sortedKeys(nodeLabel)

	if err := writef(w, "digraph blast_radius {\n"); err != nil {
		return fmt.Errorf("%w: writing DOT header: %v", ErrRenderFailed, err)
	}
	if err := writef(w, "    rankdir=LR;\n"); err != nil {
		return fmt.Errorf("%w: writing rankdir: %v", ErrRenderFailed, err)
	}
	if err := writef(w, "    node [shape=box, fontname=\"Helvetica\"];\n"); err != nil {
		return fmt.Errorf("%w: writing node defaults: %v", ErrRenderFailed, err)
	}

	for _, nodeID := range sortedNodeIDs {
		label := nodeLabel[nodeID]
		nodeColor := "green"
		if fromPrincipals[nodeID] {
			nodeColor = "red"
		}
		if err := writef(w, "    %s [label=%s, color=%s];\n",
			dotQuote(nodeID),
			dotQuote(label),
			nodeColor,
		); err != nil {
			return fmt.Errorf("%w: writing node %q: %v", ErrRenderFailed, nodeID, err)
		}
	}

	if report.BlastRadius != nil {
		for _, path := range report.BlastRadius.Paths {
			if path == nil {
				continue
			}
			if err := renderPathEdges(w, path, edgeByID); err != nil {
				return fmt.Errorf("%w: writing edges for path %q: %v", ErrRenderFailed, path.ID, err)
			}
		}
	}

	if err := writef(w, "}\n"); err != nil {
		return fmt.Errorf("%w: writing DOT footer: %v", ErrRenderFailed, err)
	}

	return nil
}

// renderPathEdges writes one DOT edge per hop in path.
//
// The edge label is the EdgeKind looked up via edgeByID. When an edge ID is
// not found in the index, the label falls back to the empty string.
//
// Parameters:
//   - w: destination writer.
//   - path: the attack path whose hops are rendered.
//   - edgeByID: map from edge ID to *model.Edge.
//
// Returns the first I/O error encountered.
func renderPathEdges(w io.Writer, path *model.AttackPath, edgeByID map[string]*model.Edge) error {
	// PathNodes has len N; PathEdges has len N-1 (one edge per hop).
	for i := 0; i < len(path.PathNodes)-1; i++ {
		fromNode := path.PathNodes[i]
		toNode := path.PathNodes[i+1]

		edgeLabel := ""
		if i < len(path.PathEdges) {
			if edge, ok := edgeByID[path.PathEdges[i]]; ok {
				edgeLabel = string(edge.Kind)
			}
		}

		if err := writef(w, "    %s -> %s [label=%s];\n",
			dotQuote(fromNode),
			dotQuote(toNode),
			dotQuote(edgeLabel),
		); err != nil {
			return err
		}
	}
	return nil
}

// buildEdgeIndex constructs a map from edge ID to *model.Edge from the
// snapshot's edge list.
//
// Parameters:
//   - report: the report whose snapshot's edges are indexed.
//
// Returns a (possibly empty) map; never nil.
func buildEdgeIndex(report *model.Report) map[string]*model.Edge {
	idx := make(map[string]*model.Edge)
	if report.Snapshot == nil {
		return idx
	}
	for _, e := range report.Snapshot.Edges {
		if e != nil {
			idx[e.ID] = e
		}
	}
	return idx
}

// buildNodeLabels collects all unique node IDs from all attack path PathNodes
// and maps each to a display label.
//
// The label is derived from report.Snapshot node data when available. When a
// node ID does not appear in the snapshot's entity lists, the node ID itself
// is used as the label.
//
// Parameters:
//   - report: the report whose BlastRadius paths are inspected.
//
// Returns a map from node ID to label string; never nil.
func buildNodeLabels(report *model.Report) map[string]string {
	labels := make(map[string]string)

	if report.BlastRadius == nil {
		return labels
	}

	for _, path := range report.BlastRadius.Paths {
		if path == nil {
			continue
		}
		for _, nodeID := range path.PathNodes {
			if _, seen := labels[nodeID]; !seen {
				labels[nodeID] = resolveNodeLabel(nodeID, report)
			}
		}
	}

	return labels
}

// resolveNodeLabel returns a human-readable label for nodeID by searching the
// snapshot's Principals and Resources lists.
//
// Priority:
//  1. Principal ARN if nodeID matches a Principal.ID.
//  2. Resource ARN if nodeID matches a Resource.ID.
//  3. The nodeID itself as a fallback.
//
// Parameters:
//   - nodeID: the node identifier to resolve.
//   - report: the report whose snapshot is searched.
//
// Returns the resolved label string.
func resolveNodeLabel(nodeID string, report *model.Report) string {
	if report.Snapshot == nil {
		return nodeID
	}
	for _, p := range report.Snapshot.Principals {
		if p != nil && p.ID == nodeID {
			if p.ARN != "" {
				return p.ARN
			}
			return p.Name
		}
	}
	for _, res := range report.Snapshot.Resources {
		if res != nil && res.ID == nodeID {
			return res.ARN
		}
	}
	return nodeID
}

// buildFromPrincipalSet collects all FromPrincipalIDs across all attack paths
// and returns them as a set (map to bool).
//
// Parameters:
//   - report: the report whose BlastRadius paths are inspected.
//
// Returns a map where the keys are "from" principal IDs; never nil.
func buildFromPrincipalSet(report *model.Report) map[string]bool {
	set := make(map[string]bool)
	if report.BlastRadius == nil {
		return set
	}
	for _, path := range report.BlastRadius.Paths {
		if path != nil && path.FromPrincipalID != "" {
			set[path.FromPrincipalID] = true
		}
	}
	return set
}

// sortedKeys returns the keys of m sorted lexicographically.
//
// Parameters:
//   - m: the map whose keys are collected and sorted.
//
// Returns a sorted string slice.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// dotQuote wraps s in double quotes, escaping any internal double-quote
// characters with a backslash.
//
// Parameters:
//   - s: the string to quote for DOT output.
//
// Returns the quoted string.
func dotQuote(s string) string {
	escaped := strings.ReplaceAll(s, `"`, `\"`)
	return `"` + escaped + `"`
}

// writef is a helper that calls fmt.Fprintf and discards the byte count,
// returning only the error. It reduces verbosity at call sites.
//
// Parameters:
//   - w: the destination writer.
//   - format: printf format string.
//   - args: format arguments.
//
// Returns any error from fmt.Fprintf.
func writef(w io.Writer, format string, args ...any) error {
	_, err := fmt.Fprintf(w, format, args...)
	return err
}
