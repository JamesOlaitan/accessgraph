package graph

import (
	"fmt"

	"github.com/JamesOlaitan/accessgraph/internal/iampolicy"
	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// Engine is the concrete, in-memory implementation of Traverser.
//
// Safe for concurrent use: all traversal methods (BFS, Neighbors, ShortestPath,
// NodeCount, EdgeCount) are read-only after construction and may be called from
// multiple goroutines without synchronization.
//
// An Engine is constructed by NewEngine and must not be copied after first use.
// The only mutation allowed after construction is the addition of synthesized
// escalation edges via SynthesizeEscalationEdges, which is designed to be
// called exactly once immediately after NewEngine returns.
//
// All map fields are keyed by the corresponding entity ID and are populated
// exclusively during construction; no subsequent method mutates them except
// SynthesizeEscalationEdges.
type Engine struct {
	// snapshot is the source of truth from which this engine was built.
	snapshot *model.Snapshot

	// nodes maps every node ID to its Node descriptor.
	nodes map[string]*model.Node

	// edges maps every edge ID to its Edge descriptor.
	edges map[string]*model.Edge

	// outbound maps a node ID to the slice of edges that originate from it.
	outbound map[string][]*model.Edge

	// inbound maps a node ID to the slice of edges that terminate at it.
	inbound map[string][]*model.Edge

	// sensitiveNodes is the set of resource node IDs for which IsSensitive == true.
	sensitiveNodes map[string]bool
}

// NewEngine constructs an Engine from the provided Snapshot.
//
// The constructor performs the following steps in order:
//  1. Validates that snapshot is non-nil.
//  2. Allocates all internal maps.
//  3. Creates one Node for every Principal, Policy, and Resource in the snapshot.
//  4. Registers each Resource that has IsSensitive == true in sensitiveNodes.
//  5. Indexes every Edge from snapshot.Edges into edges, outbound, and inbound.
//     Edges whose FromNodeID or ToNodeID do not correspond to a known node are
//     still indexed; the caller is responsible for snapshot consistency.
//
// Parameters:
//   - snapshot: the point-in-time IAM environment to build the graph from.
//
// Returns:
//   - *Engine ready for traversal.
//   - ErrInvalidInput if snapshot is nil.
func NewEngine(snapshot *model.Snapshot) (*Engine, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("NewEngine: %w", ErrInvalidInput)
	}

	e := &Engine{
		snapshot:       snapshot,
		nodes:          make(map[string]*model.Node),
		edges:          make(map[string]*model.Edge),
		outbound:       make(map[string][]*model.Edge),
		inbound:        make(map[string][]*model.Edge),
		sensitiveNodes: make(map[string]bool),
	}

	// Register a node for every Principal.
	// Kind is the string representation of PrincipalKind.
	// Label is the ARN (most useful for security analysis display).
	for _, p := range snapshot.Principals {
		if p == nil {
			continue
		}
		e.nodes[p.ID] = &model.Node{
			ID:    p.ID,
			Kind:  string(p.Kind),
			Label: p.ARN,
		}
	}

	// Register a node for every Policy.
	// Kind is "Policy"; Label is the policy Name (ARN may be empty for inline policies).
	// Admin-equivalent policies (AdministratorAccess or wildcard-grant) are added to
	// sensitiveNodes so that BFS can detect privilege-escalation chains that terminate
	// at a policy node rather than a resource node.
	for _, pol := range snapshot.Policies {
		if pol == nil {
			continue
		}
		e.nodes[pol.ID] = &model.Node{
			ID:    pol.ID,
			Kind:  "Policy",
			Label: pol.Name,
		}
		if iampolicy.IsAdminEquivalentPolicy(pol) {
			e.sensitiveNodes[pol.ID] = true
		}
	}

	// Register a node for every Resource.
	// Kind is the resource service type (e.g., "S3Bucket"); Label is the ARN.
	for _, r := range snapshot.Resources {
		if r == nil {
			continue
		}
		e.nodes[r.ID] = &model.Node{
			ID:    r.ID,
			Kind:  r.Kind,
			Label: r.ARN,
		}
		if r.IsSensitive {
			e.sensitiveNodes[r.ID] = true
		}
	}

	// Index all edges from the snapshot.
	for _, edge := range snapshot.Edges {
		if edge == nil {
			continue
		}
		e.addEdge(edge)
	}

	return e, nil
}

// addEdge inserts a single edge into the engine's edge index, outbound map, and
// inbound map. It is the single point of mutation used by both the constructor
// and SynthesizeEscalationEdges.
//
// Parameters:
//   - edge: the edge to add; must not be nil.
func (e *Engine) addEdge(edge *model.Edge) {
	e.edges[edge.ID] = edge
	e.outbound[edge.FromNodeID] = append(e.outbound[edge.FromNodeID], edge)
	e.inbound[edge.ToNodeID] = append(e.inbound[edge.ToNodeID], edge)

	// Ensure both endpoint nodes have an entry in the nodes map even when the
	// snapshot omits an explicit node descriptor for a synthetic endpoint.
	if _, ok := e.nodes[edge.FromNodeID]; !ok {
		e.nodes[edge.FromNodeID] = &model.Node{
			ID:    edge.FromNodeID,
			Kind:  "Unknown",
			Label: edge.FromNodeID,
		}
	}
	if _, ok := e.nodes[edge.ToNodeID]; !ok {
		e.nodes[edge.ToNodeID] = &model.Node{
			ID:    edge.ToNodeID,
			Kind:  "Unknown",
			Label: edge.ToNodeID,
		}
	}
}

// NodeCount returns the total number of nodes in the graph.
//
// Returns:
//   - int count of all nodes, including any added for synthesized escalation edges.
func (e *Engine) NodeCount() int {
	return len(e.nodes)
}

// EdgeCount returns the total number of edges in the graph.
//
// Returns:
//   - int count of all edges, including synthesized escalation edges.
func (e *Engine) EdgeCount() int {
	return len(e.edges)
}
