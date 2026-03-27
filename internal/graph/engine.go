// Package graph implements the in-memory permission graph engine for AccessGraph.
//
// The package exposes a single concrete type, Engine, which implements the
// Traverser interface. Callers construct an Engine via NewEngine (the
// canonical constructor), optionally run SynthesizeEscalationEdges against it,
// and then call BFS, Neighbors, or ShortestPath to traverse the resulting graph.
//
// Dependency rule: this package imports only the standard library and
// github.com/JamesOlaitan/accessgraph/internal/model. This package must not
// import any other internal package.
package graph

import (
	"context"
	"errors"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// Sentinel errors returned by Traverser methods.
var (
	// ErrNotFound is returned when a requested node ID does not exist in the graph.
	ErrNotFound = errors.New("entity not found")

	// ErrNoPath is returned when no path exists between two nodes within the
	// requested hop limit.
	ErrNoPath = errors.New("no path exists within hop limit")

	// ErrInvalidInput is returned when a caller supplies a parameter that fails
	// a precondition check (e.g., maxHops < 1, nil snapshot).
	ErrInvalidInput = errors.New("invalid input")

	// ErrGraphUnavailable is returned when graph operations are attempted before
	// the engine has been successfully built from a snapshot.
	ErrGraphUnavailable = errors.New("graph has not been built")
)

// Traverser defines the read-only traversal surface of the permission graph.
//
// An implementation is obtained via NewEngine. After construction, callers may
// optionally enrich the graph with synthesized escalation edges via
// SynthesizeEscalationEdges before calling any traversal method.
//
// All methods are safe for concurrent read access after construction completes.
// No method mutates the engine state.
type Traverser interface {
	// BFS returns all attack paths reachable from fromPrincipalID within maxHops
	// steps. Only paths that terminate at a sensitive resource (IsSensitive == true)
	// are included in the result. Paths are sorted by HopCount ascending.
	//
	// Parameters:
	//   - ctx: context for cancellation; the BFS loop checks ctx.Done between hops.
	//   - fromPrincipalID: the node ID of the starting principal.
	//   - maxHops: maximum number of edges to traverse; must be >= 1.
	//
	// Returns:
	//   - []*model.AttackPath sorted by HopCount ascending; may be empty but never nil.
	//
	// Errors:
	//   - ErrNotFound if fromPrincipalID does not exist in the graph.
	//   - ErrInvalidInput if maxHops < 1.
	//   - context.Canceled / context.DeadlineExceeded if ctx is done.
	BFS(ctx context.Context, fromPrincipalID string, maxHops int) ([]*model.AttackPath, error)

	// Neighbors returns all nodes directly reachable from nodeID via a single
	// outbound edge whose Kind is in edgeKinds. An empty edgeKinds slice means
	// all edge kinds are accepted.
	//
	// Parameters:
	//   - ctx: context for cancellation.
	//   - nodeID: the source node ID.
	//   - edgeKinds: filter; only edges of these kinds are followed.
	//
	// Returns:
	//   - []*model.Node, one entry per reachable neighbor (no duplicates).
	//
	// Errors:
	//   - ErrNotFound if nodeID does not exist in the graph.
	Neighbors(ctx context.Context, nodeID string, edgeKinds []model.EdgeKind) ([]*model.Node, error)

	// ShortestPath returns the minimum-hop path between two nodes using BFS.
	//
	// Parameters:
	//   - ctx: context for cancellation.
	//   - from: source node ID.
	//   - to: destination node ID.
	//   - maxHops: search depth limit; must be >= 1.
	//
	// Returns:
	//   - *model.AttackPath describing the shortest path found.
	//
	// Errors:
	//   - ErrNoPath if no path exists between from and to within maxHops.
	//   - ErrNotFound if either from or to does not exist in the graph.
	//   - ErrInvalidInput if maxHops < 1.
	ShortestPath(ctx context.Context, from, to string, maxHops int) (*model.AttackPath, error)

	// NodeCount returns the total number of nodes currently in the graph,
	// including any nodes added by SynthesizeEscalationEdges.
	NodeCount() int

	// EdgeCount returns the total number of edges currently in the graph,
	// including synthesized escalation edges.
	EdgeCount() int
}

// Compile-time assertion that *Engine satisfies Traverser.
var _ Traverser = (*Engine)(nil)
