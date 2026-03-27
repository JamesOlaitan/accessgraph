// Package analyzer computes blast-radius metrics for a single compromised
// principal within an AccessGraph permission snapshot.
//
// The package defines the BlastRadiusAnalyzer interface and a local Traverser
// interface that mirrors the subset of graph.Traverser required here. Using
// a local interface instead of importing graph.Traverser directly avoids an
// import cycle and keeps the dependency graph acyclic.
//
// Dependency rule: this file imports only the standard library and
// github.com/JamesOlaitan/accessgraph/internal/model. The concrete
// implementation in blast_radius.go additionally imports internal/graph
// and internal/store for error sentinel translation.
package analyzer

import (
	"context"
	"errors"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// Sentinel errors returned by BlastRadiusAnalyzer implementations.
var (
	// ErrNotFound is returned when the requested principal ID does not exist
	// in the graph engine.
	ErrNotFound = errors.New("entity not found")

	// ErrInvalidInput is returned when a required parameter fails a precondition
	// check (e.g., empty principalID, maxHops < 1).
	ErrInvalidInput = errors.New("invalid input")
)

// Traverser is a structural subset of the graph.Traverser interface,
// defined here to avoid an import cycle between internal/analyzer and
// internal/graph. The concrete *graph.Engine satisfies this interface.
//
// If internal/graph adds or renames methods used by the analyzer, this
// interface must be updated in sync. Tests exercising both packages together
// will catch any drift at compile time.
type Traverser interface {
	// BFS returns all attack paths reachable from fromPrincipalID within
	// maxHops steps. Only paths that terminate at a sensitive resource are
	// included.
	//
	// Parameters:
	//   - ctx:             context for cancellation.
	//   - fromPrincipalID: node ID of the starting principal.
	//   - maxHops:         maximum edge traversal depth; must be >= 1.
	//
	// Returns:
	//   - []*model.AttackPath sorted by HopCount ascending; never nil.
	//
	// Errors:
	//   - ErrNotFound    if fromPrincipalID does not exist.
	//   - ErrInvalidInput if maxHops < 1.
	//   - context.Canceled / context.DeadlineExceeded if ctx is done.
	BFS(ctx context.Context, fromPrincipalID string, maxHops int) ([]*model.AttackPath, error)

	// NodeCount returns the total number of nodes currently in the graph.
	//
	// Returns:
	//   - int total node count.
	NodeCount() int
}

// BlastRadiusAnalyzer computes the full blast-radius report for a single
// compromised principal.
//
// Implementations must be safe for concurrent use after construction.
type BlastRadiusAnalyzer interface {
	// Analyze computes the full blast-radius report for principalID by running
	// a BFS traversal on the provided engine up to maxHops edges deep.
	//
	// Parameters:
	//   - ctx:         context for cancellation; passed through to engine.BFS.
	//   - engine:      a built graph engine that exposes BFS and NodeCount.
	//   - snapshotID:  the ID of the snapshot being analysed; stamped on the report.
	//   - principalID: the ID of the starting principal; must be non-empty.
	//   - maxHops:     maximum BFS depth; must be >= 1.
	//
	// Returns:
	//   - *model.BlastRadiusReport with all metric fields populated.
	//   - ErrNotFound    if principalID does not exist in the engine.
	//   - ErrInvalidInput if principalID is empty or maxHops < 1.
	Analyze(ctx context.Context, engine Traverser, snapshotID string, principalID string, maxHops int) (*model.BlastRadiusReport, error)
}

// Compile-time assertion: *Analyzer must satisfy BlastRadiusAnalyzer.
var _ BlastRadiusAnalyzer = (*Analyzer)(nil)
