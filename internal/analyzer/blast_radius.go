package analyzer

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/JamesOlaitan/accessgraph/internal/graph"
	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// Analyzer is the concrete implementation of BlastRadiusAnalyzer.
//
// Construct instances via NewAnalyzer. The zero value is not ready for use.
// All exported methods are safe for concurrent use after construction.
type Analyzer struct{}

// NewAnalyzer constructs a ready-to-use Analyzer.
//
// Returns:
//   - *Analyzer ready for Analyze calls.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Analyze implements BlastRadiusAnalyzer.Analyze.
//
// It delegates graph traversal to engine.BFS and then derives the following
// metrics from the returned attack paths:
//
//   - ReachableResourceCount: distinct ToResourceID values across all paths.
//   - PctEnvironmentReachable: ReachableResourceCount / engine.NodeCount() * 100;
//     zero if NodeCount() returns 0.
//   - MinHopToAdmin: minimum HopCount across paths where IsPrivilegeEscalation
//     is true; -1 when no escalation path exists or when paths is empty.
//   - DistinctPathCount: total number of paths returned by BFS.
//   - Paths: all paths sorted by HopCount ascending then by ID ascending for
//     deterministic output.
//
// Parameters:
//   - ctx:         context for cancellation; forwarded to engine.BFS.
//   - engine:      graph engine used for BFS traversal; must not be nil.
//   - snapshotID:  the ID of the snapshot being analysed; stamped on the report.
//   - principalID: the ID of the starting principal; must be non-empty.
//   - maxHops:     maximum BFS depth; must be >= 1.
//
// Returns:
//   - *model.BlastRadiusReport with all metric fields populated.
//   - ErrInvalidInput if principalID is empty or maxHops < 1.
//   - ErrNotFound    if principalID does not exist in the engine (propagated
//     from engine.BFS).
func (a *Analyzer) Analyze(
	ctx context.Context,
	engine Traverser,
	snapshotID string,
	principalID string,
	maxHops int,
) (*model.BlastRadiusReport, error) {
	if principalID == "" {
		return nil, fmt.Errorf("Analyze: %w: principalID must not be empty", ErrInvalidInput)
	}
	if maxHops < 1 {
		return nil, fmt.Errorf("Analyze: %w: maxHops must be >= 1, got %d", ErrInvalidInput, maxHops)
	}

	paths, err := engine.BFS(ctx, principalID, maxHops)
	if err != nil {
		// Translate graph.ErrNotFound into the local sentinel so callers of
		// this package do not need to import the graph package.
		if isNotFound(err) {
			return nil, fmt.Errorf("Analyze: %w: principal %q not found in graph", ErrNotFound, principalID)
		}
		return nil, fmt.Errorf("Analyze: BFS failed: %w", err)
	}

	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		if p.ToResourceID != "" {
			seen[p.ToResourceID] = true
		}
	}
	reachableCount := len(seen)

	nodeCount := engine.NodeCount()
	var pct float64
	if nodeCount > 0 {
		pct = float64(reachableCount) / float64(nodeCount) * 100.0
	}

	minHopToAdmin := computeMinHopToAdmin(paths)

	// Sort paths: HopCount ascending, then ID ascending for deterministic output.
	sortedPaths := make([]*model.AttackPath, len(paths))
	copy(sortedPaths, paths)
	sort.Slice(sortedPaths, func(i, j int) bool {
		if sortedPaths[i].HopCount != sortedPaths[j].HopCount {
			return sortedPaths[i].HopCount < sortedPaths[j].HopCount
		}
		return sortedPaths[i].ID < sortedPaths[j].ID
	})

	report := &model.BlastRadiusReport{
		PrincipalID:             principalID,
		SnapshotID:              snapshotID,
		ReachableResourceCount:  reachableCount,
		PctEnvironmentReachable: model.MetricFloat(pct),
		MinHopToAdmin:           minHopToAdmin,
		DistinctPathCount:       len(sortedPaths),
		Paths:                   sortedPaths,
	}

	return report, nil
}

// computeMinHopToAdmin returns the minimum HopCount across all paths where
// IsPrivilegeEscalation is true. Returns -1 when no escalation path exists
// or when paths is empty.
func computeMinHopToAdmin(paths []*model.AttackPath) int {
	if len(paths) == 0 {
		return -1
	}

	minEscalation := -1

	for _, p := range paths {
		if p.IsPrivilegeEscalation {
			if minEscalation < 0 || p.HopCount < minEscalation {
				minEscalation = p.HopCount
			}
		}
	}

	return minEscalation
}

// isNotFound reports whether err wraps a "not found" sentinel from any package.
// The graph, store, and analyzer packages each define their own ErrNotFound
// sentinel with the same canonical message; all three must be checked here
// because the graph package cannot import analyzer (or store) due to the
// acyclic dependency rule, so it wraps its own sentinel rather than the
// analyzer or store sentinel.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrNotFound) ||
		errors.Is(err, store.ErrNotFound) ||
		errors.Is(err, graph.ErrNotFound)
}
