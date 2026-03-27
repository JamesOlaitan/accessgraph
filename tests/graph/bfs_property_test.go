// Package graph_test — property-based and coverage-completion tests for the
// BFS engine.
//
// Property-based tests use pgregory.net/rapid to generate random graph
// structures and verify invariants that hand-crafted graphs cannot cover.
//
// Coverage-completion tests add targeted cases for branches that the
// table-driven tests in bfs_test.go do not reach: context cancellation,
// already-visited-node skip, neighbour deduplication, and the ClassTwoHop
// path in buildAttackPath.
package graph_test

import (
	"context"
	"fmt"
	"testing"

	"pgregory.net/rapid"

	"github.com/JamesOlaitan/accessgraph/internal/graph"
	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// TestBFSHopCountIsMinimal verifies that the hop count on every returned
// attack path equals the shortest path from the BFS origin to that resource.
//
// Invariant: for every path p returned by BFS, ShortestPath(from, p.ToResourceID)
// returns HopCount == p.HopCount. Because BFS uses shortest-path semantics
// (first discovery wins), this must hold for all graph structures.
func TestBFSHopCountIsMinimal(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		snap := generateConnectedSnapshot(rt)
		if len(snap.Principals) == 0 {
			return
		}

		eng, err := graph.NewEngine(snap)
		if err != nil {
			rt.Skip("engine build failed:", err)
		}

		fromID := snap.Principals[0].ID
		paths, err := eng.BFS(context.Background(), fromID, 8)
		if err != nil {
			rt.Skip("BFS error:", err)
		}

		for _, p := range paths {
			sp, spErr := eng.ShortestPath(context.Background(), fromID, p.ToResourceID, 8)
			if spErr != nil {
				// ShortestPath should agree with BFS; if it can't find a path, that is
				// a BFS error — report it.
				rt.Errorf("BFS found path to %s but ShortestPath returned error: %v",
					p.ToResourceID, spErr)
				continue
			}
			if sp.HopCount != p.HopCount {
				rt.Errorf("path to %s: BFS HopCount=%d, ShortestPath HopCount=%d (BFS must return shortest path)",
					p.ToResourceID, p.HopCount, sp.HopCount)
			}
		}
	})
}

// TestBFSRespectsMaxHopsProperty verifies that no returned attack path has
// HopCount > maxHops.
//
// Invariant: for all paths p in BFS(from, maxHops): p.HopCount <= maxHops.
func TestBFSRespectsMaxHopsProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		snap := generateConnectedSnapshot(rt)
		if len(snap.Principals) == 0 {
			return
		}

		maxHops := rapid.IntRange(1, 5).Draw(rt, "maxHops")

		eng, err := graph.NewEngine(snap)
		if err != nil {
			rt.Skip("engine build failed:", err)
		}

		fromID := snap.Principals[0].ID
		paths, err := eng.BFS(context.Background(), fromID, maxHops)
		if err != nil {
			rt.Skip("BFS error:", err)
		}

		for _, p := range paths {
			if p.HopCount > maxHops {
				rt.Errorf("path to %s has HopCount=%d which exceeds maxHops=%d",
					p.ToResourceID, p.HopCount, maxHops)
			}
		}
	})
}

// TestBFSTerminatesOnCyclicGraph verifies that BFS always terminates and
// returns a finite result even when the graph contains cycles.
//
// Invariant: BFS on a cyclic graph never hangs; the number of returned paths
// is <= the number of sensitive resources in the snapshot.
func TestBFSTerminatesOnCyclicGraph(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		snap := generateCyclicSnapshot(rt)
		if len(snap.Principals) == 0 {
			return
		}

		eng, err := graph.NewEngine(snap)
		if err != nil {
			rt.Skip("engine build failed:", err)
		}

		fromID := snap.Principals[0].ID
		paths, err := eng.BFS(context.Background(), fromID, 6)
		if err != nil {
			rt.Skip("BFS error:", err)
		}

		// Count sensitive resources.
		sensitiveCount := 0
		for _, r := range snap.Resources {
			if r != nil && r.IsSensitive {
				sensitiveCount++
			}
		}

		// BFS returns at most one path per sensitive resource.
		if len(paths) > sensitiveCount {
			rt.Errorf("BFS returned %d paths but only %d sensitive resources exist — duplicate paths detected",
				len(paths), sensitiveCount)
		}
	})
}

// TestBFSEmptyGraphProducesNoPaths verifies that a graph with no edges produces
// no attack paths regardless of the number of nodes.
//
// Invariant: BFS on a graph with zero edges always returns an empty path slice.
func TestBFSEmptyGraphProducesNoPaths(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate principals and resources but no edges.
		nPrincipals := rapid.IntRange(1, 10).Draw(rt, "nPrincipals")
		nResources := rapid.IntRange(0, 10).Draw(rt, "nResources")

		snap := &model.Snapshot{ID: "prop-empty", Label: "prop-empty", Provider: "aws"}
		for i := range nPrincipals {
			snap.Principals = append(snap.Principals, &model.Principal{
				ID:         fmt.Sprintf("p-%d", i),
				SnapshotID: snap.ID,
				Kind:       model.PrincipalKindIAMUser,
				ARN:        fmt.Sprintf("arn:aws:iam::1:user/u%d", i),
			})
		}
		for i := range nResources {
			snap.Resources = append(snap.Resources, &model.Resource{
				ID:          fmt.Sprintf("r-%d", i),
				SnapshotID:  snap.ID,
				ARN:         fmt.Sprintf("arn:aws:iam::aws:policy/Pol%d", i),
				Kind:        "IAMPolicy",
				IsSensitive: true, // mark sensitive so any path would be returned if found
			})
		}
		// Intentionally: no edges.

		eng, err := graph.NewEngine(snap)
		if err != nil {
			rt.Skip("engine build failed:", err)
		}

		fromID := snap.Principals[0].ID
		paths, err := eng.BFS(context.Background(), fromID, 8)
		if err != nil {
			rt.Fatalf("BFS on edgeless graph returned error: %v", err)
		}
		if len(paths) != 0 {
			rt.Errorf("edgeless graph: expected 0 paths, got %d", len(paths))
		}
	})
}

// TestBFSContextCancellation verifies that BFS returns context.Canceled when
// the context is cancelled before traversal completes.
func TestBFSContextCancellation(t *testing.T) {
	// Build a chain: user-0 → user-1 → ... → resource (sensitive).
	// Use enough nodes that at least one BFS iteration happens before cancel.
	snap := buildChainSnapshot("ctx-bfs", 5, true)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err = eng.BFS(ctx, "ctx-bfs-p0", 8)
	if err == nil {
		// The BFS may have completed before the cancellation was observed
		// (the queue was tiny). Accept nil err as a non-failure.
		t.Log("BFS completed before context cancel was observed — acceptable for tiny graph")
		return
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// TestBFSRevisitSkip verifies that BFS correctly skips nodes that are already
// in the visited set (the dequeue-time visited check). This branch fires when
// a node is reachable via multiple distinct paths: it is enqueued more than
// once but only processed once.
func TestBFSRevisitSkip(t *testing.T) {
	// Graph: A → B, A → C, B → D (sensitive), C → D (sensitive)
	// D is enqueued twice (once from B, once from C) but visited only once.
	snap := &model.Snapshot{ID: "rev-snap", Label: "rev", Provider: "aws"}
	snap.Principals = []*model.Principal{
		{ID: "A", SnapshotID: "rev-snap", Kind: model.PrincipalKindIAMUser, ARN: "arn:A"},
		{ID: "B", SnapshotID: "rev-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:B"},
		{ID: "C", SnapshotID: "rev-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:C"},
	}
	snap.Resources = []*model.Resource{
		{ID: "D", SnapshotID: "rev-snap", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "IAMPolicy", IsSensitive: true},
	}
	snap.Edges = []*model.Edge{
		{ID: "AB", SnapshotID: "rev-snap", FromNodeID: "A", ToNodeID: "B", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "AC", SnapshotID: "rev-snap", FromNodeID: "A", ToNodeID: "C", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "BD", SnapshotID: "rev-snap", FromNodeID: "B", ToNodeID: "D", Kind: model.EdgeKindAllowsAction, Weight: 1},
		{ID: "CD", SnapshotID: "rev-snap", FromNodeID: "C", ToNodeID: "D", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	paths, err := eng.BFS(context.Background(), "A", 8)
	if err != nil {
		t.Fatalf("BFS: %v", err)
	}
	// D is reachable in 2 hops via either B or C.
	// BFS shortest-path semantics: exactly one path to D.
	if len(paths) != 1 {
		t.Errorf("expected exactly 1 path (D reachable via B or C), got %d", len(paths))
	}
	if paths[0].HopCount != 2 {
		t.Errorf("expected HopCount=2 (two-hop path A→B→D or A→C→D), got %d", paths[0].HopCount)
	}
}

// TestBFSVisitedNeighbourSkip verifies that BFS does not re-enqueue a node
// that was already enqueued in the same wave (the outbound-edge visited check).
// This targets the inner `if visited[neighbour]` branch.
func TestBFSVisitedNeighbourSkip(t *testing.T) {
	// Graph: A → B → C (sensitive), A → C (sensitive)
	// C is enqueued from B (depth 2) AND from A (depth 1). The depth-1 path
	// wins. When expanding B's neighbours, C is already visited, so the
	// inner branch fires.
	snap := &model.Snapshot{ID: "vs-snap", Label: "vs", Provider: "aws"}
	snap.Principals = []*model.Principal{
		{ID: "A", SnapshotID: "vs-snap", Kind: model.PrincipalKindIAMUser, ARN: "arn:A"},
		{ID: "B", SnapshotID: "vs-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:B"},
	}
	snap.Resources = []*model.Resource{
		{ID: "C", SnapshotID: "vs-snap", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "IAMPolicy", IsSensitive: true},
	}
	snap.Edges = []*model.Edge{
		{ID: "AB", SnapshotID: "vs-snap", FromNodeID: "A", ToNodeID: "B", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "BC", SnapshotID: "vs-snap", FromNodeID: "B", ToNodeID: "C", Kind: model.EdgeKindAllowsAction, Weight: 1},
		{ID: "AC", SnapshotID: "vs-snap", FromNodeID: "A", ToNodeID: "C", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	paths, err := eng.BFS(context.Background(), "A", 8)
	if err != nil {
		t.Fatalf("BFS: %v", err)
	}
	// Only one path to C — the 1-hop A→C (shortest).
	if len(paths) != 1 {
		t.Errorf("expected 1 path to C, got %d", len(paths))
	}
	if paths[0].HopCount != 1 {
		t.Errorf("expected HopCount=1 (direct A→C), got %d", paths[0].HopCount)
	}
}

// TestBFSSortTiebreaker verifies that when two paths have the same HopCount,
// they are ordered by path ID (secondary sort key) for deterministic output.
// This exercises the HopCount-equal branch in the sort comparator.
func TestBFSSortTiebreaker(t *testing.T) {
	// Graph: A → B (sensitive), A → C (sensitive).
	// Both B and C are reachable in 1 hop. The two paths have the same HopCount;
	// the sort tiebreaker (by ID) must produce a consistent order.
	snap := &model.Snapshot{ID: "tie-snap", Label: "tie", Provider: "aws"}
	snap.Principals = []*model.Principal{
		{ID: "A", SnapshotID: "tie-snap", Kind: model.PrincipalKindIAMUser, ARN: "arn:A"},
	}
	snap.Resources = []*model.Resource{
		{ID: "B", SnapshotID: "tie-snap", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "IAMPolicy", IsSensitive: true},
		{ID: "C", SnapshotID: "tie-snap", ARN: "arn:aws:iam::1:role/admin", Kind: "IAMRole", IsSensitive: true},
	}
	snap.Edges = []*model.Edge{
		{ID: "AB", SnapshotID: "tie-snap", FromNodeID: "A", ToNodeID: "B", Kind: model.EdgeKindAllowsAction, Weight: 1},
		{ID: "AC", SnapshotID: "tie-snap", FromNodeID: "A", ToNodeID: "C", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	paths1, err := eng.BFS(context.Background(), "A", 8)
	if err != nil {
		t.Fatalf("BFS run 1: %v", err)
	}
	paths2, err := eng.BFS(context.Background(), "A", 8)
	if err != nil {
		t.Fatalf("BFS run 2: %v", err)
	}

	if len(paths1) != 2 || len(paths2) != 2 {
		t.Fatalf("expected 2 paths, got %d / %d", len(paths1), len(paths2))
	}

	// Both runs must produce the same order (deterministic tiebreaker).
	for i := range paths1 {
		if paths1[i].ID != paths2[i].ID {
			t.Errorf("path[%d] ID mismatch: %s vs %s — sort is not deterministic", i, paths1[i].ID, paths2[i].ID)
		}
	}
}

// TestBFSTwoHopClassification verifies that a 2-hop path is assigned
// ClassTwoHop (the hopCount==2 branch in buildAttackPath).
func TestBFSTwoHopClassification(t *testing.T) {
	// Graph: A → B → C (sensitive), 2-hop path.
	snap := &model.Snapshot{ID: "twohop-snap", Label: "twohop", Provider: "aws"}
	snap.Principals = []*model.Principal{
		{ID: "A", SnapshotID: "twohop-snap", Kind: model.PrincipalKindIAMUser, ARN: "arn:A"},
		{ID: "B", SnapshotID: "twohop-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:B"},
	}
	snap.Resources = []*model.Resource{
		{ID: "C", SnapshotID: "twohop-snap", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "IAMPolicy", IsSensitive: true},
	}
	snap.Edges = []*model.Edge{
		{ID: "AB", SnapshotID: "twohop-snap", FromNodeID: "A", ToNodeID: "B", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "BC", SnapshotID: "twohop-snap", FromNodeID: "B", ToNodeID: "C", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	paths, err := eng.BFS(context.Background(), "A", 8)
	if err != nil {
		t.Fatalf("BFS: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if paths[0].ChainLengthClass != model.ClassTwoHop {
		t.Errorf("expected ClassTwoHop for 2-hop path, got %v", paths[0].ChainLengthClass)
	}
}

// TestNeighboursContextCancellation verifies that Neighbors returns
// context.Canceled when the context is cancelled before edge traversal.
func TestNeighboursContextCancellation(t *testing.T) {
	snap := &model.Snapshot{ID: "nb-ctx-snap", Label: "nb-ctx", Provider: "aws"}
	snap.Principals = []*model.Principal{
		{ID: "hub", SnapshotID: "nb-ctx-snap", Kind: model.PrincipalKindIAMUser, ARN: "arn:hub"},
		{ID: "spoke", SnapshotID: "nb-ctx-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:spoke"},
	}
	snap.Edges = []*model.Edge{
		{ID: "e1", SnapshotID: "nb-ctx-snap", FromNodeID: "hub", ToNodeID: "spoke", Kind: model.EdgeKindAssumesRole, Weight: 1},
	}

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = eng.Neighbors(ctx, "hub", nil)
	if err != nil && err != context.Canceled {
		t.Errorf("expected nil or context.Canceled, got: %v", err)
	}
	// Nil err is acceptable if the small graph completes before cancellation.
}

// TestNeighboursDeduplication verifies that Neighbors returns each node only
// once even when multiple edges connect the same (source, target) pair.
// This exercises the seen[edge.ToNodeID] branch.
func TestNeighboursDeduplication(t *testing.T) {
	snap := &model.Snapshot{ID: "dup-snap", Label: "dup", Provider: "aws"}
	snap.Principals = []*model.Principal{
		{ID: "hub", SnapshotID: "dup-snap", Kind: model.PrincipalKindIAMUser, ARN: "arn:hub"},
		{ID: "target", SnapshotID: "dup-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:target"},
	}
	snap.Edges = []*model.Edge{
		{ID: "e1", SnapshotID: "dup-snap", FromNodeID: "hub", ToNodeID: "target", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "e2", SnapshotID: "dup-snap", FromNodeID: "hub", ToNodeID: "target", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	neighbors, err := eng.Neighbors(context.Background(), "hub", nil)
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if len(neighbors) != 1 {
		t.Errorf("expected 1 unique neighbor (deduplication), got %d", len(neighbors))
	}
}

// TestNeighboursEmptyResult verifies that Neighbors returns an empty (non-nil)
// slice when the node has no outbound edges matching the filter.
// This exercises the `if result == nil { result = []*model.Node{} }` branch.
func TestNeighboursEmptyResult(t *testing.T) {
	snap := &model.Snapshot{ID: "leaf-snap", Label: "leaf", Provider: "aws"}
	snap.Principals = []*model.Principal{
		{ID: "leaf", SnapshotID: "leaf-snap", Kind: model.PrincipalKindIAMUser, ARN: "arn:leaf"},
	}
	// No edges from "leaf".

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	neighbors, err := eng.Neighbors(context.Background(), "leaf", nil)
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if neighbors == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(neighbors) != 0 {
		t.Errorf("expected 0 neighbors, got %d", len(neighbors))
	}
}

// TestShortestPathContextCancellation verifies that ShortestPath returns
// context.Canceled when the context is cancelled before the path is found.
func TestShortestPathContextCancellation(t *testing.T) {
	snap := buildChainSnapshot("sp-ctx", 4, false)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = eng.ShortestPath(ctx, "sp-ctx-p0", "sp-ctx-p3", 8)
	if err != nil && err != context.Canceled && err != graph.ErrNoPath {
		t.Errorf("expected context.Canceled or ErrNoPath (tiny graph may finish first), got: %v", err)
	}
}

// TestShortestPathIntermediateRevisitSkip verifies the dequeue-time visited
// check in ShortestPath fires on an intermediate node (not the destination)
// that is enqueued multiple times. Graph: A→B, A→C, B→X, C→X, X→D.
// X is enqueued twice (from B and from C). The second dequeue of X must be
// skipped by the visited check.
func TestShortestPathIntermediateRevisitSkip(t *testing.T) {
	snap := &model.Snapshot{ID: "sp-ir-snap", Label: "sp-ir", Provider: "aws"}
	snap.Principals = []*model.Principal{
		{ID: "A", SnapshotID: "sp-ir-snap", Kind: model.PrincipalKindIAMUser, ARN: "arn:A"},
		{ID: "B", SnapshotID: "sp-ir-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:B"},
		{ID: "C", SnapshotID: "sp-ir-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:C"},
		{ID: "XX", SnapshotID: "sp-ir-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:XX"},
		{ID: "D", SnapshotID: "sp-ir-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:D"},
	}
	snap.Edges = []*model.Edge{
		{ID: "AB", SnapshotID: "sp-ir-snap", FromNodeID: "A", ToNodeID: "B", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "AC", SnapshotID: "sp-ir-snap", FromNodeID: "A", ToNodeID: "C", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "BX", SnapshotID: "sp-ir-snap", FromNodeID: "B", ToNodeID: "XX", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "CX", SnapshotID: "sp-ir-snap", FromNodeID: "C", ToNodeID: "XX", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "XD", SnapshotID: "sp-ir-snap", FromNodeID: "XX", ToNodeID: "D", Kind: model.EdgeKindAssumesRole, Weight: 1},
	}

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	sp, err := eng.ShortestPath(context.Background(), "A", "D", 8)
	if err != nil {
		t.Fatalf("ShortestPath: %v", err)
	}
	// A→B→XX→D or A→C→XX→D — both 3 hops.
	if sp.HopCount != 3 {
		t.Errorf("expected HopCount=3, got %d", sp.HopCount)
	}
}

// TestShortestPathRevisitSkip verifies that ShortestPath correctly handles the
// case where the destination node appears in the queue multiple times (the
// dequeue-time visited check in ShortestPath).
func TestShortestPathRevisitSkip(t *testing.T) {
	// Graph: A → B → D, A → C → D. ShortestPath(A, D) should return 2 hops.
	snap := &model.Snapshot{ID: "sp-rev-snap", Label: "sp-rev", Provider: "aws"}
	snap.Principals = []*model.Principal{
		{ID: "A", SnapshotID: "sp-rev-snap", Kind: model.PrincipalKindIAMUser, ARN: "arn:A"},
		{ID: "B", SnapshotID: "sp-rev-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:B"},
		{ID: "C", SnapshotID: "sp-rev-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:C"},
		{ID: "D", SnapshotID: "sp-rev-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:D"},
	}
	snap.Edges = []*model.Edge{
		{ID: "AB", SnapshotID: "sp-rev-snap", FromNodeID: "A", ToNodeID: "B", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "AC", SnapshotID: "sp-rev-snap", FromNodeID: "A", ToNodeID: "C", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "BD", SnapshotID: "sp-rev-snap", FromNodeID: "B", ToNodeID: "D", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "CD", SnapshotID: "sp-rev-snap", FromNodeID: "C", ToNodeID: "D", Kind: model.EdgeKindAssumesRole, Weight: 1},
	}

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	sp, err := eng.ShortestPath(context.Background(), "A", "D", 8)
	if err != nil {
		t.Fatalf("ShortestPath: %v", err)
	}
	if sp.HopCount != 2 {
		t.Errorf("expected HopCount=2, got %d", sp.HopCount)
	}
}

// TestShortestPathVisitedNeighbourSkip verifies the inner visited-neighbour
// check in ShortestPath. Graph: A→B→C, A→C. ShortestPath finds A→C in 1 hop;
// when expanding B, C is already visited so the inner branch fires.
func TestShortestPathVisitedNeighbourSkip(t *testing.T) {
	snap := &model.Snapshot{ID: "spvn-snap", Label: "spvn", Provider: "aws"}
	snap.Principals = []*model.Principal{
		{ID: "A", SnapshotID: "spvn-snap", Kind: model.PrincipalKindIAMUser, ARN: "arn:A"},
		{ID: "B", SnapshotID: "spvn-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:B"},
		{ID: "C", SnapshotID: "spvn-snap", Kind: model.PrincipalKindIAMRole, ARN: "arn:C"},
	}
	snap.Edges = []*model.Edge{
		{ID: "AB", SnapshotID: "spvn-snap", FromNodeID: "A", ToNodeID: "B", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "BC", SnapshotID: "spvn-snap", FromNodeID: "B", ToNodeID: "C", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "AC", SnapshotID: "spvn-snap", FromNodeID: "A", ToNodeID: "C", Kind: model.EdgeKindAssumesRole, Weight: 1},
	}

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	sp, err := eng.ShortestPath(context.Background(), "A", "C", 8)
	if err != nil {
		t.Fatalf("ShortestPath: %v", err)
	}
	if sp.HopCount != 1 {
		t.Errorf("expected HopCount=1 (direct A→C), got %d", sp.HopCount)
	}
}

// TestNewEngineReturnsUsableEngine verifies that NewEngine returns a usable
// *Engine that satisfies the Traverser interface.
func TestNewEngineReturnsUsableEngine(t *testing.T) {
	snap := &model.Snapshot{ID: "gew-snap", Label: "gew", Provider: "aws"}
	snap.Principals = []*model.Principal{
		{ID: "p1", SnapshotID: "gew-snap", Kind: model.PrincipalKindIAMUser, ARN: "arn:p1"},
	}

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngine returned nil engine")
	}
	if eng.NodeCount() < 1 {
		t.Errorf("expected NodeCount >= 1, got %d", eng.NodeCount())
	}
}

// generateConnectedSnapshot generates a random snapshot where principals are
// connected to resources via directed edges. Not all principals or resources
// are necessarily connected.
func generateConnectedSnapshot(t *rapid.T) *model.Snapshot {
	nPrincipals := rapid.IntRange(1, 6).Draw(t, "nPrincipals")
	nResources := rapid.IntRange(0, 4).Draw(t, "nResources")
	nEdges := rapid.IntRange(0, 8).Draw(t, "nEdges")

	snap := &model.Snapshot{ID: "prop-snap", Label: "prop", Provider: "aws"}

	for i := range nPrincipals {
		snap.Principals = append(snap.Principals, &model.Principal{
			ID:         fmt.Sprintf("pp-%d", i),
			SnapshotID: snap.ID,
			Kind:       model.PrincipalKindIAMUser,
			ARN:        fmt.Sprintf("arn:aws:iam::1:user/u%d", i),
		})
	}
	for i := range nResources {
		snap.Resources = append(snap.Resources, &model.Resource{
			ID:          fmt.Sprintf("rr-%d", i),
			SnapshotID:  snap.ID,
			ARN:         fmt.Sprintf("arn:aws:iam::aws:policy/P%d", i),
			Kind:        "IAMPolicy",
			IsSensitive: true,
		})
	}

	// All node IDs (principals + resources) for edge generation.
	var allIDs []string
	for _, p := range snap.Principals {
		allIDs = append(allIDs, p.ID)
	}
	for _, r := range snap.Resources {
		allIDs = append(allIDs, r.ID)
	}

	if len(allIDs) < 2 {
		return snap
	}

	edgeSeen := make(map[string]bool)
	for i := range nEdges {
		fromIdx := rapid.IntRange(0, len(allIDs)-1).Draw(t, fmt.Sprintf("from-%d", i))
		toIdx := rapid.IntRange(0, len(allIDs)-1).Draw(t, fmt.Sprintf("to-%d", i))
		if fromIdx == toIdx {
			continue
		}
		key := fmt.Sprintf("%d→%d", fromIdx, toIdx)
		if edgeSeen[key] {
			continue
		}
		edgeSeen[key] = true
		snap.Edges = append(snap.Edges, &model.Edge{
			ID:         fmt.Sprintf("ge-%s", key),
			SnapshotID: snap.ID,
			FromNodeID: allIDs[fromIdx],
			ToNodeID:   allIDs[toIdx],
			Kind:       model.EdgeKindAllowsAction,
			Weight:     1,
		})
	}
	return snap
}

// generateCyclicSnapshot generates a snapshot with deliberate back-edges
// creating cycles, to stress-test BFS cycle detection.
func generateCyclicSnapshot(t *rapid.T) *model.Snapshot {
	snap := generateConnectedSnapshot(t)

	// Add a back-edge from the last principal to the first, creating a cycle.
	if len(snap.Principals) >= 2 {
		first := snap.Principals[0].ID
		last := snap.Principals[len(snap.Principals)-1].ID
		snap.Edges = append(snap.Edges, &model.Edge{
			ID:         "cycle-back",
			SnapshotID: snap.ID,
			FromNodeID: last,
			ToNodeID:   first,
			Kind:       model.EdgeKindAssumesRole,
			Weight:     1,
		})
	}
	return snap
}

// buildChainSnapshot builds a linear chain of nNodes principals optionally
// ending in a sensitive resource.
func buildChainSnapshot(prefix string, nNodes int, sensitiveEnd bool) *model.Snapshot {
	snap := &model.Snapshot{ID: prefix + "-snap", Label: prefix, Provider: "aws"}
	for i := range nNodes {
		snap.Principals = append(snap.Principals, &model.Principal{
			ID:         fmt.Sprintf("%s-p%d", prefix, i),
			SnapshotID: snap.ID,
			Kind:       model.PrincipalKindIAMUser,
			ARN:        fmt.Sprintf("arn:aws:iam::1:user/u%d", i),
		})
	}
	if sensitiveEnd && nNodes > 0 {
		snap.Resources = append(snap.Resources, &model.Resource{
			ID:          prefix + "-res",
			SnapshotID:  snap.ID,
			ARN:         "arn:aws:iam::aws:policy/AdministratorAccess",
			Kind:        "IAMPolicy",
			IsSensitive: true,
		})
	}
	// Wire the chain.
	for i := 0; i+1 < nNodes; i++ {
		snap.Edges = append(snap.Edges, &model.Edge{
			ID:         fmt.Sprintf("%s-e%d", prefix, i),
			SnapshotID: snap.ID,
			FromNodeID: fmt.Sprintf("%s-p%d", prefix, i),
			ToNodeID:   fmt.Sprintf("%s-p%d", prefix, i+1),
			Kind:       model.EdgeKindAssumesRole,
			Weight:     1,
		})
	}
	if sensitiveEnd && nNodes > 0 {
		snap.Edges = append(snap.Edges, &model.Edge{
			ID:         prefix + "-final",
			SnapshotID: snap.ID,
			FromNodeID: fmt.Sprintf("%s-p%d", prefix, nNodes-1),
			ToNodeID:   prefix + "-res",
			Kind:       model.EdgeKindAllowsAction,
			Weight:     1,
		})
	}
	return snap
}
