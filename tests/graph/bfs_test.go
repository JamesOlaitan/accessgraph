package graph_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JamesOlaitan/accessgraph/internal/graph"
	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// makeSnapshot builds a *model.Snapshot from plain slices, assigning
// SnapshotID = "test-snap" on all entities and populating pointer slices.
func makeSnapshot(principals []model.Principal, resources []model.Resource, edges []model.Edge) *model.Snapshot {
	snap := &model.Snapshot{
		ID:    "test-snap",
		Label: "test",
	}

	for i := range principals {
		p := principals[i]
		p.SnapshotID = snap.ID
		snap.Principals = append(snap.Principals, &p)
	}
	for i := range resources {
		r := resources[i]
		r.SnapshotID = snap.ID
		snap.Resources = append(snap.Resources, &r)
	}
	for i := range edges {
		e := edges[i]
		e.SnapshotID = snap.ID
		snap.Edges = append(snap.Edges, &e)
	}

	return snap
}

// TestBFSFindsDirectPath verifies that BFS discovers a single one-hop path
// when a principal has a direct ALLOWS_ACTION edge to a sensitive resource.
func TestBFSFindsDirectPath(t *testing.T) {
	principals := []model.Principal{
		{ID: "user-1", Kind: model.PrincipalKindIAMUser, ARN: "arn:aws:iam::1:user/u"},
	}
	resources := []model.Resource{
		{ID: "res-1", ARN: "arn:aws:iam::1:role/Admin", Kind: "IAMRole", IsSensitive: true},
	}
	edges := []model.Edge{
		{ID: "e1", FromNodeID: "user-1", ToNodeID: "res-1", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	snap := makeSnapshot(principals, resources, edges)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx := context.Background()
	paths, err := eng.BFS(ctx, "user-1", 5)
	if err != nil {
		t.Fatalf("BFS returned error: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if paths[0].HopCount != 1 {
		t.Errorf("expected HopCount=1, got %d", paths[0].HopCount)
	}
	if paths[0].FromPrincipalID != "user-1" {
		t.Errorf("expected FromPrincipalID=user-1, got %s", paths[0].FromPrincipalID)
	}
	if paths[0].ToResourceID != "res-1" {
		t.Errorf("expected ToResourceID=res-1, got %s", paths[0].ToResourceID)
	}
}

// TestBFSFindsMultiHopPath verifies that BFS traverses a two-hop chain:
// principal → role (ASSUMES_ROLE) → sensitive resource (ALLOWS_ACTION).
func TestBFSFindsMultiHopPath(t *testing.T) {
	principals := []model.Principal{
		{ID: "user-2", Kind: model.PrincipalKindIAMUser, ARN: "arn:aws:iam::1:user/u2"},
		{ID: "role-2", Kind: model.PrincipalKindIAMRole, ARN: "arn:aws:iam::1:role/r2"},
	}
	resources := []model.Resource{
		{ID: "res-2", ARN: "arn:aws:iam::1:role/Admin2", Kind: "IAMRole", IsSensitive: true},
	}
	edges := []model.Edge{
		{ID: "e-hop1", FromNodeID: "user-2", ToNodeID: "role-2", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "e-hop2", FromNodeID: "role-2", ToNodeID: "res-2", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	snap := makeSnapshot(principals, resources, edges)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx := context.Background()
	paths, err := eng.BFS(ctx, "user-2", 2)
	if err != nil {
		t.Fatalf("BFS returned error: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if paths[0].HopCount != 2 {
		t.Errorf("expected HopCount=2, got %d", paths[0].HopCount)
	}
}

// TestBFSRespectsMaxHops verifies that BFS does not return paths with
// HopCount greater than maxHops.
func TestBFSRespectsMaxHops(t *testing.T) {
	// Chain: n0 → n1 → n2 → n3 → n4 → sensitive-resource (5 hops).
	principals := []model.Principal{
		{ID: "n0", Kind: model.PrincipalKindIAMUser, ARN: "arn:n0"},
		{ID: "n1", Kind: model.PrincipalKindIAMRole, ARN: "arn:n1"},
		{ID: "n2", Kind: model.PrincipalKindIAMRole, ARN: "arn:n2"},
		{ID: "n3", Kind: model.PrincipalKindIAMRole, ARN: "arn:n3"},
		{ID: "n4", Kind: model.PrincipalKindIAMRole, ARN: "arn:n4"},
	}
	resources := []model.Resource{
		{ID: "sens", ARN: "arn:aws:iam::1:role/Sens", Kind: "IAMRole", IsSensitive: true},
	}
	edges := []model.Edge{
		{ID: "c1", FromNodeID: "n0", ToNodeID: "n1", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "c2", FromNodeID: "n1", ToNodeID: "n2", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "c3", FromNodeID: "n2", ToNodeID: "n3", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "c4", FromNodeID: "n3", ToNodeID: "n4", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "c5", FromNodeID: "n4", ToNodeID: "sens", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	snap := makeSnapshot(principals, resources, edges)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx := context.Background()
	paths, err := eng.BFS(ctx, "n0", 2) // maxHops=2, cannot reach sensitive in 2 hops
	if err != nil {
		t.Fatalf("BFS returned error: %v", err)
	}
	for _, p := range paths {
		if p.HopCount > 2 {
			t.Errorf("path has HopCount=%d which exceeds maxHops=2", p.HopCount)
		}
	}
	// The sensitive resource is 5 hops away; with maxHops=2 no paths are expected.
	if len(paths) != 0 {
		t.Errorf("expected 0 paths with maxHops=2, got %d", len(paths))
	}
}

// TestBFSHandlesCycles verifies that BFS terminates on a graph containing a
// cycle (A assumes B, B assumes A, both can reach a sensitive resource).
func TestBFSHandlesCycles(t *testing.T) {
	principals := []model.Principal{
		{ID: "roleA", Kind: model.PrincipalKindIAMRole, ARN: "arn:aws:iam::1:role/A"},
		{ID: "roleB", Kind: model.PrincipalKindIAMRole, ARN: "arn:aws:iam::1:role/B"},
	}
	resources := []model.Resource{
		{ID: "admin", ARN: "arn:aws:iam::1:role/Admin", Kind: "IAMRole", IsSensitive: true},
	}
	// Cycle: roleA ⇆ roleB; both reach admin.
	edges := []model.Edge{
		{ID: "ab", FromNodeID: "roleA", ToNodeID: "roleB", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "ba", FromNodeID: "roleB", ToNodeID: "roleA", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "ba-admin", FromNodeID: "roleB", ToNodeID: "admin", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	snap := makeSnapshot(principals, resources, edges)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx := context.Background()
	// Use a short timeout to guarantee termination even if BFS loops.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	paths, err := eng.BFS(ctx, "roleA", 10)
	if err != nil {
		t.Fatalf("BFS returned error (possible infinite loop): %v", err)
	}
	// The admin resource must be reachable from roleA via roleB in 2 hops.
	foundAdmin := false
	for _, p := range paths {
		if p.ToResourceID == "admin" {
			foundAdmin = true
			break
		}
	}
	if !foundAdmin {
		t.Error("expected admin resource to be reachable from roleA; not found in results")
	}
}

// TestBFSNoSensitiveResources verifies that BFS returns an empty (non-nil)
// slice when no resources in the graph are marked sensitive.
func TestBFSNoSensitiveResources(t *testing.T) {
	principals := []model.Principal{
		{ID: "user-plain", Kind: model.PrincipalKindIAMUser, ARN: "arn:user-plain"},
	}
	resources := []model.Resource{
		{ID: "bucket", ARN: "arn:aws:s3:::my-bucket", Kind: "S3Bucket", IsSensitive: false},
	}
	edges := []model.Edge{
		{ID: "ub", FromNodeID: "user-plain", ToNodeID: "bucket", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	snap := makeSnapshot(principals, resources, edges)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx := context.Background()
	paths, err := eng.BFS(ctx, "user-plain", 5)
	if err != nil {
		t.Fatalf("BFS returned unexpected error: %v", err)
	}
	if paths == nil {
		t.Error("BFS returned nil slice; expected empty non-nil slice")
	}
	if len(paths) != 0 {
		t.Errorf("expected 0 paths (no sensitive resources), got %d", len(paths))
	}
}

// TestBFSFromNonexistentPrincipal verifies that calling BFS with a principal
// ID not present in the graph returns ErrNotFound.
func TestBFSFromNonexistentPrincipal(t *testing.T) {
	principals := []model.Principal{
		{ID: "existing-user", Kind: model.PrincipalKindIAMUser, ARN: "arn:existing"},
	}
	snap := makeSnapshot(principals, nil, nil)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx := context.Background()
	_, err = eng.BFS(ctx, "ghost-user", 5)
	if err == nil {
		t.Fatal("expected error for non-existent principal, got nil")
	}
	if !errors.Is(err, graph.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestBFSInvalidMaxHops verifies that BFS with maxHops=0 returns ErrInvalidInput.
func TestBFSInvalidMaxHops(t *testing.T) {
	principals := []model.Principal{
		{ID: "user-mh", Kind: model.PrincipalKindIAMUser, ARN: "arn:user-mh"},
	}
	snap := makeSnapshot(principals, nil, nil)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx := context.Background()
	_, err = eng.BFS(ctx, "user-mh", 0)
	if err == nil {
		t.Fatal("expected ErrInvalidInput for maxHops=0, got nil")
	}
	if !errors.Is(err, graph.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

// TestBFSNegativeMaxHops verifies that BFS with maxHops < 0 returns ErrInvalidInput.
func TestBFSNegativeMaxHops(t *testing.T) {
	principals := []model.Principal{
		{ID: "user-neg", Kind: model.PrincipalKindIAMUser, ARN: "arn:user-neg"},
	}
	snap := makeSnapshot(principals, nil, nil)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx := context.Background()
	_, err = eng.BFS(ctx, "user-neg", -1)
	if err == nil {
		t.Fatal("expected ErrInvalidInput for maxHops=-1, got nil")
	}
	if !errors.Is(err, graph.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

// TestBFSPathNodeOrder verifies that PathNodes in the returned attack path
// starts with the principal ID and ends with the resource ID.
func TestBFSPathNodeOrder(t *testing.T) {
	principals := []model.Principal{
		{ID: "start", Kind: model.PrincipalKindIAMUser, ARN: "arn:start"},
	}
	resources := []model.Resource{
		{ID: "end", ARN: "arn:aws:iam::1:role/End", Kind: "IAMRole", IsSensitive: true},
	}
	edges := []model.Edge{
		{ID: "se", FromNodeID: "start", ToNodeID: "end", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	snap := makeSnapshot(principals, resources, edges)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	paths, err := eng.BFS(context.Background(), "start", 5)
	if err != nil {
		t.Fatalf("BFS: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("expected at least one path")
	}
	p := paths[0]
	if len(p.PathNodes) < 2 {
		t.Fatalf("expected PathNodes length >= 2, got %d", len(p.PathNodes))
	}
	if p.PathNodes[0] != "start" {
		t.Errorf("PathNodes[0]=%q, want \"start\"", p.PathNodes[0])
	}
	if p.PathNodes[len(p.PathNodes)-1] != "end" {
		t.Errorf("PathNodes[last]=%q, want \"end\"", p.PathNodes[len(p.PathNodes)-1])
	}
}

// TestShortestPathDirect verifies that ShortestPath returns the 1-hop direct
// route even when a longer alternative route also exists.
func TestShortestPathDirect(t *testing.T) {
	// A can reach B in 1 hop directly, or A→C→D→B in 3 hops.
	principals := []model.Principal{
		{ID: "A", Kind: model.PrincipalKindIAMUser, ARN: "arn:A"},
		{ID: "C", Kind: model.PrincipalKindIAMRole, ARN: "arn:C"},
		{ID: "D", Kind: model.PrincipalKindIAMRole, ARN: "arn:D"},
	}
	resources := []model.Resource{
		{ID: "B", ARN: "arn:aws:iam::1:role/B", Kind: "IAMRole", IsSensitive: true},
	}
	edges := []model.Edge{
		{ID: "AB", FromNodeID: "A", ToNodeID: "B", Kind: model.EdgeKindAllowsAction, Weight: 1},
		{ID: "AC", FromNodeID: "A", ToNodeID: "C", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "CD", FromNodeID: "C", ToNodeID: "D", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "DB", FromNodeID: "D", ToNodeID: "B", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	snap := makeSnapshot(principals, resources, edges)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	path, err := eng.ShortestPath(context.Background(), "A", "B", 10)
	if err != nil {
		t.Fatalf("ShortestPath: %v", err)
	}
	if path.HopCount != 1 {
		t.Errorf("expected HopCount=1, got %d", path.HopCount)
	}
}

// TestShortestPathNoPath verifies that ShortestPath returns ErrNoPath when
// the two nodes are in disconnected components.
func TestShortestPathNoPath(t *testing.T) {
	principals := []model.Principal{
		{ID: "isolated-A", Kind: model.PrincipalKindIAMUser, ARN: "arn:iA"},
		{ID: "isolated-B", Kind: model.PrincipalKindIAMUser, ARN: "arn:iB"},
	}
	snap := makeSnapshot(principals, nil, nil)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	_, err = eng.ShortestPath(context.Background(), "isolated-A", "isolated-B", 10)
	if err == nil {
		t.Fatal("expected ErrNoPath for disconnected nodes, got nil")
	}
	if !errors.Is(err, graph.ErrNoPath) {
		t.Errorf("expected ErrNoPath, got: %v", err)
	}
}

// TestShortestPathNonexistentSource verifies that ShortestPath returns
// ErrNotFound when the source node does not exist.
func TestShortestPathNonexistentSource(t *testing.T) {
	principals := []model.Principal{
		{ID: "existing", Kind: model.PrincipalKindIAMUser, ARN: "arn:existing"},
	}
	snap := makeSnapshot(principals, nil, nil)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	_, err = eng.ShortestPath(context.Background(), "ghost", "existing", 5)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, graph.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestShortestPathNonexistentDestination verifies that ShortestPath returns
// ErrNotFound when the destination node does not exist.
func TestShortestPathNonexistentDestination(t *testing.T) {
	principals := []model.Principal{
		{ID: "src", Kind: model.PrincipalKindIAMUser, ARN: "arn:src"},
	}
	snap := makeSnapshot(principals, nil, nil)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	_, err = eng.ShortestPath(context.Background(), "src", "nowhere", 5)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, graph.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestShortestPathInvalidMaxHops verifies that ShortestPath with maxHops=0
// returns ErrInvalidInput.
func TestShortestPathInvalidMaxHops(t *testing.T) {
	principals := []model.Principal{
		{ID: "p-sp", Kind: model.PrincipalKindIAMUser, ARN: "arn:p-sp"},
		{ID: "q-sp", Kind: model.PrincipalKindIAMUser, ARN: "arn:q-sp"},
	}
	snap := makeSnapshot(principals, nil, nil)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	_, err = eng.ShortestPath(context.Background(), "p-sp", "q-sp", 0)
	if err == nil {
		t.Fatal("expected ErrInvalidInput for maxHops=0, got nil")
	}
	if !errors.Is(err, graph.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

// TestNeighborsFiltersKind verifies that Neighbors with a specific EdgeKind
// filter only returns nodes reached via edges of that kind.
func TestNeighborsFiltersKind(t *testing.T) {
	principals := []model.Principal{
		{ID: "hub", Kind: model.PrincipalKindIAMUser, ARN: "arn:hub"},
		{ID: "role-target", Kind: model.PrincipalKindIAMRole, ARN: "arn:role-target"},
	}
	resources := []model.Resource{
		{ID: "policy-node", ARN: "arn:policy", Kind: "IAMPolicy", IsSensitive: false},
	}
	edges := []model.Edge{
		// ASSUMES_ROLE to role-target
		{ID: "ar1", FromNodeID: "hub", ToNodeID: "role-target", Kind: model.EdgeKindAssumesRole, Weight: 1},
		// ATTACHED_POLICY to policy-node
		{ID: "ap1", FromNodeID: "hub", ToNodeID: "policy-node", Kind: model.EdgeKindAttachedPolicy, Weight: 1},
	}

	snap := makeSnapshot(principals, resources, edges)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx := context.Background()
	// Only follow ASSUMES_ROLE edges.
	neighbors, err := eng.Neighbors(ctx, "hub", []model.EdgeKind{model.EdgeKindAssumesRole})
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if len(neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(neighbors))
	}
	if neighbors[0].ID != "role-target" {
		t.Errorf("expected neighbor ID=role-target, got %s", neighbors[0].ID)
	}
}

// TestNeighborsAllKinds verifies that passing an empty edgeKinds slice
// returns all adjacent nodes regardless of edge kind.
func TestNeighborsAllKinds(t *testing.T) {
	principals := []model.Principal{
		{ID: "hub2", Kind: model.PrincipalKindIAMUser, ARN: "arn:hub2"},
		{ID: "role-n2", Kind: model.PrincipalKindIAMRole, ARN: "arn:role-n2"},
	}
	resources := []model.Resource{
		{ID: "pol-n2", ARN: "arn:pol-n2", Kind: "IAMPolicy"},
	}
	edges := []model.Edge{
		{ID: "ar2", FromNodeID: "hub2", ToNodeID: "role-n2", Kind: model.EdgeKindAssumesRole, Weight: 1},
		{ID: "ap2", FromNodeID: "hub2", ToNodeID: "pol-n2", Kind: model.EdgeKindAttachedPolicy, Weight: 1},
	}

	snap := makeSnapshot(principals, resources, edges)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	neighbors, err := eng.Neighbors(context.Background(), "hub2", nil)
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if len(neighbors) != 2 {
		t.Errorf("expected 2 neighbors, got %d", len(neighbors))
	}
}

// TestNeighborsNonexistentNode verifies that Neighbors returns ErrNotFound
// when the given node ID does not exist.
func TestNeighborsNonexistentNode(t *testing.T) {
	snap := makeSnapshot(nil, nil, nil)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	_, err = eng.Neighbors(context.Background(), "ghost-node", nil)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, graph.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestNodeAndEdgeCount verifies that NodeCount and EdgeCount return the
// correct values after engine construction.
func TestNodeAndEdgeCount(t *testing.T) {
	principals := []model.Principal{
		{ID: "nc-user", Kind: model.PrincipalKindIAMUser, ARN: "arn:nc-user"},
	}
	resources := []model.Resource{
		{ID: "nc-res", ARN: "arn:nc-res", Kind: "IAMRole", IsSensitive: true},
	}
	edges := []model.Edge{
		{ID: "nc-edge", FromNodeID: "nc-user", ToNodeID: "nc-res", Kind: model.EdgeKindAllowsAction, Weight: 1},
	}

	snap := makeSnapshot(principals, resources, edges)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if eng.NodeCount() < 2 {
		t.Errorf("expected NodeCount >= 2, got %d", eng.NodeCount())
	}
	if eng.EdgeCount() < 1 {
		t.Errorf("expected EdgeCount >= 1, got %d", eng.EdgeCount())
	}
}

// TestNewEngineNilSnapshot verifies that NewEngine returns ErrInvalidInput
// when a nil snapshot is passed.
func TestNewEngineNilSnapshot(t *testing.T) {
	_, err := graph.NewEngine(nil)
	if err == nil {
		t.Fatal("expected error for nil snapshot, got nil")
	}
	if !errors.Is(err, graph.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}
