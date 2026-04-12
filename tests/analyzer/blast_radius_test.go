package analyzer_test

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/analyzer"
	"github.com/JamesOlaitan/accessgraph/internal/graph"
	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// Test-graph construction helper

// buildEngineFromPaths builds a graph.Engine from a set of pre-described paths.
//
// Parameters:
//   - principalIDs: IDs of principals to add as IAMUser nodes.
//   - sensitiveResourceIDs: IDs of resources to mark IsSensitive=true.
//   - extraResourceIDs: IDs of resources that are NOT sensitive (used for
//     PctEnvironmentReachable denominator).
//   - edges: directed edges wiring the graph.
//
// All nodes referenced in edges but absent from the principal/resource lists
// are still inserted by the engine's addEdge logic.
func buildEngineFromPaths(
	principalIDs []string,
	sensitiveResourceIDs []string,
	extraResourceIDs []string,
	edges []model.Edge,
) *graph.Engine {
	snap := &model.Snapshot{
		ID:    "analyzer-snap",
		Label: "analyzer-test",
	}

	for _, id := range principalIDs {
		snap.Principals = append(snap.Principals, &model.Principal{
			ID:         id,
			SnapshotID: snap.ID,
			Kind:       model.PrincipalKindIAMUser,
			ARN:        "arn:aws:iam::1:user/" + id,
			AccountID:  "1",
		})
	}

	for _, id := range sensitiveResourceIDs {
		snap.Resources = append(snap.Resources, &model.Resource{
			ID:          id,
			SnapshotID:  snap.ID,
			ARN:         "arn:aws:iam::1:role/" + id,
			Kind:        "IAMRole",
			IsSensitive: true,
		})
	}

	for _, id := range extraResourceIDs {
		snap.Resources = append(snap.Resources, &model.Resource{
			ID:          id,
			SnapshotID:  snap.ID,
			ARN:         "arn:aws:ec2::1:instance/" + id,
			Kind:        "EC2Resource",
			IsSensitive: false,
		})
	}

	for i := range edges {
		e := edges[i]
		e.SnapshotID = snap.ID
		snap.Edges = append(snap.Edges, &e)
	}

	eng, err := graph.NewEngine(snap)
	if err != nil {
		// Panic is acceptable here: if the engine cannot be built, the test
		// setup is broken and we want an immediate, loud failure.
		panic("buildEngineFromPaths: NewEngine failed: " + err.Error())
	}
	return eng
}

// TestAnalyzeReachableCount

// TestAnalyzeReachableCount verifies that BlastRadiusReport.ReachableResourceCount
// equals the number of distinct sensitive resources reachable from the principal.
func TestAnalyzeReachableCount(t *testing.T) {
	eng := buildEngineFromPaths(
		[]string{"user-rc"},
		[]string{"sens-1", "sens-2", "sens-3"},
		nil,
		[]model.Edge{
			{ID: "e1", FromNodeID: "user-rc", ToNodeID: "sens-1", Kind: model.EdgeKindAllowsAction, Weight: 1},
			{ID: "e2", FromNodeID: "user-rc", ToNodeID: "sens-2", Kind: model.EdgeKindAllowsAction, Weight: 1},
			{ID: "e3", FromNodeID: "user-rc", ToNodeID: "sens-3", Kind: model.EdgeKindAllowsAction, Weight: 1},
		},
	)

	a := analyzer.NewAnalyzer()
	report, err := a.Analyze(context.Background(), eng, "snap-test", "user-rc", 5)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.ReachableResourceCount != 3 {
		t.Errorf("expected ReachableResourceCount=3, got %d", report.ReachableResourceCount)
	}
}

// TestAnalyzePctEnvironment

// TestAnalyzePctEnvironment verifies that PctEnvironmentReachable ≈ 20.0
// when 2 of 10 total graph nodes are reachable sensitive resources.
func TestAnalyzePctEnvironment(t *testing.T) {
	// 10 total resources; 2 are sensitive and reachable.
	// We add 8 extra non-sensitive resources + user + 2 sensitive = 11 nodes.
	// PctEnvironmentReachable = 2 / nodeCount * 100.
	extras := []string{"e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8"}
	eng := buildEngineFromPaths(
		[]string{"user-pct"},
		[]string{"s1", "s2"},
		extras,
		[]model.Edge{
			{ID: "pe1", FromNodeID: "user-pct", ToNodeID: "s1", Kind: model.EdgeKindAllowsAction, Weight: 1},
			{ID: "pe2", FromNodeID: "user-pct", ToNodeID: "s2", Kind: model.EdgeKindAllowsAction, Weight: 1},
		},
	)

	a := analyzer.NewAnalyzer()
	report, err := a.Analyze(context.Background(), eng, "snap-test", "user-pct", 5)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	nodeCount := eng.NodeCount()
	expected := float64(2) / float64(nodeCount) * 100.0
	if math.Abs(float64(report.PctEnvironmentReachable)-expected) > 0.01 {
		t.Errorf("PctEnvironmentReachable = %.4f, want %.4f", float64(report.PctEnvironmentReachable), expected)
	}
}

// TestAnalyzeMinHopToAdmin

// TestAnalyzeMinHopToAdmin verifies that MinHopToAdmin equals the minimum
// HopCount among paths where IsPrivilegeEscalation is true. When no escalation
// path exists, MinHopToAdmin must be -1 regardless of other paths.
func TestAnalyzeMinHopToAdmin(t *testing.T) {
	// Chain: user → roleA → roleB → adminRole (3 hops via ASSUMES_ROLE / ALLOWS_ACTION).
	// roleA and roleB are intermediary principals (not sensitive resources).
	// None of the edges are escalation edges (no CAN_PASS_ROLE, CAN_CREATE_KEY,
	// or escalation_primitive metadata), so IsPrivilegeEscalation is false on
	// all paths and MinHopToAdmin must be -1.
	eng := buildEngineFromPaths(
		[]string{"user-mh", "roleA-mh", "roleB-mh"},
		[]string{"adminRole-mh"},
		nil,
		[]model.Edge{
			{ID: "mh1", FromNodeID: "user-mh", ToNodeID: "roleA-mh", Kind: model.EdgeKindAssumesRole, Weight: 1},
			{ID: "mh2", FromNodeID: "roleA-mh", ToNodeID: "roleB-mh", Kind: model.EdgeKindAssumesRole, Weight: 1},
			{ID: "mh3", FromNodeID: "roleB-mh", ToNodeID: "adminRole-mh", Kind: model.EdgeKindAllowsAction, Weight: 1},
		},
	)

	a := analyzer.NewAnalyzer()
	report, err := a.Analyze(context.Background(), eng, "snap-test", "user-mh", 10)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.MinHopToAdmin != -1 {
		t.Errorf("expected MinHopToAdmin=-1 (no escalation paths), got %d", report.MinHopToAdmin)
	}
}

// TestAnalyzeNoReachableResources

// TestAnalyzeNoReachableResources verifies that when the principal cannot
// reach any sensitive resource the report shows count=0 and MinHopToAdmin=-1.
func TestAnalyzeNoReachableResources(t *testing.T) {
	eng := buildEngineFromPaths(
		[]string{"user-none"},
		nil, // no sensitive resources
		nil,
		nil, // no edges
	)

	a := analyzer.NewAnalyzer()
	report, err := a.Analyze(context.Background(), eng, "snap-test", "user-none", 5)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.ReachableResourceCount != 0 {
		t.Errorf("expected ReachableResourceCount=0, got %d", report.ReachableResourceCount)
	}
	if report.MinHopToAdmin != -1 {
		t.Errorf("expected MinHopToAdmin=-1, got %d", report.MinHopToAdmin)
	}
}

// TestAnalyzePathsSortedByHopCount

// TestAnalyzePathsSortedByHopCount verifies that Paths in the result are
// sorted by HopCount ascending.
func TestAnalyzePathsSortedByHopCount(t *testing.T) {
	// Three sensitive resources at hop distances 3, 1, and 2 from the user.
	eng := buildEngineFromPaths(
		[]string{"user-sort", "role-mid"},
		[]string{"sens-h1", "sens-h2", "sens-h3"},
		nil,
		[]model.Edge{
			// 1-hop path to sens-h1
			{ID: "sort-e1", FromNodeID: "user-sort", ToNodeID: "sens-h1", Kind: model.EdgeKindAllowsAction, Weight: 1},
			// 2-hop path: user-sort → role-mid → sens-h2
			{ID: "sort-e2", FromNodeID: "user-sort", ToNodeID: "role-mid", Kind: model.EdgeKindAssumesRole, Weight: 1},
			{ID: "sort-e3", FromNodeID: "role-mid", ToNodeID: "sens-h2", Kind: model.EdgeKindAllowsAction, Weight: 1},
			// 3-hop path: user-sort → role-mid → intermediary → sens-h3
			{ID: "sort-e4", FromNodeID: "role-mid", ToNodeID: "intermediary-s", Kind: model.EdgeKindAssumesRole, Weight: 1},
			{ID: "sort-e5", FromNodeID: "intermediary-s", ToNodeID: "sens-h3", Kind: model.EdgeKindAllowsAction, Weight: 1},
		},
	)

	a := analyzer.NewAnalyzer()
	report, err := a.Analyze(context.Background(), eng, "snap-test", "user-sort", 10)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(report.Paths) < 3 {
		t.Fatalf("expected at least 3 paths, got %d", len(report.Paths))
	}
	for i := 1; i < len(report.Paths); i++ {
		if report.Paths[i].HopCount < report.Paths[i-1].HopCount {
			t.Errorf("paths not sorted: Paths[%d].HopCount=%d < Paths[%d].HopCount=%d",
				i, report.Paths[i].HopCount, i-1, report.Paths[i-1].HopCount)
		}
	}
}

// TestAnalyzeInvalidPrincipalID

// TestAnalyzeInvalidPrincipalID verifies that Analyze returns ErrInvalidInput
// when the principal ID is an empty string.
func TestAnalyzeInvalidPrincipalID(t *testing.T) {
	eng := buildEngineFromPaths([]string{"u"}, nil, nil, nil)

	a := analyzer.NewAnalyzer()
	_, err := a.Analyze(context.Background(), eng, "snap-test", "", 5)
	if err == nil {
		t.Fatal("expected ErrInvalidInput for empty principalID, got nil")
	}
	if !errors.Is(err, analyzer.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

// TestAnalyzeInvalidMaxHops

// TestAnalyzeInvalidMaxHops verifies that Analyze returns ErrInvalidInput
// when maxHops is 0.
func TestAnalyzeInvalidMaxHops(t *testing.T) {
	eng := buildEngineFromPaths([]string{"u-mh"}, nil, nil, nil)

	a := analyzer.NewAnalyzer()
	_, err := a.Analyze(context.Background(), eng, "snap-test", "u-mh", 0)
	if err == nil {
		t.Fatal("expected ErrInvalidInput for maxHops=0, got nil")
	}
	if !errors.Is(err, analyzer.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

// TestAnalyzeNonexistentPrincipal

// TestAnalyzeNonexistentPrincipal verifies that Analyze returns ErrNotFound
// when the requested principal does not exist in the graph.
func TestAnalyzeNonexistentPrincipal(t *testing.T) {
	eng := buildEngineFromPaths([]string{"existing"}, nil, nil, nil)

	a := analyzer.NewAnalyzer()
	_, err := a.Analyze(context.Background(), eng, "snap-test", "ghost-principal", 5)
	if err == nil {
		t.Fatal("expected ErrNotFound for non-existent principal, got nil")
	}
	if !errors.Is(err, analyzer.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestAnalyzeDistinctPathCount

// TestAnalyzeDistinctPathCount verifies that DistinctPathCount equals the
// total number of attack paths returned by BFS.
func TestAnalyzeDistinctPathCount(t *testing.T) {
	eng := buildEngineFromPaths(
		[]string{"user-dpc"},
		[]string{"r1", "r2"},
		nil,
		[]model.Edge{
			{ID: "dpc1", FromNodeID: "user-dpc", ToNodeID: "r1", Kind: model.EdgeKindAllowsAction, Weight: 1},
			{ID: "dpc2", FromNodeID: "user-dpc", ToNodeID: "r2", Kind: model.EdgeKindAllowsAction, Weight: 1},
		},
	)

	a := analyzer.NewAnalyzer()
	report, err := a.Analyze(context.Background(), eng, "snap-test", "user-dpc", 5)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.DistinctPathCount != len(report.Paths) {
		t.Errorf("DistinctPathCount=%d does not match len(Paths)=%d",
			report.DistinctPathCount, len(report.Paths))
	}
}

// TestClassifySensitiveResources

// TestClassifySensitiveResources is a table-driven test verifying that
// ClassifySensitiveResources marks the right resources.
func TestClassifySensitiveResources(t *testing.T) {
	tests := []struct {
		name          string
		resource      model.Resource
		wantSensitive bool
	}{
		{
			name: "AdministratorAccess in ARN",
			resource: model.Resource{
				ID:   "r-admin",
				ARN:  "arn:aws:iam::aws:policy/AdministratorAccess",
				Kind: "IAMPolicy",
			},
			wantSensitive: true,
		},
		{
			name: "generic IAMRole is not sensitive",
			resource: model.Resource{
				ID:   "r-role",
				ARN:  "arn:aws:iam::1:role/MyRole",
				Kind: "IAMRole",
			},
			wantSensitive: false,
		},
		{
			name: "admin-named IAMRole is sensitive",
			resource: model.Resource{
				ID:   "r-admin-role",
				ARN:  "arn:aws:iam::1:role/admin",
				Kind: "IAMRole",
			},
			wantSensitive: true,
		},
		{
			name: ":secret: in ARN",
			resource: model.Resource{
				ID:   "r-secret",
				ARN:  "arn:aws:secretsmanager::1:secret:MySecret",
				Kind: "SecretsManagerSecret",
			},
			wantSensitive: true,
		},
		{
			name: "KMS key with :key/ in ARN",
			resource: model.Resource{
				ID:   "r-kms",
				ARN:  "arn:aws:kms::1:key/abc123",
				Kind: "KMSKey",
			},
			wantSensitive: true,
		},
		{
			name: "plain EC2 instance is not sensitive",
			resource: model.Resource{
				ID:   "r-ec2",
				ARN:  "arn:aws:ec2::1:instance/i-abc",
				Kind: "EC2Resource",
			},
			wantSensitive: false,
		},
		{
			name: "S3 bucket is not sensitive",
			resource: model.Resource{
				ID:   "r-s3",
				ARN:  "arn:aws:s3:::my-ordinary-bucket",
				Kind: "S3Bucket",
			},
			wantSensitive: false,
		},
		{
			name: "ARN with non-exact admin substring is not sensitive",
			resource: model.Resource{
				ID:   "r-admin-arn",
				ARN:  "arn:aws:iam::1:policy/MyAdminPolicy",
				Kind: "IAMPolicy",
			},
			wantSensitive: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := tc.resource
			snap := &model.Snapshot{
				ID:        "classify-snap",
				Resources: []*model.Resource{&r},
			}
			if err := analyzer.ClassifySensitiveResources(snap); err != nil {
				t.Fatalf("ClassifySensitiveResources: %v", err)
			}
			if r.IsSensitive != tc.wantSensitive {
				t.Errorf("IsSensitive=%v, want %v (ARN=%s Kind=%s)",
					r.IsSensitive, tc.wantSensitive, r.ARN, r.Kind)
			}
		})
	}
}

// TestClassifySensitiveResourcesAdminEquivalenceJoin verifies that the
// classifier marks Resources as sensitive when a Policy with the same ARN
// is admin-equivalent, without breaking existing heuristic rules.
func TestClassifySensitiveResourcesAdminEquivalenceJoin(t *testing.T) {
	snap := &model.Snapshot{
		ID: "admin-equiv-sensitivity-snap",
		Policies: []*model.Policy{
			{
				ID:  "pol-admin",
				ARN: "arn:aws:iam::123456789012:policy/privesc-admin",
				Permissions: []*model.Permission{
					{Action: "iam:*", ResourcePattern: "*", Effect: "Allow"},
				},
			},
			{
				ID:  "pol-readonly",
				ARN: "arn:aws:iam::123456789012:policy/readonly",
				Permissions: []*model.Permission{
					{Action: "s3:Get*", ResourcePattern: "*", Effect: "Allow"},
				},
			},
		},
		Resources: []*model.Resource{
			{
				ID:   "r-admin-pol",
				ARN:  "arn:aws:iam::123456789012:policy/privesc-admin",
				Kind: "IAMPolicy",
			},
			{
				ID:   "r-readonly-pol",
				ARN:  "arn:aws:iam::123456789012:policy/readonly",
				Kind: "IAMPolicy",
			},
			{
				ID:   "r-bucket",
				ARN:  "arn:aws:s3:::data-bucket",
				Kind: "S3Bucket",
			},
			{
				ID:   "r-admin-role",
				ARN:  "arn:aws:iam::123456789012:role/admin",
				Kind: "IAMRole",
			},
		},
	}

	if err := analyzer.ClassifySensitiveResources(snap); err != nil {
		t.Fatalf("ClassifySensitiveResources: %v", err)
	}

	cases := []struct {
		id   string
		want bool
	}{
		{"r-admin-pol", true},
		{"r-readonly-pol", false},
		{"r-bucket", false},
		{"r-admin-role", true},
	}
	for _, tc := range cases {
		for _, r := range snap.Resources {
			if r.ID == tc.id {
				if r.IsSensitive != tc.want {
					t.Errorf("Resource %s: IsSensitive=%v, want %v (ARN=%s)",
						tc.id, r.IsSensitive, tc.want, r.ARN)
				}
			}
		}
	}
}

// TestClassifySensitiveResourcesNilSnapshot verifies that
// ClassifySensitiveResources returns ErrInvalidInput for a nil snapshot.
func TestClassifySensitiveResourcesNilSnapshot(t *testing.T) {
	if err := analyzer.ClassifySensitiveResources(nil); err == nil {
		t.Fatal("expected ErrInvalidInput for nil snapshot, got nil")
	}
}

// TestAnalyzeReportPrincipalID verifies that the PrincipalID in the returned
// report matches the principalID argument passed to Analyze.
func TestAnalyzeReportPrincipalID(t *testing.T) {
	eng := buildEngineFromPaths([]string{"user-pid"}, nil, nil, nil)

	a := analyzer.NewAnalyzer()
	report, err := a.Analyze(context.Background(), eng, "snap-test", "user-pid", 5)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.PrincipalID != "user-pid" {
		t.Errorf("report.PrincipalID=%q, want \"user-pid\"", report.PrincipalID)
	}
}

// TestAnalyzePathsNeverNil verifies that Paths in the report is never nil,
// even when no sensitive resources are reachable.
func TestAnalyzePathsNeverNil(t *testing.T) {
	eng := buildEngineFromPaths([]string{"user-nn"}, nil, nil, nil)

	a := analyzer.NewAnalyzer()
	report, err := a.Analyze(context.Background(), eng, "snap-test", "user-nn", 5)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.Paths == nil {
		t.Error("expected non-nil Paths slice, got nil")
	}
}
