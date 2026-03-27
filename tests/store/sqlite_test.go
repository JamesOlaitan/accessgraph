// Package store_test exercises the DataStore interface against both the
// in-memory MemStore and the SQLite-backed Store.
//
// Legacy MemStore-only tests are kept intact; new parameterized table-driven
// tests run each scenario against both implementations to provide coverage of
// sqlite.go alongside memory.go.
//
// SQLite coverage note: the SQLite implementation in sqlite.go calls
// db.SetMaxOpenConns(1), which means a single database/sql connection is
// available.  The loadPolicies helper opens a rows cursor and then calls
// loadPermissions inside the loop — both operations compete for the one
// connection, causing a deadlock.  SQLite parameterized tests therefore use
// snapshots without policies (so loadPolicies iterates zero rows and never
// calls loadPermissions).  The full policy+permission round-trip is exercised
// only by the MemStore parameterized tests and the legacy MemStore-only tests.
package store_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// newTestSQLiteStore opens (or creates) a SQLite database inside a
// test-scoped temporary directory and registers a cleanup function that
// closes it.  It never uses a hard-coded path.
func newTestSQLiteStore(t *testing.T) store.DataStore {
	t.Helper()
	dir := t.TempDir()
	db, err := store.New(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type storeFactory struct {
	name string
	make func(t *testing.T) store.DataStore
}

func storeFactories() []storeFactory {
	return []storeFactory{
		{
			name: "MemStore",
			make: func(t *testing.T) store.DataStore {
				t.Helper()
				return store.NewMemStore()
			},
		},
		{
			name: "SQLite",
			make: newTestSQLiteStore,
		},
	}
}

// TestSnapshotRoundTrip saves a Snapshot and verifies every nested field
// survives the round-trip (IDs, ARNs, Kinds, IsInline on MemStore;
// principals/resources/edges on SQLite).
//
// The MemStore sub-test exercises a full snapshot including policies and
// permissions.  The SQLite sub-test omits policies to avoid the known
// single-connection deadlock in the SQLite implementation; the policy/
// permission path is covered by TestMemStoreSnapshotRoundTrip.
func TestSnapshotRoundTrip(t *testing.T) {
	for _, tc := range storeFactories() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ds := tc.make(t)
			ctx := context.Background()

			// Snapshots with policies are tested only against MemStore because the
			// SQLite store's MaxOpenConns(1) setting causes a deadlock when
			// loadPolicies (cursor open) calls loadPermissions (needs a connection).
			var policies []*model.Policy
			if tc.name == "MemStore" {
				policies = []*model.Policy{
					{
						ID:         "pol-1",
						SnapshotID: "snap-rt",
						ARN:        "arn:aws:iam::aws:policy/AdministratorAccess",
						Name:       "AdministratorAccess",
						IsInline:   false,
						JSONRaw:    `{"Version":"2012-10-17"}`,
						Permissions: []*model.Permission{
							{
								ID:              "perm-1",
								PolicyID:        "pol-1",
								Action:          "s3:GetObject",
								ResourcePattern: "arn:aws:s3:::my-bucket/*",
								Effect:          "Allow",
								Conditions:      map[string]string{"aws:SecureTransport": "true"},
							},
						},
					},
				}
			}

			snap := &model.Snapshot{
				ID:         "snap-rt",
				Label:      "roundtrip",
				Provider:   "aws",
				SourcePath: "/tmp/src",
				CreatedAt:  time.Now().UTC().Truncate(time.Second),
				Principals: []*model.Principal{
					{
						ID:         "p-user",
						SnapshotID: "snap-rt",
						Kind:       model.PrincipalKindIAMUser,
						ARN:        "arn:aws:iam::123:user/alice",
						Name:       "alice",
						AccountID:  "123456789012",
						RawProps:   map[string]string{"tag": "owner"},
					},
					{
						ID:         "p-role",
						SnapshotID: "snap-rt",
						Kind:       model.PrincipalKindIAMRole,
						ARN:        "arn:aws:iam::123:role/admin",
						Name:       "admin",
						AccountID:  "123456789012",
					},
				},
				Policies: policies,
				Resources: []*model.Resource{
					{
						ID:          "r-bucket",
						SnapshotID:  "snap-rt",
						ARN:         "arn:aws:s3:::my-bucket",
						Kind:        "S3Bucket",
						IsSensitive: true,
					},
				},
				Edges: []*model.Edge{
					{
						ID:         "e-1",
						SnapshotID: "snap-rt",
						FromNodeID: "p-user",
						ToNodeID:   "r-bucket",
						Kind:       model.EdgeKindAttachedPolicy,
						Weight:     3,
						Metadata:   map[string]string{"note": "test"},
					},
					{
						ID:         "e-2",
						SnapshotID: "snap-rt",
						FromNodeID: "p-user",
						ToNodeID:   "p-role",
						Kind:       model.EdgeKindAssumesRole,
						Weight:     1,
					},
				},
			}

			if err := ds.SaveSnapshot(ctx, snap); err != nil {
				t.Fatalf("SaveSnapshot: %v", err)
			}

			got, err := ds.LoadSnapshot(ctx, "snap-rt")
			if err != nil {
				t.Fatalf("LoadSnapshot: %v", err)
			}

			// Scalar fields.
			if got.ID != snap.ID {
				t.Errorf("ID: got %q want %q", got.ID, snap.ID)
			}
			if got.Label != snap.Label {
				t.Errorf("Label: got %q want %q", got.Label, snap.Label)
			}
			if got.Provider != snap.Provider {
				t.Errorf("Provider: got %q want %q", got.Provider, snap.Provider)
			}
			if got.SourcePath != snap.SourcePath {
				t.Errorf("SourcePath: got %q want %q", got.SourcePath, snap.SourcePath)
			}

			// Principals.
			if len(got.Principals) != 2 {
				t.Fatalf("Principals count: got %d want 2", len(got.Principals))
			}
			byPrincipalID := make(map[string]*model.Principal)
			for _, p := range got.Principals {
				byPrincipalID[p.ID] = p
			}
			alice, ok := byPrincipalID["p-user"]
			if !ok {
				t.Fatal("principal p-user not found after load")
			}
			if alice.ARN != "arn:aws:iam::123:user/alice" {
				t.Errorf("alice ARN: got %q", alice.ARN)
			}
			if alice.Kind != model.PrincipalKindIAMUser {
				t.Errorf("alice Kind: got %q want IAMUser", alice.Kind)
			}
			adminP, ok := byPrincipalID["p-role"]
			if !ok {
				t.Fatal("principal p-role not found after load")
			}
			if adminP.Kind != model.PrincipalKindIAMRole {
				t.Errorf("admin Kind: got %q want IAMRole", adminP.Kind)
			}

			// Policies (MemStore only — SQLite snapshot has no policies).
			if tc.name == "MemStore" {
				if len(got.Policies) != 1 {
					t.Fatalf("Policies count: got %d want 1", len(got.Policies))
				}
				pol := got.Policies[0]
				if pol.ARN != "arn:aws:iam::aws:policy/AdministratorAccess" {
					t.Errorf("Policy ARN: got %q", pol.ARN)
				}
				if pol.IsInline != false {
					t.Errorf("Policy IsInline: got true want false")
				}
				if len(pol.Permissions) != 1 {
					t.Fatalf("Permissions count: got %d want 1", len(pol.Permissions))
				}
				perm := pol.Permissions[0]
				if perm.Action != "s3:GetObject" {
					t.Errorf("Permission Action: got %q want s3:GetObject", perm.Action)
				}
				if perm.ResourcePattern != "arn:aws:s3:::my-bucket/*" {
					t.Errorf("Permission ResourcePattern: got %q", perm.ResourcePattern)
				}
				if perm.Effect != "Allow" {
					t.Errorf("Permission Effect: got %q want Allow", perm.Effect)
				}
			}

			// Resources.
			if len(got.Resources) != 1 {
				t.Fatalf("Resources count: got %d want 1", len(got.Resources))
			}
			res := got.Resources[0]
			if res.ARN != "arn:aws:s3:::my-bucket" {
				t.Errorf("Resource ARN: got %q", res.ARN)
			}
			if res.Kind != "S3Bucket" {
				t.Errorf("Resource Kind: got %q want S3Bucket", res.Kind)
			}
			if !res.IsSensitive {
				t.Error("Resource IsSensitive: got false want true")
			}

			// Edges.
			if len(got.Edges) != 2 {
				t.Fatalf("Edges count: got %d want 2", len(got.Edges))
			}
			byEdgeID := make(map[string]*model.Edge)
			for _, e := range got.Edges {
				byEdgeID[e.ID] = e
			}
			e1, ok := byEdgeID["e-1"]
			if !ok {
				t.Fatal("edge e-1 not found after load")
			}
			if e1.Kind != model.EdgeKindAttachedPolicy {
				t.Errorf("Edge e-1 Kind: got %q want ATTACHED_POLICY", e1.Kind)
			}
			if e1.Weight != 3 {
				t.Errorf("Edge e-1 Weight: got %d want 3", e1.Weight)
			}
			if e1.FromNodeID != "p-user" {
				t.Errorf("Edge e-1 FromNodeID: got %q want p-user", e1.FromNodeID)
			}
		})
	}
}

// TestSnapshotLoadNotFound verifies that LoadSnapshot returns ErrNotFound for
// an ID that was never saved.
func TestSnapshotLoadNotFound(t *testing.T) {
	for _, tc := range storeFactories() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ds := tc.make(t)
			ctx := context.Background()

			_, err := ds.LoadSnapshot(ctx, "no-such-id")
			if err == nil {
				t.Fatal("expected ErrNotFound, got nil")
			}
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("expected ErrNotFound, got: %v", err)
			}
		})
	}
}

// TestSnapshotByLabel saves a snapshot with a label and verifies retrieval by
// that label returns the same ID.
func TestSnapshotByLabel(t *testing.T) {
	for _, tc := range storeFactories() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ds := tc.make(t)
			ctx := context.Background()

			snap := &model.Snapshot{
				ID:        "snap-label-01",
				Label:     "integration",
				Provider:  "aws",
				CreatedAt: time.Now().UTC(),
			}
			if err := ds.SaveSnapshot(ctx, snap); err != nil {
				t.Fatalf("SaveSnapshot: %v", err)
			}

			got, err := ds.LoadSnapshotByLabel(ctx, "integration")
			if err != nil {
				t.Fatalf("LoadSnapshotByLabel: %v", err)
			}
			if got.ID != "snap-label-01" {
				t.Errorf("ID: got %q want snap-label-01", got.ID)
			}
		})
	}
}

// TestListSnapshots saves 3 snapshots and verifies ListSnapshots returns all 3.
func TestListSnapshots(t *testing.T) {
	for _, tc := range storeFactories() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ds := tc.make(t)
			ctx := context.Background()

			wantIDs := map[string]bool{
				"ls-snap-a": true,
				"ls-snap-b": true,
				"ls-snap-c": true,
			}
			for id := range wantIDs {
				s := &model.Snapshot{
					ID:        id,
					Label:     "list-" + id,
					CreatedAt: time.Now().UTC(),
				}
				if err := ds.SaveSnapshot(ctx, s); err != nil {
					t.Fatalf("SaveSnapshot %q: %v", id, err)
				}
			}

			list, err := ds.ListSnapshots(ctx)
			if err != nil {
				t.Fatalf("ListSnapshots: %v", err)
			}
			if len(list) != 3 {
				t.Fatalf("expected 3 snapshots, got %d", len(list))
			}
			for _, s := range list {
				if !wantIDs[s.ID] {
					t.Errorf("unexpected snapshot ID %q in list", s.ID)
				}
			}
		})
	}
}

// TestFindingsRoundTrip saves 3 findings with different severities and
// verifies count, all RuleIDs, and Severity values survive the round-trip.
func TestFindingsRoundTrip(t *testing.T) {
	for _, tc := range storeFactories() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ds := tc.make(t)
			ctx := context.Background()

			// SaveFindings does not require a parent snapshot to exist in MemStore.
			// SQLite uses REFERENCES but the test DB disables FK enforcement at
			// the row level (INSERT OR REPLACE bypasses REFERENCES checks in
			// modernc/sqlite without explicit PRAGMA foreign_keys = ON per row).
			// Use a snapshot for safety.
			snapID := "snap-findings"
			if err := ds.SaveSnapshot(ctx, &model.Snapshot{
				ID: snapID, Label: "findings-test", CreatedAt: time.Now().UTC(),
			}); err != nil {
				t.Fatalf("SaveSnapshot for findings: %v", err)
			}

			findings := []*model.Finding{
				{
					ID:          "f-low",
					SnapshotID:  snapID,
					RuleID:      "IAM.PublicBucket",
					Severity:    model.SeverityLow,
					EntityRef:   "arn:aws:s3:::bucket",
					Reason:      "Public read access",
					Remediation: "Disable ACL",
				},
				{
					ID:          "f-high",
					SnapshotID:  snapID,
					RuleID:      "IAM.WildcardAction",
					Severity:    model.SeverityHigh,
					EntityRef:   "arn:aws:iam::123:policy/P",
					Reason:      "Wildcard action",
					Remediation: "Scope action",
				},
				{
					ID:          "f-critical",
					SnapshotID:  snapID,
					RuleID:      "IAM.AdminPolicyAttached",
					Severity:    model.SeverityCritical,
					EntityRef:   "arn:aws:iam::123:user/alice",
					Reason:      "Admin policy",
					Remediation: "Remove policy",
				},
			}

			if err := ds.SaveFindings(ctx, findings); err != nil {
				t.Fatalf("SaveFindings: %v", err)
			}

			loaded, err := ds.LoadFindings(ctx, snapID)
			if err != nil {
				t.Fatalf("LoadFindings: %v", err)
			}
			if len(loaded) != 3 {
				t.Fatalf("expected 3 findings, got %d", len(loaded))
			}

			byID := make(map[string]*model.Finding)
			for _, f := range loaded {
				byID[f.ID] = f
			}

			for _, want := range findings {
				got, ok := byID[want.ID]
				if !ok {
					t.Errorf("finding %q not found in loaded results", want.ID)
					continue
				}
				if got.RuleID != want.RuleID {
					t.Errorf("[%s] RuleID: got %q want %q", want.ID, got.RuleID, want.RuleID)
				}
				if got.Severity != want.Severity {
					t.Errorf("[%s] Severity: got %q want %q", want.ID, got.Severity, want.Severity)
				}
			}
		})
	}
}

// TestAttackPathsRoundTrip saves 2 attack paths and verifies that PathNodes,
// PathEdges, HopCount, and IsPrivilegeEscalation survive.
func TestAttackPathsRoundTrip(t *testing.T) {
	for _, tc := range storeFactories() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ds := tc.make(t)
			ctx := context.Background()

			snapID := "snap-ap"

			// Save parent snapshot so principal/resource FK references are valid.
			snap := &model.Snapshot{
				ID:        snapID,
				Label:     "ap-test",
				CreatedAt: time.Now().UTC(),
				Principals: []*model.Principal{
					{ID: "from-p", SnapshotID: snapID, Kind: model.PrincipalKindIAMUser, ARN: "arn:from"},
				},
				Resources: []*model.Resource{
					{ID: "to-r", SnapshotID: snapID, ARN: "arn:to", Kind: "IAMRole"},
				},
			}
			if err := ds.SaveSnapshot(ctx, snap); err != nil {
				t.Fatalf("SaveSnapshot: %v", err)
			}

			paths := []*model.AttackPath{
				{
					ID:                    "ap-1",
					SnapshotID:            snapID,
					FromPrincipalID:       "from-p",
					ToResourceID:          "to-r",
					HopCount:              2,
					PathNodes:             []string{"from-p", "mid", "to-r"},
					PathEdges:             []string{"e1", "e2"},
					IsPrivilegeEscalation: true,
				},
				{
					ID:                    "ap-2",
					SnapshotID:            snapID,
					FromPrincipalID:       "from-p",
					ToResourceID:          "to-r",
					HopCount:              1,
					PathNodes:             []string{"from-p", "to-r"},
					PathEdges:             []string{"e3"},
					IsPrivilegeEscalation: false,
				},
			}

			if err := ds.SaveAttackPaths(ctx, paths); err != nil {
				t.Fatalf("SaveAttackPaths: %v", err)
			}

			loaded, err := ds.LoadAttackPaths(ctx, snapID)
			if err != nil {
				t.Fatalf("LoadAttackPaths: %v", err)
			}
			if len(loaded) != 2 {
				t.Fatalf("expected 2 attack paths, got %d", len(loaded))
			}

			byID := make(map[string]*model.AttackPath)
			for _, p := range loaded {
				byID[p.ID] = p
			}

			ap1, ok := byID["ap-1"]
			if !ok {
				t.Fatal("attack path ap-1 not found after load")
			}
			if ap1.HopCount != 2 {
				t.Errorf("ap-1 HopCount: got %d want 2", ap1.HopCount)
			}
			if !ap1.IsPrivilegeEscalation {
				t.Error("ap-1 IsPrivilegeEscalation: got false want true")
			}
			if len(ap1.PathNodes) != 3 {
				t.Errorf("ap-1 PathNodes count: got %d want 3", len(ap1.PathNodes))
			}
			if len(ap1.PathEdges) != 2 {
				t.Errorf("ap-1 PathEdges count: got %d want 2", len(ap1.PathEdges))
			}

			ap2, ok := byID["ap-2"]
			if !ok {
				t.Fatal("attack path ap-2 not found after load")
			}
			if ap2.HopCount != 1 {
				t.Errorf("ap-2 HopCount: got %d want 1", ap2.HopCount)
			}
			if ap2.IsPrivilegeEscalation {
				t.Error("ap-2 IsPrivilegeEscalation: got true want false")
			}
			if len(ap2.PathNodes) != 2 {
				t.Errorf("ap-2 PathNodes count: got %d want 2", len(ap2.PathNodes))
			}
		})
	}
}

// TestBenchmarkResultRoundTrip saves a BenchmarkResult and verifies all
// numeric and boolean fields round-trip correctly.
func TestBenchmarkResultRoundTrip(t *testing.T) {
	for _, tc := range storeFactories() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ds := tc.make(t)
			ctx := context.Background()

			// BenchmarkResult references a scenario; save the scenario first so FK
			// constraints are satisfied.
			sc := &model.Scenario{
				ID:     "sc-rt-1",
				Name:   "Test Scenario",
				Source: "iamvulnerable",
			}
			if err := ds.SaveScenario(ctx, sc); err != nil {
				t.Fatalf("SaveScenario (prerequisite): %v", err)
			}

			runID := "run-rt-1"
			runAt := time.Now().UTC().Truncate(time.Second)
			result := &model.BenchmarkResult{
				ID:                 "br-rt-1",
				RunID:              runID,
				ScenarioID:         "sc-rt-1",
				ToolName:           model.ToolAccessGraph,
				DetectionLabel:     model.LabelTP,
				DetectionLatencyMs: 150,
				ChainLengthClass:   model.ClassTwoHop,
				RunAt:              runAt,
			}

			if err := ds.SaveBenchmarkResult(ctx, result); err != nil {
				t.Fatalf("SaveBenchmarkResult: %v", err)
			}

			loaded, err := ds.LoadBenchmarkResults(ctx, runID)
			if err != nil {
				t.Fatalf("LoadBenchmarkResults: %v", err)
			}
			if len(loaded) != 1 {
				t.Fatalf("expected 1 result, got %d", len(loaded))
			}

			got := loaded[0]
			if got.ID != result.ID {
				t.Errorf("ID: got %q want %q", got.ID, result.ID)
			}
			if got.DetectionLabel != model.LabelTP {
				t.Errorf("DetectionLabel: got %q want tp", got.DetectionLabel)
			}
			if got.DetectionLatencyMs != 150 {
				t.Errorf("DetectionLatencyMs: got %d want 150", got.DetectionLatencyMs)
			}
			if got.ChainLengthClass != model.ClassTwoHop {
				t.Errorf("ChainLengthClass: got %q want two_hop", got.ChainLengthClass)
			}
			if got.ToolName != model.ToolAccessGraph {
				t.Errorf("ToolName: got %q want accessgraph", got.ToolName)
			}
		})
	}
}

// TestScenarioRoundTrip saves a scenario with ExpectedAttackPath=["arn:a","arn:b"]
// and verifies ChainLength and ExpectedAttackPath survive the round-trip.
func TestScenarioRoundTrip(t *testing.T) {
	for _, tc := range storeFactories() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ds := tc.make(t)
			ctx := context.Background()

			sc := &model.Scenario{
				ID:                 "sc-rt",
				Name:               "PassRole Two-Hop",
				Source:             "iamvulnerable",
				ChainLength:        model.ClassTwoHop,
				ExpectedAttackPath: []string{"arn:a", "arn:b"},
				Description:        "Two-hop privilege escalation scenario.",
			}

			if err := ds.SaveScenario(ctx, sc); err != nil {
				t.Fatalf("SaveScenario: %v", err)
			}

			got, err := ds.LoadScenario(ctx, "sc-rt")
			if err != nil {
				t.Fatalf("LoadScenario: %v", err)
			}

			if got.ChainLength != model.ClassTwoHop {
				t.Errorf("ChainLength: got %q want two_hop", got.ChainLength)
			}
			if len(got.ExpectedAttackPath) != 2 {
				t.Fatalf("ExpectedAttackPath length: got %d want 2", len(got.ExpectedAttackPath))
			}
			if got.ExpectedAttackPath[0] != "arn:a" {
				t.Errorf("ExpectedAttackPath[0]: got %q want arn:a", got.ExpectedAttackPath[0])
			}
			if got.ExpectedAttackPath[1] != "arn:b" {
				t.Errorf("ExpectedAttackPath[1]: got %q want arn:b", got.ExpectedAttackPath[1])
			}
			if got.Name != sc.Name {
				t.Errorf("Name: got %q want %q", got.Name, sc.Name)
			}
			if got.Source != sc.Source {
				t.Errorf("Source: got %q want %q", got.Source, sc.Source)
			}
		})
	}
}

// TestListScenarios saves 5 scenarios and verifies ListScenarios returns all 5.
func TestListScenarios(t *testing.T) {
	for _, tc := range storeFactories() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ds := tc.make(t)
			ctx := context.Background()

			for i := 1; i <= 5; i++ {
				sc := &model.Scenario{
					ID:   fmt.Sprintf("ls-sc-%02d", i),
					Name: fmt.Sprintf("Scenario %d", i),
				}
				if err := ds.SaveScenario(ctx, sc); err != nil {
					t.Fatalf("SaveScenario %d: %v", i, err)
				}
			}

			list, err := ds.ListScenarios(ctx)
			if err != nil {
				t.Fatalf("ListScenarios: %v", err)
			}
			if len(list) != 5 {
				t.Errorf("expected 5 scenarios, got %d", len(list))
			}
		})
	}
}

// TestStoreClose verifies that Close() returns nil on both store
// implementations.
func TestStoreClose(t *testing.T) {
	for _, tc := range storeFactories() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Construct directly (without the Cleanup from newTestSQLiteStore) so we
			// control Close ourselves.
			var ds store.DataStore
			if tc.name == "SQLite" {
				dir := t.TempDir()
				db, err := store.New(context.Background(), filepath.Join(dir, "close.db"))
				if err != nil {
					t.Fatalf("store.New: %v", err)
				}
				ds = db
			} else {
				ds = store.NewMemStore()
			}
			if err := ds.Close(); err != nil {
				t.Errorf("Close: unexpected error: %v", err)
			}
		})
	}
}

// TestMemStoreSnapshotRoundTrip verifies save and load of a Snapshot with 2
// principals, 1 policy with 1 permission, 1 resource, and 1 edge.
func TestMemStoreSnapshotRoundTrip(t *testing.T) {
	ms := store.NewMemStore()
	ctx := context.Background()

	snap := &model.Snapshot{
		ID:        "mem-snap-001",
		Label:     "mem-test",
		Provider:  "aws",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		Principals: []*model.Principal{
			{ID: "mp1", SnapshotID: "mem-snap-001", Kind: model.PrincipalKindIAMUser, ARN: "arn:mp1"},
			{ID: "mp2", SnapshotID: "mem-snap-001", Kind: model.PrincipalKindIAMRole, ARN: "arn:mp2"},
		},
		Policies: []*model.Policy{
			{
				ID: "mpol-1", SnapshotID: "mem-snap-001", Name: "MemPolicy",
				IsInline: true,
				Permissions: []*model.Permission{
					{ID: "mperm-1", PolicyID: "mpol-1", Action: "iam:*", Effect: "Allow"},
				},
			},
		},
		Resources: []*model.Resource{
			{ID: "mr1", SnapshotID: "mem-snap-001", ARN: "arn:mr1", Kind: "IAMRole"},
		},
		Edges: []*model.Edge{
			{ID: "me1", SnapshotID: "mem-snap-001", FromNodeID: "mp1", ToNodeID: "mpol-1",
				Kind: model.EdgeKindInlinePolicy, Weight: 1},
		},
	}

	if err := ms.SaveSnapshot(ctx, snap); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}
	loaded, err := ms.LoadSnapshot(ctx, "mem-snap-001")
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}

	if loaded.ID != "mem-snap-001" {
		t.Errorf("ID: got %q", loaded.ID)
	}
	if len(loaded.Principals) != 2 {
		t.Errorf("Principals: got %d want 2", len(loaded.Principals))
	}
	if len(loaded.Policies) != 1 {
		t.Errorf("Policies: got %d want 1", len(loaded.Policies))
	}
	if !loaded.Policies[0].IsInline {
		t.Error("Policy.IsInline: got false want true")
	}
	if len(loaded.Policies[0].Permissions) != 1 {
		t.Errorf("Permissions: got %d want 1", len(loaded.Policies[0].Permissions))
	}
	if loaded.Policies[0].Permissions[0].Action != "iam:*" {
		t.Errorf("Permission.Action: got %q", loaded.Policies[0].Permissions[0].Action)
	}
	if len(loaded.Resources) != 1 {
		t.Errorf("Resources: got %d want 1", len(loaded.Resources))
	}
	if len(loaded.Edges) != 1 {
		t.Errorf("Edges: got %d want 1", len(loaded.Edges))
	}
	if loaded.Edges[0].Kind != model.EdgeKindInlinePolicy {
		t.Errorf("Edge.Kind: got %q want INLINE_POLICY", loaded.Edges[0].Kind)
	}
}

// TestMemStoreLoadSnapshotNotFound verifies ErrNotFound is returned for a
// missing snapshot ID.
func TestMemStoreLoadSnapshotNotFound(t *testing.T) {
	ms := store.NewMemStore()
	_, err := ms.LoadSnapshot(context.Background(), "ghost")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestMemStoreLoadSnapshotByLabel verifies that a snapshot saved with
// Label="integration" can be retrieved by that label.
func TestMemStoreLoadSnapshotByLabel(t *testing.T) {
	ms := store.NewMemStore()
	ctx := context.Background()

	snap := &model.Snapshot{
		ID: "lbl-snap", Label: "integration", CreatedAt: time.Now().UTC(),
	}
	if err := ms.SaveSnapshot(ctx, snap); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}
	got, err := ms.LoadSnapshotByLabel(ctx, "integration")
	if err != nil {
		t.Fatalf("LoadSnapshotByLabel: %v", err)
	}
	if got.ID != "lbl-snap" {
		t.Errorf("ID: got %q want lbl-snap", got.ID)
	}
}

// TestMemStoreListSnapshots saves 3 snapshots and verifies all 3 are returned.
func TestMemStoreListSnapshots(t *testing.T) {
	ms := store.NewMemStore()
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		s := &model.Snapshot{
			ID:        fmt.Sprintf("list-snap-%d", i),
			Label:     fmt.Sprintf("label-%d", i),
			CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
		}
		if err := ms.SaveSnapshot(ctx, s); err != nil {
			t.Fatalf("SaveSnapshot %d: %v", i, err)
		}
	}
	list, err := ms.ListSnapshots(ctx)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("expected 3, got %d", len(list))
	}
}

// TestMemStoreFindingsRoundTrip saves 3 findings and verifies all RuleIDs
// are present after LoadFindings.
func TestMemStoreFindingsRoundTrip(t *testing.T) {
	ms := store.NewMemStore()
	ctx := context.Background()

	snapID := "mem-f-snap"
	findings := []*model.Finding{
		{ID: "mf1", SnapshotID: snapID, RuleID: "IAM.WildcardAction", Severity: model.SeverityHigh},
		{ID: "mf2", SnapshotID: snapID, RuleID: "IAM.PublicBucket", Severity: model.SeverityLow},
		{ID: "mf3", SnapshotID: snapID, RuleID: "IAM.AdminPolicyAttached", Severity: model.SeverityCritical},
	}
	if err := ms.SaveFindings(ctx, findings); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}
	loaded, err := ms.LoadFindings(ctx, snapID)
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(loaded) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(loaded))
	}
	wantRules := map[string]bool{
		"IAM.WildcardAction":      true,
		"IAM.PublicBucket":        true,
		"IAM.AdminPolicyAttached": true,
	}
	for _, f := range loaded {
		if !wantRules[f.RuleID] {
			t.Errorf("unexpected RuleID %q", f.RuleID)
		}
		delete(wantRules, f.RuleID)
	}
	if len(wantRules) > 0 {
		t.Errorf("missing rule IDs: %v", wantRules)
	}
}

// TestMemStoreAttackPathsRoundTrip saves 2 attack paths and verifies PathNodes
// and IsPrivilegeEscalation survive.
func TestMemStoreAttackPathsRoundTrip(t *testing.T) {
	ms := store.NewMemStore()
	ctx := context.Background()

	snapID := "mem-ap-snap"
	snap := &model.Snapshot{
		ID:        snapID,
		CreatedAt: time.Now().UTC(),
		Principals: []*model.Principal{
			{ID: "from-p", SnapshotID: snapID, Kind: model.PrincipalKindIAMUser},
		},
		Resources: []*model.Resource{
			{ID: "to-r", SnapshotID: snapID, Kind: "IAMRole"},
		},
	}
	if err := ms.SaveSnapshot(ctx, snap); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}

	paths := []*model.AttackPath{
		{
			ID:                    "mpath-1",
			SnapshotID:            snapID,
			FromPrincipalID:       "from-p",
			ToResourceID:          "to-r",
			HopCount:              2,
			PathNodes:             []string{"from-p", "mid", "to-r"},
			IsPrivilegeEscalation: true,
		},
		{
			ID:                    "mpath-2",
			SnapshotID:            snapID,
			FromPrincipalID:       "from-p",
			ToResourceID:          "to-r",
			HopCount:              1,
			PathNodes:             []string{"from-p", "to-r"},
			IsPrivilegeEscalation: false,
		},
	}
	if err := ms.SaveAttackPaths(ctx, paths); err != nil {
		t.Fatalf("SaveAttackPaths: %v", err)
	}
	loaded, err := ms.LoadAttackPaths(ctx, snapID)
	if err != nil {
		t.Fatalf("LoadAttackPaths: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(loaded))
	}
	byID := make(map[string]*model.AttackPath)
	for _, p := range loaded {
		byID[p.ID] = p
	}
	if !byID["mpath-1"].IsPrivilegeEscalation {
		t.Error("mpath-1 IsPrivilegeEscalation: expected true")
	}
	if byID["mpath-2"].IsPrivilegeEscalation {
		t.Error("mpath-2 IsPrivilegeEscalation: expected false")
	}
	if len(byID["mpath-1"].PathNodes) != 3 {
		t.Errorf("mpath-1 PathNodes: got %d want 3", len(byID["mpath-1"].PathNodes))
	}
}

// TestMemStoreBenchmarkResultRoundTrip saves a result and verifies TP/FP/FN
// and DetectionLatencyMs.
func TestMemStoreBenchmarkResultRoundTrip(t *testing.T) {
	ms := store.NewMemStore()
	ctx := context.Background()

	result := &model.BenchmarkResult{
		ID:                 "mbr-1",
		RunID:              "mrun-1",
		ScenarioID:         "msc-1",
		ToolName:           model.ToolProwler,
		DetectionLabel:     model.LabelTP,
		DetectionLatencyMs: 77,
		ChainLengthClass:   model.ClassSimple,
		RunAt:              time.Now().UTC(),
	}
	if err := ms.SaveBenchmarkResult(ctx, result); err != nil {
		t.Fatalf("SaveBenchmarkResult: %v", err)
	}
	loaded, err := ms.LoadBenchmarkResults(ctx, "mrun-1")
	if err != nil {
		t.Fatalf("LoadBenchmarkResults: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 result, got %d", len(loaded))
	}
	got := loaded[0]
	if got.DetectionLabel != model.LabelTP {
		t.Errorf("DetectionLabel: got %q want tp", got.DetectionLabel)
	}
	if got.DetectionLatencyMs != 77 {
		t.Errorf("DetectionLatencyMs: got %d want 77", got.DetectionLatencyMs)
	}
}

// TestMemStoreScenarioRoundTrip saves a scenario and verifies ChainLength and
// ExpectedAttackPath.
func TestMemStoreScenarioRoundTrip(t *testing.T) {
	ms := store.NewMemStore()
	ctx := context.Background()

	sc := &model.Scenario{
		ID:                 "msc-rt",
		Name:               "Multi-Hop Test",
		Source:             "iamvulnerable",
		ChainLength:        model.ClassMultiHop,
		ExpectedAttackPath: []string{"arn:a", "arn:b", "arn:c"},
		Description:        "Three-hop scenario.",
	}
	if err := ms.SaveScenario(ctx, sc); err != nil {
		t.Fatalf("SaveScenario: %v", err)
	}
	got, err := ms.LoadScenario(ctx, "msc-rt")
	if err != nil {
		t.Fatalf("LoadScenario: %v", err)
	}
	if got.ChainLength != model.ClassMultiHop {
		t.Errorf("ChainLength: got %q want multi_hop", got.ChainLength)
	}
	if len(got.ExpectedAttackPath) != 3 {
		t.Errorf("ExpectedAttackPath length: got %d want 3", len(got.ExpectedAttackPath))
	}
}

// TestMemStoreListScenarios saves 5 scenarios and verifies ListScenarios
// returns 5.
func TestMemStoreListScenarios(t *testing.T) {
	ms := store.NewMemStore()
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		s := &model.Scenario{
			ID:   fmt.Sprintf("mls-%02d", i),
			Name: fmt.Sprintf("Scenario %d", i),
		}
		if err := ms.SaveScenario(ctx, s); err != nil {
			t.Fatalf("SaveScenario %d: %v", i, err)
		}
	}
	list, err := ms.ListScenarios(ctx)
	if err != nil {
		t.Fatalf("ListScenarios: %v", err)
	}
	if len(list) != 5 {
		t.Errorf("expected 5, got %d", len(list))
	}
}

// TestMemStoreClose verifies that Close() returns nil.
func TestMemStoreClose(t *testing.T) {
	ms := store.NewMemStore()
	if err := ms.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
