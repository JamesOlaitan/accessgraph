// Package service_test exercises the AnalysisFacade implementation.
//
// Tests use store.NewMemStore so they run offline without any SQLite or
// filesystem dependencies. OPA policy evaluation runs in degraded mode when
// policyDir does not contain .rego files; that is the expected behaviour for
// unit tests.
package service_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/report"
	"github.com/JamesOlaitan/accessgraph/internal/service"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// minimalSnapshot builds a *model.Snapshot with one principal and one
// sensitive resource connected by an ALLOWS_ACTION edge. The snapshot is
// saved into ds and returned.
func minimalSnapshot(t *testing.T, ctx context.Context, ds store.DataStore) *model.Snapshot {
	t.Helper()
	snap := &model.Snapshot{
		ID:        "snap-svc-test",
		Label:     "svc-test",
		Provider:  "aws",
		CreatedAt: time.Now().UTC(),
		Principals: []*model.Principal{
			{
				ID:         "user-svc-1",
				SnapshotID: "snap-svc-test",
				Kind:       model.PrincipalKindIAMUser,
				ARN:        "arn:aws:iam::111:user/alice",
				Name:       "alice",
			},
		},
		Resources: []*model.Resource{
			{
				ID:          "res-svc-1",
				SnapshotID:  "snap-svc-test",
				ARN:         "arn:aws:iam::aws:policy/AdministratorAccess",
				Kind:        "IAMPolicy",
				IsSensitive: true,
			},
		},
		Edges: []*model.Edge{
			{
				ID:         "edge-svc-1",
				SnapshotID: "snap-svc-test",
				FromNodeID: "user-svc-1",
				ToNodeID:   "res-svc-1",
				Kind:       model.EdgeKindAllowsAction,
				Weight:     1,
			},
		},
	}
	if err := ds.SaveSnapshot(ctx, snap); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}
	return snap
}

// TestAnalysisFacadeUnknownFormat verifies that Run returns ErrInvalidInput
// immediately — before any store access — when the format argument is not one
// of {terminal, json, dot}.
func TestAnalysisFacadeUnknownFormat(t *testing.T) {
	ds := store.NewMemStore()
	// No snapshot is saved into the store; the facade must not access it.
	facade := service.NewAnalysisFacade(ds, t.TempDir(), report.NewRendererRegistry())

	var buf bytes.Buffer
	err := facade.Run(context.Background(), "nonexistent-label", "arn:aws:iam::111:user/alice", 8, "xml", &buf)
	if err == nil {
		t.Fatal("expected ErrInvalidInput for format=xml, got nil")
	}
	if !errors.Is(err, service.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

// TestAnalysisFacadeTerminalFormat seeds a snapshot and verifies that Run
// with format="terminal" succeeds and writes non-empty output.
func TestAnalysisFacadeTerminalFormat(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	snap := minimalSnapshot(t, ctx, ds)

	facade := service.NewAnalysisFacade(ds, t.TempDir(), report.NewRendererRegistry())

	var buf bytes.Buffer
	err := facade.Run(ctx, snap.Label, "arn:aws:iam::111:user/alice", 8, "terminal", &buf)
	if err != nil {
		t.Fatalf("Run(terminal): unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected non-empty terminal output, got empty")
	}
}

// TestAnalysisFacadeJSONFormat verifies that Run with format="json" produces
// output that begins with "{" (well-formed JSON object).
func TestAnalysisFacadeJSONFormat(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	snap := minimalSnapshot(t, ctx, ds)

	facade := service.NewAnalysisFacade(ds, t.TempDir(), report.NewRendererRegistry())

	var buf bytes.Buffer
	err := facade.Run(ctx, snap.Label, "arn:aws:iam::111:user/alice", 8, "json", &buf)
	if err != nil {
		t.Fatalf("Run(json): unexpected error: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "{") {
		t.Errorf("expected JSON output starting with '{', got: %.30q", buf.String())
	}
}

// TestAnalysisFacadeDOTFormat verifies that Run with format="dot" produces
// DOT graph output (starts with "digraph").
func TestAnalysisFacadeDOTFormat(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	snap := minimalSnapshot(t, ctx, ds)

	facade := service.NewAnalysisFacade(ds, t.TempDir(), report.NewRendererRegistry())

	var buf bytes.Buffer
	err := facade.Run(ctx, snap.Label, "arn:aws:iam::111:user/alice", 8, "dot", &buf)
	if err != nil {
		t.Fatalf("Run(dot): unexpected error: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "digraph") {
		t.Errorf("expected DOT output starting with 'digraph', got: %.40q", buf.String())
	}
}

// TestAnalysisFacadeSnapshotNotFound verifies that Run returns an error when
// the requested snapshot label does not exist in the store.
func TestAnalysisFacadeSnapshotNotFound(t *testing.T) {
	ds := store.NewMemStore()
	facade := service.NewAnalysisFacade(ds, t.TempDir(), report.NewRendererRegistry())

	var buf bytes.Buffer
	err := facade.Run(context.Background(), "does-not-exist", "arn:aws:iam::111:user/alice", 8, "terminal", &buf)
	if err == nil {
		t.Fatal("expected error for missing snapshot, got nil")
	}
}

// TestAnalysisFacadePrincipalNotFound verifies that Run returns an error when
// the --from ARN does not match any principal in the snapshot.
func TestAnalysisFacadePrincipalNotFound(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	snap := minimalSnapshot(t, ctx, ds)

	facade := service.NewAnalysisFacade(ds, t.TempDir(), report.NewRendererRegistry())

	var buf bytes.Buffer
	err := facade.Run(ctx, snap.Label, "arn:aws:iam::999:user/nobody", 8, "terminal", &buf)
	if err == nil {
		t.Fatal("expected error for unknown principal ARN, got nil")
	}
}

// TestAnalysisFacadePolicyEvalSkippedWhenNoRego verifies that Run succeeds even
// when the policyDir contains no .rego files. OPA runs in degraded mode — the
// report may have PolicyEvalSkipped=true, but no error is returned.
func TestAnalysisFacadePolicyEvalSkippedWhenNoRego(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	snap := minimalSnapshot(t, ctx, ds)

	// t.TempDir() returns an empty directory — no .rego files.
	facade := service.NewAnalysisFacade(ds, t.TempDir(), report.NewRendererRegistry())

	var buf bytes.Buffer
	err := facade.Run(ctx, snap.Label, "arn:aws:iam::111:user/alice", 8, "json", &buf)
	if err != nil {
		t.Fatalf("Run with empty policyDir: unexpected error: %v", err)
	}
}
