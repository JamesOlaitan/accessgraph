package service

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/JamesOlaitan/accessgraph/internal/config"
	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/report"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// ReportInput holds the parameters required by the report service.
//
// Fields:
//   - SnapshotID: the snapshot ID to render.
//   - OutputFormat: "terminal", "json", or "dot".
//   - Cfg: global configuration.
type ReportInput struct {
	SnapshotID   string
	OutputFormat string
	Cfg          *config.Config
}

// RunReport executes the report service: load stored data and render.
//
// It loads the snapshot, attack paths, and findings stored by a prior "analyze"
// run and renders the assembled report to w. No re-analysis is performed.
//
// Parameters:
//   - ctx: context for cancellation.
//   - in: report parameters.
//   - w: writer for the rendered output.
//
// Errors:
//   - Any store or rendering error.
func RunReport(ctx context.Context, in ReportInput, w io.Writer) error {
	var ds store.DataStore
	sqliteStore, err := store.New(ctx, in.Cfg.DBPath)
	if err != nil {
		return fmt.Errorf("service.RunReport: open store: %w", err)
	}
	ds = sqliteStore
	defer sqliteStore.Close()

	snapshot, err := ds.LoadSnapshot(ctx, in.SnapshotID)
	if err != nil {
		return fmt.Errorf("service.RunReport: load snapshot %q: %w", in.SnapshotID, err)
	}

	paths, err := ds.LoadAttackPaths(ctx, in.SnapshotID)
	if err != nil {
		return fmt.Errorf("service.RunReport: load attack paths: %w", err)
	}

	findings, err := ds.LoadFindings(ctx, in.SnapshotID)
	if err != nil {
		return fmt.Errorf("service.RunReport: load findings: %w", err)
	}

	blastRadius := buildBlastRadiusFromPaths(paths, in.SnapshotID)

	rpt := model.Report{
		Snapshot:    snapshot,
		BlastRadius: blastRadius,
		Findings:    findings,
		GeneratedAt: time.Now().UTC(),
	}

	registry := report.NewRendererRegistry()
	renderer, ok := registry[in.OutputFormat]
	if !ok {
		renderer = registry["terminal"] // default
	}
	return renderer.Render(w, &rpt)
}

// buildBlastRadiusFromPaths assembles a BlastRadiusReport from stored attack paths
// without re-running BFS. PctEnvironmentReachable cannot be recomputed without
// node count and is left at its zero value.
//
// Parameters:
//   - paths: the stored attack paths for the snapshot.
//   - snapshotID: the snapshot these paths belong to.
//
// Returns:
//   - A *model.BlastRadiusReport with available metrics populated.
func buildBlastRadiusFromPaths(paths []*model.AttackPath, snapshotID string) *model.BlastRadiusReport {
	br := &model.BlastRadiusReport{
		SnapshotID:        snapshotID,
		Paths:             paths,
		DistinctPathCount: len(paths),
	}

	if len(paths) == 0 {
		br.MinHopToAdmin = -1
		return br
	}

	br.PrincipalID = paths[0].FromPrincipalID

	seenResources := make(map[string]bool, len(paths))
	for _, p := range paths {
		if p != nil && p.ToResourceID != "" {
			seenResources[p.ToResourceID] = true
		}
	}
	br.ReachableResourceCount = len(seenResources)

	minEscalation := -1
	minOverall := -1
	for _, p := range paths {
		if p == nil {
			continue
		}
		if minOverall < 0 || p.HopCount < minOverall {
			minOverall = p.HopCount
		}
		if p.IsPrivilegeEscalation {
			if minEscalation < 0 || p.HopCount < minEscalation {
				minEscalation = p.HopCount
			}
		}
	}
	if minEscalation >= 0 {
		br.MinHopToAdmin = minEscalation
	} else {
		br.MinHopToAdmin = minOverall
	}

	return br
}
