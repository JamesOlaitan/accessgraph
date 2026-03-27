package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/JamesOlaitan/accessgraph/internal/analyzer"
	"github.com/JamesOlaitan/accessgraph/internal/config"
	"github.com/JamesOlaitan/accessgraph/internal/graph"
	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/policy"
	"github.com/JamesOlaitan/accessgraph/internal/report"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// AnalysisInput holds the parameters required by the analysis service.
//
// Fields:
//   - Label: snapshot label to analyze.
//   - FromARN: ARN of the compromised starting principal.
//   - MaxHops: maximum BFS depth.
//   - OutputFormat: "terminal", "json", or "dot".
//   - Cfg: global configuration.
type AnalysisInput struct {
	Label        string
	FromARN      string
	MaxHops      int
	OutputFormat string
	Cfg          *config.Config
}

// RunAnalysis executes the full analysis service:
//  1. Load snapshot by label.
//  2. Build graph engine and synthesize escalation edges.
//  3. Resolve --from ARN to principal ID.
//  4. Run blast-radius analysis.
//  5. Evaluate OPA policy rules (degraded mode: failure sets PolicyEvalSkipped).
//  6. Persist attack paths and findings.
//  7. Assemble model.Report and render to w.
//
// Parameters:
//   - ctx: context for cancellation.
//   - in: analysis parameters.
//   - w: writer for the rendered report.
//
// Errors:
//   - Any store, graph, analysis, or rendering error.
func RunAnalysis(ctx context.Context, in AnalysisInput, w io.Writer) error {
	var ds store.DataStore
	sqliteStore, err := store.New(ctx, in.Cfg.DBPath)
	if err != nil {
		return fmt.Errorf("service.RunAnalysis: open store: %w", err)
	}
	ds = sqliteStore
	defer sqliteStore.Close()

	snapshot, err := ds.LoadSnapshotByLabel(ctx, in.Label)
	if err != nil {
		return fmt.Errorf("service.RunAnalysis: load snapshot %q: %w", in.Label, err)
	}

	engine, err := graph.NewEngine(snapshot)
	if err != nil {
		return fmt.Errorf("service.RunAnalysis: build graph engine: %w", err)
	}

	if err := graph.SynthesizeEscalationEdges(engine, snapshot); err != nil {
		return fmt.Errorf("service.RunAnalysis: synthesize escalation edges: %w", err)
	}

	fromPrincipalID, err := ResolvePrincipalByARN(snapshot, in.FromARN)
	if err != nil {
		return fmt.Errorf("service.RunAnalysis: resolve principal ARN %q: %w", in.FromARN, err)
	}

	blastRadius, err := analyzer.NewAnalyzer().Analyze(ctx, engine, snapshot.ID, fromPrincipalID, in.MaxHops)
	if err != nil {
		return fmt.Errorf("service.RunAnalysis: blast-radius analysis: %w", err)
	}

	// OPA evaluation runs in degraded mode: a failure is logged but does not
	// abort the analysis. The report will contain an empty findings slice when
	// OPA is unavailable, and PolicyEvalSkipped is set on the report.
	var findings []*model.Finding
	var policyEvalSkipped bool
	evaluator, opaErr := policy.NewOPAEvaluator(os.DirFS(in.Cfg.PolicyDir))
	if opaErr != nil {
		policyEvalSkipped = true
	} else {
		findings, opaErr = evaluator.Evaluate(ctx, snapshot)
		if opaErr != nil {
			policyEvalSkipped = true
			findings = nil
		}
	}

	if len(blastRadius.Paths) > 0 {
		if err := ds.SaveAttackPaths(ctx, blastRadius.Paths); err != nil {
			return fmt.Errorf("service.RunAnalysis: save attack paths: %w", err)
		}
	}
	if len(findings) > 0 {
		if err := ds.SaveFindings(ctx, findings); err != nil {
			return fmt.Errorf("service.RunAnalysis: save findings: %w", err)
		}
	}

	rpt := model.Report{
		Snapshot:          snapshot,
		BlastRadius:       blastRadius,
		Findings:          findings,
		GeneratedAt:       time.Now().UTC(),
		PolicyEvalSkipped: policyEvalSkipped,
	}

	registry := report.NewRendererRegistry()
	renderer, ok := registry[in.OutputFormat]
	if !ok {
		renderer = registry["terminal"] // default
	}
	return renderer.Render(w, &rpt)
}
