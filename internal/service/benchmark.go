package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/JamesOlaitan/accessgraph/internal/benchmark"
	"github.com/JamesOlaitan/accessgraph/internal/config"
	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/report"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// benchmarkFacade is the concrete implementation of BenchmarkFacade.
type benchmarkFacade struct {
	runners    map[model.ToolName]benchmark.ScenarioRunner
	aggregator benchmark.Aggregator
	ds         store.DataStore
	renderers  map[string]report.Renderer
	cfg        *config.Config
}

// Compile-time assertion that *benchmarkFacade satisfies BenchmarkFacade.
var _ BenchmarkFacade = (*benchmarkFacade)(nil)

// NewBenchmarkFacade returns a new BenchmarkFacade.
func NewBenchmarkFacade(
	runners map[model.ToolName]benchmark.ScenarioRunner,
	aggregator benchmark.Aggregator,
	ds store.DataStore,
	renderers map[string]report.Renderer,
	cfg *config.Config,
) *benchmarkFacade {
	return &benchmarkFacade{
		runners:    runners,
		aggregator: aggregator,
		ds:         ds,
		renderers:  renderers,
		cfg:        cfg,
	}
}

// Run implements BenchmarkFacade.
func (f *benchmarkFacade) Run(ctx context.Context, runID, scenarioDir string, tools []model.ToolName, format string, w io.Writer) error {
	renderer, ok := f.renderers[format]
	if !ok {
		return fmt.Errorf("benchmarkFacade.Run: unsupported format %q: %w", format, ErrInvalidInput)
	}

	scenarios, err := benchmark.LoadScenarios(scenarioDir)
	if err != nil {
		return fmt.Errorf("benchmarkFacade.Run: load scenarios: %w", err)
	}
	if len(scenarios) == 0 {
		return fmt.Errorf("benchmarkFacade.Run: no scenarios found in %q", scenarioDir)
	}

	for _, sc := range scenarios {
		if err := f.ds.SaveScenario(ctx, sc); err != nil {
			return fmt.Errorf("benchmarkFacade.Run: save scenario %q: %w", sc.ID, err)
		}
	}

	for _, toolName := range tools {
		runner, ok := f.runners[toolName]
		if !ok {
			continue
		}
		for _, sc := range scenarios {
			result, runErr := runner.RunScenario(ctx, sc)
			if runErr != nil {
				continue
			}
			result.ID = uuid.NewString()
			result.RunID = runID
			result.ToolName = toolName
			result.ScenarioID = sc.ID
			result.RunAt = time.Now().UTC()
			if err := f.ds.SaveBenchmarkResult(ctx, result); err != nil {
				return fmt.Errorf("benchmarkFacade.Run: save result for tool %q scenario %q: %w", toolName, sc.ID, err)
			}
		}
	}

	// AccessGraph in-process self-evaluation.
	if benchmark.ToolListContains(tools, model.ToolAccessGraph) {
		for _, sc := range scenarios {
			agResult, agErr := benchmark.RunAccessGraphOnScenario(ctx, sc, scenarioDir, f.cfg)
			if agErr != nil {
				continue
			}
			agResult.RunID = runID
			agResult.ResultID = model.ComputeResultID(runID, agResult.ScenarioID, agResult.ToolName)
			if err := f.ds.SaveBenchmarkResult(ctx, agResult); err != nil {
				return fmt.Errorf("benchmarkFacade.Run: save accessgraph result for scenario %q: %w", sc.ID, err)
			}
		}
	}

	ar, err := f.aggregator.Aggregate(ctx, f.ds, runID, scenarios)
	if err != nil {
		return fmt.Errorf("benchmarkFacade.Run: aggregate: %w", err)
	}
	ar.RunID = runID
	ar.GeneratedAt = time.Now().UTC()
	ar.SchemaVersion = "1.0.0"
	ar.Label = "run-" + ar.GeneratedAt.Format("20060102-150405")

	// Read IAMVulnerable commit SHA from fixtures if available.
	commitPath := filepath.Join(scenarioDir, "..", "COMMIT")
	if data, err := os.ReadFile(commitPath); err == nil {
		ar.IAMVulnerableCommit = strings.TrimSpace(string(data))
	}

	for tool, classes := range ar.ByToolAndClass {
		for class, cm := range classes {
			if err := f.ds.SaveClassMetrics(ctx, runID, tool, class, cm); err != nil {
				return fmt.Errorf("benchmarkFacade.Run: save class metrics %v/%v: %w", tool, class, err)
			}
		}
	}

	for tool, tm := range ar.ByTool {
		if err := f.ds.SaveToolMetrics(ctx, runID, tool, tm); err != nil {
			return fmt.Errorf("benchmarkFacade.Run: save tool metrics %v: %w", tool, err)
		}
	}

	for tool, fpr := range ar.FPRByTool {
		if err := f.ds.SaveFalsePositiveRate(ctx, runID, tool, fpr); err != nil {
			return fmt.Errorf("benchmarkFacade.Run: save FPR %v: %w", tool, err)
		}
	}

	rpt := &model.Report{
		AggregationResult: ar,
	}
	return renderer.Render(w, rpt)
}
