package service

import (
	"context"
	"fmt"
	"io"

	"github.com/google/uuid"

	"github.com/JamesOlaitan/accessgraph/internal/benchmark"
	"github.com/JamesOlaitan/accessgraph/internal/config"
	"github.com/JamesOlaitan/accessgraph/internal/report"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// BenchmarkInput holds the parameters required by the benchmark service.
type BenchmarkInput struct {
	ScenariosDir string
	Tools        string
	Output       string
	Cfg          *config.Config
}

// RunBenchmark executes the full benchmark pipeline:
//  1. Open the data store.
//  2. Build the scenario registry, aggregator, and renderer registry.
//  3. Parse the tool list.
//  4. Delegate to BenchmarkFacade.Run.
//
// Parameters:
//   - ctx: context for cancellation.
//   - in: benchmark parameters.
//   - w: writer for the rendered report.
func RunBenchmark(ctx context.Context, in BenchmarkInput, w io.Writer) error {
	ds, err := store.New(ctx, in.Cfg.DBPath)
	if err != nil {
		return fmt.Errorf("service.RunBenchmark: open store: %w", err)
	}
	defer ds.Close()

	runID := uuid.NewString()
	registry := report.NewRendererRegistry()
	runners := benchmark.NewScenarioRegistry(benchmark.ToolConfig{}, nil)

	facade := NewBenchmarkFacade(runners, benchmark.NewAggregator(), ds, registry)

	tools := benchmark.ParseToolList(in.Tools)
	if len(tools) == 0 {
		return fmt.Errorf("--tools produced an empty list")
	}

	return facade.Run(ctx, runID, in.ScenariosDir, tools, in.Output, w)
}
