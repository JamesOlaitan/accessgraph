//go:build integration

package benchmark

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/google/uuid"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// adapterRegistry maps each ToolName to its ToolAdapter implementation.
// Adding a new tool requires one new entry here and one new adapter file.
// No other file changes.
var adapterRegistry = map[model.ToolName]ToolAdapter{
	model.ToolProwler: &prowlerAdapter{},
	model.ToolPMapper: &pmapperAdapter{},
	model.ToolCheckov: &checkovAdapter{},
}

// dispatch invokes the registered adapter for the given tool.
func (r *runner) dispatch(ctx context.Context, tool model.ToolName, scenarioDir string, scenario model.Scenario) (*model.BenchmarkResult, error) {
	adapter, ok := adapterRegistry[tool]
	if !ok {
		return nil, ErrToolNotFound
	}

	start := time.Now()
	stdout, stderr, err := adapter.Invoke(ctx, r.cfg.BinaryPathFor(tool), scenarioDir)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return nil, err
	}

	detected, err := adapter.Parse(stdout, scenario)
	if err != nil {
		return nil, ErrToolFailed
	}

	var label model.DetectionLabel
	if detected {
		label = model.LabelTP
	} else {
		label = model.LabelFN
	}

	stdoutB64 := base64.StdEncoding.EncodeToString(stdout)
	stderrB64 := base64.StdEncoding.EncodeToString(stderr)

	return &model.BenchmarkResult{
		ID:                 uuid.NewString(),
		ScenarioID:         scenario.ID,
		ToolName:           tool,
		DetectionLabel:     label,
		TimeoutKind:        model.TimeoutNone,
		IsTrueNegative:     scenario.IsTrueNegative,
		DetectionLatencyMs: latency,
		ChainLengthClass:   scenario.ChainLength,
		Category:           scenario.Category,
		RunAt:              time.Now().UTC(),
		RawStdout:          &stdoutB64,
		RawStderr:          &stderrB64,
	}, nil
}
