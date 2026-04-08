package benchmark

import (
	"context"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// ScenarioRunner is the per-tool variant of Runner.
// Unlike Runner.RunTool (which takes a tool name parameter and dispatches
// via a switch/registry inside runner), each ScenarioRunner implementation serves
// exactly one tool. Tool selection is done at construction time via the registry
// map returned by NewScenarioRegistry, eliminating any per-call switch statement.
type ScenarioRunner interface {
	// RunScenario invokes this runner's tool against the given scenario and returns
	// a structured result. The tool identity is baked into the implementation; the
	// caller does not pass a tool name.
	//
	// Parameters:
	//   - ctx: context for timeout and cancellation.
	//   - scenario: the scenario to evaluate.
	//
	// Returns a *model.BenchmarkResult with DetectionLabel and DetectionLatencyMs
	// populated on success.
	//
	// Errors:
	//   - ErrToolNotFound if the binary cannot be located.
	//   - ErrToolFailed if the binary exits non-zero or produces unparseable output.
	RunScenario(ctx context.Context, scenario *model.Scenario) (*model.BenchmarkResult, error)
}

// toolScenarioRunner implements ScenarioRunner for a single external tool by
// delegating to the existing runner.RunTool dispatch mechanism.
//
// This is a compatibility shim: it allows the new ScenarioRunner interface to
// be satisfied without duplicating the adapter/dispatch logic that already lives
// in dispatch_integration.go and dispatch_stub.go.
type toolScenarioRunner struct {
	runner        *runner
	tool          model.ToolName
	scenarioDirFn func(scenario *model.Scenario) string
}

// RunScenario resolves the scenario directory via scenarioDirFn (if set) and
// delegates to runner.RunTool.
func (r *toolScenarioRunner) RunScenario(ctx context.Context, scenario *model.Scenario) (*model.BenchmarkResult, error) {
	dir := ""
	if r.scenarioDirFn != nil {
		dir = r.scenarioDirFn(scenario)
	}
	return r.runner.RunTool(ctx, r.tool, dir, *scenario)
}

// NewScenarioRegistry constructs the per-tool ScenarioRunner registry for all
// supported external tools. The returned map key is the model.ToolName; the
// value is the ScenarioRunner implementation for that tool.
//
// Parameters:
//   - cfg: tool binary paths passed to newRunner; empty strings default to bare
//     binary names resolved via PATH at invocation time.
//   - scenarioDirFn: a function that resolves the on-disk directory path for a
//     given scenario. It is called once per RunScenario invocation and its result
//     is forwarded to runner.RunTool as the scenarioDir argument. If nil, an
//     empty string is passed (RunTool will return ErrInvalidInput in that case).
//
// The registry does not include model.ToolAccessGraph because the AccessGraph
// self-evaluation path is handled separately (it runs in-process via
// runAccessGraphOnScenario in pipeline.go).
//
// The returned map is safe to read concurrently after construction; the caller
// must not mutate it.
func NewScenarioRegistry(cfg ToolConfig, scenarioDirFn func(*model.Scenario) string) map[model.ToolName]ScenarioRunner {
	r := newRunner(cfg)
	tools := []model.ToolName{
		model.ToolProwler,
		model.ToolPMapper,
		model.ToolCheckov,
	}
	registry := make(map[model.ToolName]ScenarioRunner, len(tools))
	for _, tn := range tools {
		registry[tn] = &toolScenarioRunner{
			runner:        r,
			tool:          tn,
			scenarioDirFn: scenarioDirFn,
		}
	}
	return registry
}
