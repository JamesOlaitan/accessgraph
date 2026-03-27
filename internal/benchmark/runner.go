// Package benchmark provides the Runner interface and its concrete
// implementation for running external IAM security tools against IAMVulnerable
// scenarios and collecting structured detection results.
//
// The runner dispatches each tool invocation to a dedicated function defined in
// the corresponding source file. Tool invocations (Prowler, PMapper, Checkov)
// are gated behind the "integration" build tag so that unit builds of this
// package never shell out to external binaries.
package benchmark

import (
	"context"
	"errors"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// ErrToolNotFound is returned when the requested tool binary cannot be located
// on PATH or at the configured path.
var ErrToolNotFound = errors.New("tool binary not found on PATH")

// ErrToolFailed is returned when the tool binary is found but exits with a
// non-zero status or produces unparseable output.
var ErrToolFailed = errors.New("tool execution failed")

// ErrInvalidInput is returned when the caller supplies an invalid combination
// of arguments (e.g., an empty scenarioDir, or ToolNameAccessGraph which
// evaluates itself separately).
var ErrInvalidInput = errors.New("invalid input")

// ToolConfig holds filesystem paths to external tool binaries.
//
// Each field defaults to the bare binary name (resolved via PATH) when left
// empty. Override the fields to point at non-PATH installations.
//
// Fields:
//   - ProwlerPath: path to the prowler binary; defaults to "prowler".
//   - PMapperPath: path to the pmapper binary; defaults to "pmapper".
//   - CheckovPath: path to the checkov binary; defaults to "checkov".
//   - SteampipePath: path to the steampipe binary; defaults to "steampipe".
//   - CloudSploitPath: path to the cloudsploit binary; defaults to "cloudsploit".
type ToolConfig struct {
	// ProwlerPath is the path to the Prowler binary.
	// If empty, "prowler" is resolved via PATH at invocation time.
	ProwlerPath string

	// PMapperPath is the path to the PMapper binary.
	// If empty, "pmapper" is resolved via PATH at invocation time.
	PMapperPath string

	// CheckovPath is the path to the Checkov binary.
	// If empty, "checkov" is resolved via PATH at invocation time.
	CheckovPath string

	// SteampipePath is the path to the Steampipe binary.
	// If empty, "steampipe" is resolved via PATH at invocation time.
	SteampipePath string

	// CloudSploitPath is the path to the CloudSploit binary.
	// If empty, "cloudsploit" is resolved via PATH at invocation time.
	CloudSploitPath string
}

// BinaryPathFor returns the configured binary path for the given tool.
// The returned string is always non-empty: newRunner guarantees that every
// field defaults to the bare binary name when no explicit path is provided.
func (c ToolConfig) BinaryPathFor(tool model.ToolName) string {
	switch tool {
	case model.ToolProwler:
		return c.ProwlerPath
	case model.ToolPMapper:
		return c.PMapperPath
	case model.ToolCheckov:
		return c.CheckovPath
	case model.ToolSteampipe:
		return c.SteampipePath
	case model.ToolCloudSploit:
		return c.CloudSploitPath
	default:
		return ""
	}
}

// Runner defines the contract for invoking an external security tool
// against an IAMVulnerable scenario and collecting a structured result.
type Runner interface {
	// RunTool invokes the named tool against the scenario's source directory and
	// returns a structured result. The result's TruePositive field is set by
	// comparing the tool's output against scenario.ExpectedAttackPath.
	//
	// Parameters:
	//   - ctx: context for timeout and cancellation.
	//   - tool: the tool to invoke (must not be ToolNameAccessGraph).
	//   - scenarioDir: path to the directory containing the scenario's policy JSON files.
	//   - scenario: the scenario being evaluated, used for ground-truth comparison.
	//
	// Returns a BenchmarkResult with TP/FP/FN and DetectionLatencyMs populated.
	//
	// Errors:
	//   - ErrInvalidInput if scenarioDir is empty or tool is ToolNameAccessGraph.
	//   - ErrToolNotFound if the binary cannot be located.
	//   - ErrToolFailed if the binary exits non-zero or produces unparseable output.
	RunTool(ctx context.Context, tool model.ToolName, scenarioDir string, scenario model.Scenario) (*model.BenchmarkResult, error)
}

// runner is the concrete implementation of Runner.
//
// Construct with newRunner. The zero value is not usable.
type runner struct {
	cfg ToolConfig
}

// Compile-time assertion that *runner satisfies Runner.
var _ Runner = (*runner)(nil)

// newRunner constructs a runner with the supplied ToolConfig.
//
// Parameters:
//   - cfg: tool binary paths; empty strings are replaced by bare binary names
//     resolved via PATH at invocation time.
//
// Returns an initialized *runner ready for use.
func newRunner(cfg ToolConfig) *runner {
	if cfg.ProwlerPath == "" {
		cfg.ProwlerPath = "prowler"
	}
	if cfg.PMapperPath == "" {
		cfg.PMapperPath = "pmapper"
	}
	if cfg.CheckovPath == "" {
		cfg.CheckovPath = "checkov"
	}
	if cfg.SteampipePath == "" {
		cfg.SteampipePath = "steampipe"
	}
	if cfg.CloudSploitPath == "" {
		cfg.CloudSploitPath = "cloudsploit"
	}
	return &runner{cfg: cfg}
}

// RunTool dispatches to the appropriate tool-specific implementation.
//
// Parameters:
//   - ctx: context for timeout and cancellation.
//   - tool: the tool to invoke.
//   - scenarioDir: path to the directory containing the scenario's policy JSON files.
//   - scenario: the scenario being evaluated.
//
// Returns a *model.BenchmarkResult on success.
//
// Errors:
//   - ErrInvalidInput if scenarioDir is empty or tool is ToolNameAccessGraph.
//   - ErrToolNotFound if the binary cannot be located.
//   - ErrToolFailed if execution fails or output cannot be parsed.
func (r *runner) RunTool(ctx context.Context, tool model.ToolName, scenarioDir string, scenario model.Scenario) (*model.BenchmarkResult, error) {
	if scenarioDir == "" {
		return nil, ErrInvalidInput
	}
	if tool == model.ToolAccessGraph {
		// AccessGraph evaluates itself separately; it is not a valid target for
		// this runner.
		return nil, ErrInvalidInput
	}
	return r.dispatch(ctx, tool, scenarioDir, scenario)
}
