package benchmark

import (
	"context"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// ToolAdapter is the per-tool output normalization interface.
//
// Each external tool adapter implements ToolAdapter to parse its specific output
// format into a standardized detection decision. The adapter pattern isolates
// tool-specific output parsing from the benchmark runner loop, so that adding
// a new tool requires only a new adapter file and a registry entry.
//
// Exit code semantics differ across tools; each adapter documents its tool's
// behavior in its package-level comment.
type ToolAdapter interface {
	// Invoke runs the tool binary against the scenario directory and returns
	// stdout and stderr separately. It encapsulates all tool-specific invocation
	// logic (argument construction, temp-dir management, exit-code handling).
	//
	// Parameters:
	//   - ctx: context for timeout and cancellation.
	//   - binaryPath: path to the tool binary.
	//   - scenarioDir: path to the directory containing the scenario files.
	//
	// Returns stdout and stderr as separate byte slices.
	//
	// Errors:
	//   - ErrToolNotFound if the binary cannot be located.
	//   - ErrToolFailed if the binary exits with an unexpected status.
	Invoke(ctx context.Context, binaryPath, scenarioDir string) (stdout, stderr []byte, err error)

	// Parse converts raw stdout bytes from the tool invocation into a detection
	// decision. It returns true if the tool's output indicates the expected
	// attack path was detected.
	//
	// Parameters:
	//   - stdout: the complete stdout from the tool invocation.
	//   - expected: the scenario's ground-truth attack path.
	//
	// Returns:
	//   - true if the expected attack path was detected.
	//   - false if the tool did not detect it or produced no output.
	//
	// Errors:
	//   - Any parse or format error encountered while reading stdout.
	Parse(stdout []byte, expected model.Scenario) (bool, error)
}
