//go:build !integration

package benchmark

import (
	"context"
	"fmt"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// dispatch is the non-integration stub. It always returns ErrToolFailed because
// external tool binaries are not available without the "integration" build tag.
//
// This file is compiled when the "integration" tag is absent.
// The live implementation lives in dispatch_integration.go.
//
// Parameters:
//   - ctx: context (unused in this stub).
//   - tool: the tool name that was requested.
//   - scenarioDir: path to the scenario directory (unused in this stub).
//   - scenario: the scenario being evaluated (unused in this stub).
//
// Errors:
//   - Always returns ErrToolFailed with a message directing the caller to build
//     with the "integration" tag.
func (r *runner) dispatch(_ context.Context, tool model.ToolName, _ string, _ model.Scenario) (*model.BenchmarkResult, error) {
	return nil, fmt.Errorf("%w: tool %q requires build tag 'integration'", ErrToolFailed, tool)
}
