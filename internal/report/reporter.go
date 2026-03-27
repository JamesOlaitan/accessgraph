// Package report provides rendering implementations for AccessGraph analysis
// output. It supports terminal (colored), JSON, Graphviz DOT, and benchmark
// comparison table formats.
//
// The package is read-only with respect to the model: it never modifies any
// *model.Report or *model.ComparisonReport it receives. All rendering is driven
// by writing to an io.Writer supplied by the caller.
//
// Dependency rule: report imports only from model and standard library / third-
// party formatting packages. It must never import from cmd/, internal/store/,
// internal/graph/, internal/analyzer/, or internal/policy/.
package report

import (
	"errors"
	"io"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// ErrRenderFailed is returned when a rendering operation cannot complete due to
// an I/O error or a structurally invalid model object.
var ErrRenderFailed = errors.New("render failed")

// Reporter defines the contract for rendering an AccessGraph analysis report
// in one of several output formats.
//
// Each method writes entirely to the supplied io.Writer and returns an error
// only when the write fails or the supplied report is structurally invalid.
// Callers remain responsible for closing the writer.
type Reporter interface {
	// RenderTerminal writes a human-readable, colored report to w.
	//
	// Parameters:
	//   - w: destination writer; must not be nil.
	//   - report: the analysis report to render; must not be nil.
	//
	// Returns ErrRenderFailed (wrapped) on I/O error.
	RenderTerminal(w io.Writer, report *model.Report) error

	// RenderJSON writes the report as structured, indented JSON to w.
	//
	// Parameters:
	//   - w: destination writer; must not be nil.
	//   - report: the analysis report to render; must not be nil.
	//
	// Returns ErrRenderFailed (wrapped) on encoding or I/O error.
	RenderJSON(w io.Writer, report *model.Report) error

	// RenderDOT writes the permission graph in Graphviz DOT format to w.
	//
	// The DOT output represents the attack paths found in report.BlastRadius.Paths.
	// Output is deterministic: node IDs are sorted before writing.
	//
	// Parameters:
	//   - w: destination writer; must not be nil.
	//   - report: the analysis report to render; must not be nil.
	//
	// Returns ErrRenderFailed (wrapped) on I/O error.
	RenderDOT(w io.Writer, report *model.Report) error

	// RenderAggregationResult writes the benchmark aggregation as a formatted
	// table to w.
	//
	// Parameters:
	//   - w: destination writer; must not be nil.
	//   - ar: the aggregation result to render; must not be nil.
	//
	// Returns ErrRenderFailed (wrapped) on I/O error.
	RenderAggregationResult(w io.Writer, ar *model.AggregationResult) error
}

// DefaultReporter is the concrete implementation of Reporter.
//
// Construct with NewReporter. The zero value is usable but prefer NewReporter
// for future extensibility.
type DefaultReporter struct{}

// Compile-time assertion that *DefaultReporter satisfies Reporter.
var _ Reporter = (*DefaultReporter)(nil)

// NewReporter constructs a DefaultReporter.
//
// Returns a ready-to-use *DefaultReporter.
func NewReporter() *DefaultReporter {
	return &DefaultReporter{}
}
