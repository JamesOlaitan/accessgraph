package report

import (
	"fmt"
	"io"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// Renderer formats and emits a model.Report in one specific output format.
// It writes to the provided io.Writer and never reads from it.
type Renderer interface {
	// Format returns the format identifier registered in RendererRegistry.
	Format() string

	// Render writes the formatted report to w.
	// Implementations must handle nil fields in model.Report gracefully.
	Render(w io.Writer, report *model.Report) error
}

// NewRendererRegistry returns a fresh map of format identifiers to Renderer implementations.
// Registered formats: "terminal", "json", "dot".
func NewRendererRegistry() map[string]Renderer {
	return map[string]Renderer{
		"terminal": &terminalRenderer{},
		"json":     &jsonRenderer{},
		"dot":      &dotRenderer{},
	}
}

// Compile-time assertions that concrete renderers satisfy the Renderer interface.
var _ Renderer = (*terminalRenderer)(nil)
var _ Renderer = (*jsonRenderer)(nil)
var _ Renderer = (*dotRenderer)(nil)

// terminalRenderer implements Renderer by delegating to DefaultReporter.RenderTerminal.
type terminalRenderer struct{}

func (r *terminalRenderer) Format() string { return "terminal" }
func (r *terminalRenderer) Render(w io.Writer, rpt *model.Report) error {
	if rpt == nil {
		return fmt.Errorf("%w: nil report", ErrRenderFailed)
	}
	return NewReporter().RenderTerminal(w, rpt)
}

// jsonRenderer implements Renderer by delegating to DefaultReporter.RenderJSON.
type jsonRenderer struct{}

func (r *jsonRenderer) Format() string { return "json" }
func (r *jsonRenderer) Render(w io.Writer, rpt *model.Report) error {
	if rpt == nil {
		return fmt.Errorf("%w: nil report", ErrRenderFailed)
	}
	if rpt.AggregationResult != nil {
		return NewReporter().RenderAggregationResult(w, rpt.AggregationResult)
	}
	return NewReporter().RenderJSON(w, rpt)
}

// dotRenderer implements Renderer by delegating to DefaultReporter.RenderDOT.
type dotRenderer struct{}

func (r *dotRenderer) Format() string { return "dot" }
func (r *dotRenderer) Render(w io.Writer, rpt *model.Report) error {
	if rpt == nil {
		return fmt.Errorf("%w: nil report", ErrRenderFailed)
	}
	return NewReporter().RenderDOT(w, rpt)
}
