package benchmark

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// Aggregator computes precision, recall, F1, and Wilson-score 95%
// confidence intervals for each (tool, chain_length_class) pair from a set of
// BenchmarkResult rows, producing an AggregationResult.
//
// Timeout rows are excluded from the TP+FN denominator for recall and reported
// separately in ClassMetrics.Timeouts. They are also excluded from the FPR
// denominator for true-negative scenarios.
type Aggregator interface {
	// Aggregate reads all BenchmarkResult rows for the given runID and computes
	// per-(tool, chain_length_class) and per-tool precision/recall metrics,
	// plus per-tool false-positive rates across true-negative scenarios.
	//
	// Parameters:
	//   - ctx: context for cancellation.
	//   - reader: the BenchmarkResultReader to load results from.
	//   - runID: the benchmark run to aggregate; must be non-empty.
	//   - scenarios: all scenarios evaluated in this benchmark run.
	//
	// Returns:
	//   - A *model.AggregationResult with ByToolAndClass, ByTool, FPRByTool populated.
	//
	// Errors:
	//   - Any store error encountered while reading results.
	Aggregate(ctx context.Context, reader store.BenchmarkResultReader, runID string, scenarios []*model.Scenario) (*model.AggregationResult, error)
}

// defaultAggregator is the standard implementation of Aggregator.
type defaultAggregator struct{}

// Compile-time assertion that *defaultAggregator satisfies Aggregator.
var _ Aggregator = (*defaultAggregator)(nil)

// NewAggregator returns a new Aggregator.
func NewAggregator() Aggregator {
	return &defaultAggregator{}
}

// wilsonCI computes the Wilson-score 95% confidence interval for a proportion
// p_hat = successes/n. Both low and high are clamped to [0, 1].
//
// Returns (pHat, low, high). When n == 0, returns (0, 0, 0).
func wilsonCI(successes, n int) (pHat, low, high float64) {
	if n == 0 {
		return 0, 0, 0
	}
	z := 1.96 // 95% two-tailed
	p := float64(successes) / float64(n)
	nf := float64(n)
	denom := 1.0 + z*z/nf
	centre := (p + z*z/(2*nf)) / denom
	margin := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf)) / denom
	low = math.Max(0, centre-margin)
	high = math.Min(1, centre+margin)
	pHat = p
	if !(low <= pHat && pHat <= high && high <= 1) {
		panic(fmt.Sprintf("wilsonCI invariant violated: low=%f p_hat=%f high=%f", low, pHat, high))
	}
	return
}

// Aggregate computes per-(tool, chain_length_class) and per-tool metrics from
// BenchmarkResults for the given runID. Timeout rows are excluded from
// precision/recall denominators.
func (a *defaultAggregator) Aggregate(
	ctx context.Context,
	reader store.BenchmarkResultReader,
	runID string,
	scenarios []*model.Scenario,
) (*model.AggregationResult, error) {
	if runID == "" {
		return nil, fmt.Errorf("Aggregator.Aggregate: %w", ErrInvalidInput)
	}

	results, err := reader.LoadBenchmarkResults(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("Aggregator.Aggregate: load results: %w", err)
	}

	// Index scenario IsTrueNegative flag.
	isTN := make(map[string]bool, len(scenarios))
	for _, sc := range scenarios {
		if sc != nil {
			isTN[sc.ID] = sc.IsTrueNegative
		}
	}

	// Per-(tool, class) raw counts.
	type counts struct{ tp, fp, fn, tn, timeouts int }
	byClass := make(map[model.ToolName]map[model.ChainLengthClass]*counts)

	// Per-tool FPR counts (FP + TN across TN scenarios).
	type fprCounts struct{ fp, tn, tnTimeouts int }
	fprAcc := make(map[model.ToolName]*fprCounts)

	ensure := func(tool model.ToolName, cls model.ChainLengthClass) *counts {
		if byClass[tool] == nil {
			byClass[tool] = make(map[model.ChainLengthClass]*counts)
		}
		if byClass[tool][cls] == nil {
			byClass[tool][cls] = &counts{}
		}
		return byClass[tool][cls]
	}
	ensureFPR := func(tool model.ToolName) *fprCounts {
		if fprAcc[tool] == nil {
			fprAcc[tool] = &fprCounts{}
		}
		return fprAcc[tool]
	}

	for _, r := range results {
		if r == nil {
			continue
		}
		c := ensure(r.ToolName, r.ChainLengthClass)
		switch r.DetectionLabel {
		case model.LabelTP:
			c.tp++
		case model.LabelFP:
			c.fp++
			if isTN[r.ScenarioID] {
				ensureFPR(r.ToolName).fp++
			}
		case model.LabelFN:
			c.fn++
		case model.LabelTN:
			c.tn++
			if isTN[r.ScenarioID] {
				ensureFPR(r.ToolName).tn++
			}
		case model.LabelTimeout:
			c.timeouts++
			if isTN[r.ScenarioID] {
				ensureFPR(r.ToolName).tnTimeouts++
			}
		}
	}

	// Build ByToolAndClass.
	byToolAndClass := make(map[model.ToolName]map[model.ChainLengthClass]*model.ClassMetrics)
	for tool, perClass := range byClass {
		byToolAndClass[tool] = make(map[model.ChainLengthClass]*model.ClassMetrics)
		for cls, c := range perClass {
			if cls == model.ClassNone {
				continue
			}
			cm := &model.ClassMetrics{
				TP:       c.tp,
				FN:       c.fn,
				Timeouts: c.timeouts,
			}
			recallN := c.tp + c.fn // timeouts excluded from denominator
			rHat, rLow, rHigh := wilsonCI(c.tp, recallN)

			cm.Recall = model.MetricFloat(rHat)
			cm.RecallLow = model.MetricFloat(rLow)
			cm.RecallHigh = model.MetricFloat(rHigh)
			byToolAndClass[tool][cls] = cm
		}
	}

	// Build ByTool (aggregate across all classes per tool).
	byTool := make(map[model.ToolName]*model.ToolMetrics)
	for tool, perClass := range byClass {
		tm := &model.ToolMetrics{}
		var totalFP int
		for _, c := range perClass {
			tm.TP += c.tp
			totalFP += c.fp
			tm.FN += c.fn
			tm.Timeouts += c.timeouts
		}
		precN := tm.TP + totalFP
		recallN := tm.TP + tm.FN
		pHat, pLow, pHigh := wilsonCI(tm.TP, precN)
		rHat, rLow, rHigh := wilsonCI(tm.TP, recallN)
		tm.Precision = model.MetricFloat(pHat)
		tm.PrecisionLow = model.MetricFloat(pLow)
		tm.PrecisionHigh = model.MetricFloat(pHigh)
		tm.Recall = model.MetricFloat(rHat)
		tm.RecallLow = model.MetricFloat(rLow)
		tm.RecallHigh = model.MetricFloat(rHigh)
		p := float64(tm.Precision)
		r2 := float64(tm.Recall)
		if p+r2 > 0 {
			tm.F1 = model.MetricFloat(2 * p * r2 / (p + r2))
		}
		var vulnEval int
		for cls, c := range perClass {
			if cls != model.ClassNone {
				vulnEval += c.tp + c.fn + c.timeouts
			}
		}
		tm.VulnerableScenariosEvaluated = vulnEval
		byTool[tool] = tm
	}

	// Build FPRByTool (only when TN scenarios exist).
	// A tool appears in fprAcc only when it produced LabelFP or LabelTN results
	// on TN scenarios, which means its FPR was actually measured.
	fprByTool := make(map[model.ToolName]*model.FalsePositiveRate)
	for tool, fc := range fprAcc {
		n := fc.fp + fc.tn
		fprHat, fprLow, fprHigh := wilsonCI(fc.fp, n)
		fprByTool[tool] = &model.FalsePositiveRate{
			FP:          fc.fp,
			TN:          fc.tn,
			TNTimeouts:  fc.tnTimeouts,
			FPR:         model.MetricFloat(fprHat),
			FPRLow:      model.MetricFloat(fprLow),
			FPRHigh:     model.MetricFloat(fprHigh),
			FPRMeasured: true,
		}
	}

	// Sort results by scenario_id then tool_name for deterministic output.
	sort.Slice(results, func(i, j int) bool {
		if results[i].ScenarioID != results[j].ScenarioID {
			return results[i].ScenarioID < results[j].ScenarioID
		}
		return results[i].ToolName < results[j].ToolName
	})

	return &model.AggregationResult{
		RunID:          runID,
		GeneratedAt:    time.Now().UTC(),
		ByToolAndClass: byToolAndClass,
		ByTool:         byTool,
		FPRByTool:      fprByTool,
		Results:        results,
	}, nil
}

// RunIDForRun generates a deterministic UUIDv4 for use as a benchmark run ID.
// Callers that need a fresh ID should use uuid.NewString() directly; this
// helper exists only as a named entry point for documentation purposes.
func RunIDForRun() string {
	return uuid.NewString()
}
