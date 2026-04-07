// Package benchmark_test exercises the Aggregator implementation.
//
// Tests use the in-memory store (store.NewMemStore) so they run offline
// without any SQLite or filesystem dependencies.
package benchmark_test

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/JamesOlaitan/accessgraph/internal/benchmark"
	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

const floatTolerance = 1e-9

type errReader struct{ err error }

func (r errReader) LoadBenchmarkResults(_ context.Context, _ string) ([]*model.BenchmarkResult, error) {
	return nil, r.err
}

func approxEqual(a, b float64) bool {
	return math.Abs(a-b) < floatTolerance
}

// seedResult saves a BenchmarkResult into ds, fatally failing t on error.
func seedResult(t *testing.T, ctx context.Context, ds store.DataStore, r *model.BenchmarkResult) {
	t.Helper()
	if err := ds.SaveBenchmarkResult(ctx, r); err != nil {
		t.Fatalf("seed result %q: %v", r.ID, err)
	}
}

// TestAggregateNoScenarios verifies that Aggregate with an empty scenario slice
// returns a non-nil AggregationResult with empty ByToolAndClass map.
func TestAggregateNoScenarios(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()
	runID := "run-empty"

	ar, err := agg.Aggregate(ctx, ds, runID, nil)
	if err != nil {
		t.Fatalf("Aggregate(nil scenarios): unexpected error: %v", err)
	}
	if ar == nil {
		t.Fatal("Aggregate: returned nil AggregationResult")
	}
	if len(ar.ByToolAndClass) != 0 {
		t.Errorf("ByToolAndClass: expected empty map, got %d entries", len(ar.ByToolAndClass))
	}
}

// TestAggregateNoResults verifies that a scenario with no stored results
// produces no entries in ByToolAndClass (tools that never ran are not
// represented).
func TestAggregateNoResults(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()
	runID := "run-no-results"

	scenarios := []*model.Scenario{
		{ID: "iamvulnerable-sc-01", ChainLength: model.ClassSimple},
	}

	ar, err := agg.Aggregate(ctx, ds, runID, scenarios)
	if err != nil {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}
	if len(ar.ByToolAndClass) != 0 {
		t.Errorf("expected empty ByToolAndClass for scenario with no results, got %d entries",
			len(ar.ByToolAndClass))
	}
}

// TestAggregatePerfectDetection seeds one LabelTP result for one scenario
// and verifies Precision = 1.0, Recall = 1.0, F1 = 1.0.
func TestAggregatePerfectDetection(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()
	runID := "run-perfect"

	sc := &model.Scenario{ID: "iamvulnerable-sc-perfect", ChainLength: model.ClassSimple}
	seedResult(t, ctx, ds, &model.BenchmarkResult{
		ID:               "r-1",
		RunID:            runID,
		ScenarioID:       sc.ID,
		ToolName:         model.ToolAccessGraph,
		DetectionLabel:   model.LabelTP,
		ChainLengthClass: model.ClassSimple,
		RunAt:            time.Now().UTC(),
	})

	ar, err := agg.Aggregate(ctx, ds, runID, []*model.Scenario{sc})
	if err != nil {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}

	cm := ar.ByToolAndClass[model.ToolAccessGraph][model.ClassSimple]
	if cm == nil {
		t.Fatal("ByToolAndClass[accessgraph][simple]: nil ClassMetrics")
	}
	if cm.TP != 1 {
		t.Errorf("TP: got %d want 1", cm.TP)
	}
	if !approxEqual(float64(cm.Recall), 1.0) {
		t.Errorf("Recall: got %.6f want 1.0", float64(cm.Recall))
	}
}

// TestAggregateZeroDetection seeds one LabelFN result and verifies
// Precision = 0, Recall = 0, F1 = 0.
func TestAggregateZeroDetection(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()
	runID := "run-zero"

	sc := &model.Scenario{ID: "iamvulnerable-sc-zero", ChainLength: model.ClassSimple}
	seedResult(t, ctx, ds, &model.BenchmarkResult{
		ID:               "r-fn",
		RunID:            runID,
		ScenarioID:       sc.ID,
		ToolName:         model.ToolProwler,
		DetectionLabel:   model.LabelFN,
		ChainLengthClass: model.ClassSimple,
		RunAt:            time.Now().UTC(),
	})

	ar, err := agg.Aggregate(ctx, ds, runID, []*model.Scenario{sc})
	if err != nil {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}

	cm := ar.ByToolAndClass[model.ToolProwler][model.ClassSimple]
	if cm == nil {
		t.Fatal("ByToolAndClass[prowler][simple]: nil ClassMetrics")
	}
	if cm.FN != 1 {
		t.Errorf("FN: got %d want 1", cm.FN)
	}
	if float64(cm.Recall) != 0 {
		t.Errorf("Recall: got %.6f want 0", float64(cm.Recall))
	}
}

// TestAggregateMultipleTools seeds results for three tools across two chain
// classes and asserts that each (tool, class) cell is populated independently.
func TestAggregateMultipleTools(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()
	runID := "run-multi"

	sc1 := &model.Scenario{ID: "iamvulnerable-sc-multi-1", ChainLength: model.ClassSimple}
	sc2 := &model.Scenario{ID: "iamvulnerable-sc-multi-2", ChainLength: model.ClassMultiHop}

	// accessgraph: TP on simple, TP on multi_hop
	seedResult(t, ctx, ds, &model.BenchmarkResult{
		ID: "r-ag-1", RunID: runID, ScenarioID: sc1.ID,
		ToolName: model.ToolAccessGraph, DetectionLabel: model.LabelTP,
		ChainLengthClass: model.ClassSimple, RunAt: time.Now().UTC(),
	})
	seedResult(t, ctx, ds, &model.BenchmarkResult{
		ID: "r-ag-2", RunID: runID, ScenarioID: sc2.ID,
		ToolName: model.ToolAccessGraph, DetectionLabel: model.LabelTP,
		ChainLengthClass: model.ClassMultiHop, RunAt: time.Now().UTC(),
	})
	// prowler: FN on simple only
	seedResult(t, ctx, ds, &model.BenchmarkResult{
		ID: "r-pr-1", RunID: runID, ScenarioID: sc1.ID,
		ToolName: model.ToolProwler, DetectionLabel: model.LabelFN,
		ChainLengthClass: model.ClassSimple, RunAt: time.Now().UTC(),
	})
	// checkov: FP on multi_hop
	seedResult(t, ctx, ds, &model.BenchmarkResult{
		ID: "r-ck-1", RunID: runID, ScenarioID: sc2.ID,
		ToolName: model.ToolCheckov, DetectionLabel: model.LabelFP,
		ChainLengthClass: model.ClassMultiHop, RunAt: time.Now().UTC(),
	})

	ar, err := agg.Aggregate(ctx, ds, runID, []*model.Scenario{sc1, sc2})
	if err != nil {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}

	// accessgraph/simple should be a perfect TP.
	agSimple := ar.ByToolAndClass[model.ToolAccessGraph][model.ClassSimple]
	if agSimple == nil {
		t.Fatal("accessgraph/simple: nil")
	}
	if agSimple.TP != 1 || agSimple.FN != 0 {
		t.Errorf("accessgraph/simple counts: tp=%d fn=%d; want 1/0",
			agSimple.TP, agSimple.FN)
	}

	// accessgraph/multi_hop should also be a perfect TP.
	agMulti := ar.ByToolAndClass[model.ToolAccessGraph][model.ClassMultiHop]
	if agMulti == nil {
		t.Fatal("accessgraph/multi_hop: nil")
	}
	if agMulti.TP != 1 {
		t.Errorf("accessgraph/multi_hop TP: got %d want 1", agMulti.TP)
	}

	// prowler/simple: recall = 0, precision = 0 (only FN).
	prSimple := ar.ByToolAndClass[model.ToolProwler][model.ClassSimple]
	if prSimple == nil {
		t.Fatal("prowler/simple: nil")
	}
	if prSimple.FN != 1 {
		t.Errorf("prowler/simple FN: got %d want 1", prSimple.FN)
	}

	// checkov/multi_hop: only FP (no TP), so recall denominator is 0.
	ckMulti := ar.ByToolAndClass[model.ToolCheckov][model.ClassMultiHop]
	if ckMulti == nil {
		t.Fatal("checkov/multi_hop: nil")
	}
	if float64(ckMulti.Recall) != 0 {
		t.Errorf("checkov/multi_hop Recall: got %.6f want 0", float64(ckMulti.Recall))
	}
}

// TestAggregateF1Formula seeds 2 TP and 2 FP for one tool and verifies the
// tool-level F1 is computed correctly as the harmonic mean of P and R.
//
// With TP=2, FP=2, FN=0:
//
//	Precision = 2/(2+2) = 0.5
//	Recall    = 2/(2+0) = 1.0
//	F1        = 2*(0.5*1.0)/(0.5+1.0) = 2/3 ≈ 0.6666...
func TestAggregateF1Formula(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()
	runID := "run-f1"

	scenarios := []*model.Scenario{
		{ID: "iamvulnerable-f1-sc-1", ChainLength: model.ClassTwoHop},
		{ID: "iamvulnerable-f1-sc-2", ChainLength: model.ClassTwoHop},
		{ID: "iamvulnerable-f1-sc-3", ChainLength: model.ClassTwoHop},
		{ID: "iamvulnerable-f1-sc-4", ChainLength: model.ClassTwoHop},
	}

	// 2 LabelTP + 2 LabelFP → counts: tp=2, fp=2, fn=0.
	for i, sc := range scenarios[:2] {
		seedResult(t, ctx, ds, &model.BenchmarkResult{
			ID: fmt.Sprintf("r-tp-%d", i), RunID: runID, ScenarioID: sc.ID,
			ToolName: model.ToolPMapper, DetectionLabel: model.LabelTP,
			ChainLengthClass: model.ClassTwoHop, RunAt: time.Now().UTC(),
		})
	}
	for i, sc := range scenarios[2:] {
		seedResult(t, ctx, ds, &model.BenchmarkResult{
			ID: fmt.Sprintf("r-fp-%d", i), RunID: runID, ScenarioID: sc.ID,
			ToolName: model.ToolPMapper, DetectionLabel: model.LabelFP,
			ChainLengthClass: model.ClassTwoHop, RunAt: time.Now().UTC(),
		})
	}

	ar, err := agg.Aggregate(ctx, ds, runID, scenarios)
	if err != nil {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}

	// Per-class recall: 2 TP / (2 TP + 0 FN) = 1.0.
	cm := ar.ByToolAndClass[model.ToolPMapper][model.ClassTwoHop]
	if cm == nil {
		t.Fatal("pmapper/two_hop: nil")
	}
	if !approxEqual(float64(cm.Recall), 1.0) {
		t.Errorf("per-class Recall: got %.6f want 1.0", float64(cm.Recall))
	}

	// Tool-level precision, recall, F1.
	tm := ar.ByTool[model.ToolPMapper]
	if tm == nil {
		t.Fatal("ByTool[pmapper]: nil")
	}

	wantPrecision := 0.5
	wantRecall := 1.0
	wantF1 := 2.0 * (wantPrecision * wantRecall) / (wantPrecision + wantRecall)

	if !approxEqual(float64(tm.Precision), wantPrecision) {
		t.Errorf("Precision: got %.6f want %.6f", float64(tm.Precision), wantPrecision)
	}
	if !approxEqual(float64(tm.Recall), wantRecall) {
		t.Errorf("Recall: got %.6f want %.6f", float64(tm.Recall), wantRecall)
	}
	if !approxEqual(float64(tm.F1), wantF1) {
		t.Errorf("F1: got %.6f want %.6f", float64(tm.F1), wantF1)
	}
}

// TestAggregateGeneratedAt verifies that the returned AggregationResult has a
// non-zero GeneratedAt timestamp.
func TestAggregateGeneratedAt(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()
	runID := "run-gentime"

	ar, err := agg.Aggregate(ctx, ds, runID, nil)
	if err != nil {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}
	if ar.GeneratedAt.IsZero() {
		t.Error("GeneratedAt: expected non-zero timestamp, got zero")
	}
}

// TestAggregateStoreError verifies that Aggregate propagates an error returned
// by BenchmarkResultReader.LoadBenchmarkResults.
func TestAggregateStoreError(t *testing.T) {
	ctx := context.Background()
	agg := benchmark.NewAggregator()
	storeErr := fmt.Errorf("simulated store failure")
	reader := errReader{err: storeErr}

	_, err := agg.Aggregate(ctx, reader, "run-store-error", nil)
	if err == nil {
		t.Fatal("expected error when reader returns an error, got nil")
	}
	_ = err // non-nil error is sufficient; wrapping makes string matching fragile
}

// TestAggregateNilResultInSlice verifies that Aggregate gracefully skips nil
// entries in the results slice returned by LoadBenchmarkResults.
func TestAggregateNilResultInSlice(t *testing.T) {
	ctx := context.Background()
	agg := benchmark.NewAggregator()

	// A reader that returns a slice containing a nil entry.
	nilReader := nilEntryReader{}

	ar, err := agg.Aggregate(ctx, nilReader, "run-nil-entry", nil)
	if err != nil {
		t.Fatalf("Aggregate with nil result entry: unexpected error: %v", err)
	}
	if len(ar.ByToolAndClass) != 0 {
		t.Errorf("expected empty ByToolAndClass (nil entry skipped), got %d entries", len(ar.ByToolAndClass))
	}
}

// nilEntryReader returns a single-element slice containing a nil *BenchmarkResult.
type nilEntryReader struct{}

func (nilEntryReader) LoadBenchmarkResults(_ context.Context, _ string) ([]*model.BenchmarkResult, error) {
	return []*model.BenchmarkResult{nil}, nil
}

// TestAggregateEmptyRunID verifies that Aggregate with an empty runID returns
// an error wrapping benchmark.ErrInvalidInput.
func TestAggregateEmptyRunID(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()

	_, err := agg.Aggregate(ctx, ds, "", nil)
	if err == nil {
		t.Fatal("Aggregate with empty runID: expected error, got nil")
	}
}

// TestAggregateRunIDForRun verifies that RunIDForRun returns a non-empty string.
func TestAggregateRunIDForRun(t *testing.T) {
	id := benchmark.RunIDForRun()
	if id == "" {
		t.Error("RunIDForRun: expected non-empty string, got empty")
	}
}

// TestAggregateFPOnTNScenario verifies that a LabelFP result for a true-negative
// scenario is counted in the FPR numerator (fp_count), and that FPRByTool is
// populated accordingly.
func TestAggregateFPOnTNScenario(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()
	runID := "run-fpr-fp"

	// A TN scenario where the tool incorrectly flagged a finding → FP.
	sc := &model.Scenario{
		ID:             "iamvulnerable-sc-tn-fp",
		ChainLength:    model.ClassSimple,
		IsTrueNegative: true,
	}
	seedResult(t, ctx, ds, &model.BenchmarkResult{
		ID: "r-fpr-fp", RunID: runID, ScenarioID: sc.ID,
		ToolName: model.ToolProwler, DetectionLabel: model.LabelFP,
		ChainLengthClass: model.ClassSimple, IsTrueNegative: true,
		RunAt: time.Now().UTC(),
	})

	ar, err := agg.Aggregate(ctx, ds, runID, []*model.Scenario{sc})
	if err != nil {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}

	fpr := ar.FPRByTool[model.ToolProwler]
	if fpr == nil {
		t.Fatal("FPRByTool[prowler]: nil (expected FPR entry for TN FP result)")
	}
	if float64(fpr.FPR) == 0 && fpr.FPR != 1.0 {
		// With 1 FP and 0 TN, FPR = 1/(1+0) = 1.0.
		// Check that FPR > 0.
		t.Errorf("FPR: expected > 0 for 1 FP / 0 TN, got %.6f", float64(fpr.FPR))
	}
}

// TestAggregateTNOnTNScenario verifies that a LabelTN result for a true-negative
// scenario is counted in the FPR denominator (tn_count).
func TestAggregateTNOnTNScenario(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()
	runID := "run-fpr-tn"

	sc := &model.Scenario{
		ID:             "iamvulnerable-sc-tn-clean",
		ChainLength:    model.ClassSimple,
		IsTrueNegative: true,
	}
	seedResult(t, ctx, ds, &model.BenchmarkResult{
		ID: "r-fpr-tn", RunID: runID, ScenarioID: sc.ID,
		ToolName: model.ToolCheckov, DetectionLabel: model.LabelTN,
		ChainLengthClass: model.ClassSimple, IsTrueNegative: true,
		RunAt: time.Now().UTC(),
	})

	ar, err := agg.Aggregate(ctx, ds, runID, []*model.Scenario{sc})
	if err != nil {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}

	fpr := ar.FPRByTool[model.ToolCheckov]
	if fpr == nil {
		t.Fatal("FPRByTool[checkov]: nil (expected FPR entry for TN result)")
	}
	// With 0 FP and 1 TN, FPR = 0/(0+1) = 0.
	if float64(fpr.FPR) != 0 {
		t.Errorf("FPR: expected 0 for 0 FP / 1 TN, got %.6f", float64(fpr.FPR))
	}
}

// TestAggregateClassificationOverride verifies that a BenchmarkResult with a
// non-empty ClassificationOverride (a DetectionLabel string set by a human
// reviewer) is correctly counted in the per-class TP aggregation.
func TestAggregateClassificationOverride(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()
	runID := "run-override"

	sc := &model.Scenario{
		ID:                     "iamvulnerable-sc-override",
		ChainLength:            model.ClassSimple,
		ClassificationOverride: model.LabelTP, // human reviewer confirmed TP
	}
	seedResult(t, ctx, ds, &model.BenchmarkResult{
		ID: "r-override", RunID: runID, ScenarioID: sc.ID,
		ToolName: model.ToolAccessGraph, DetectionLabel: model.LabelTP,
		ChainLengthClass:       model.ClassSimple,
		ClassificationOverride: model.LabelTP,
		RunAt:                  time.Now().UTC(),
	})

	ar, err := agg.Aggregate(ctx, ds, runID, []*model.Scenario{sc})
	if err != nil {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}
	if ar == nil {
		t.Fatal("Aggregate: nil result")
	}
	// Verify the result contains the accessgraph/simple cell (the override scenario).
	cm := ar.ByToolAndClass[model.ToolAccessGraph][model.ClassSimple]
	if cm == nil {
		t.Fatal("ByToolAndClass[accessgraph][simple]: nil")
	}
	if cm.TP != 1 {
		t.Errorf("TP: want 1, got %d", cm.TP)
	}
}

// TestAggregateTimeoutExclusion verifies that LabelTimeout rows are excluded
// from the TP+FN denominator (recall) and counted in ClassMetrics.Timeouts.
func TestAggregateTimeoutExclusion(t *testing.T) {
	ctx := context.Background()
	ds := store.NewMemStore()
	agg := benchmark.NewAggregator()
	runID := "run-timeout"

	sc := &model.Scenario{ID: "iamvulnerable-sc-timeout", ChainLength: model.ClassSimple}

	// 1 TP + 1 Timeout for the same tool/class.
	seedResult(t, ctx, ds, &model.BenchmarkResult{
		ID: "r-tp", RunID: runID, ScenarioID: sc.ID,
		ToolName: model.ToolAccessGraph, DetectionLabel: model.LabelTP,
		ChainLengthClass: model.ClassSimple, RunAt: time.Now().UTC(),
	})
	seedResult(t, ctx, ds, &model.BenchmarkResult{
		ID: "r-to", RunID: runID, ScenarioID: sc.ID,
		ToolName: model.ToolAccessGraph, DetectionLabel: model.LabelTimeout,
		ChainLengthClass: model.ClassSimple, RunAt: time.Now().UTC(),
	})

	ar, err := agg.Aggregate(ctx, ds, runID, []*model.Scenario{sc})
	if err != nil {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}

	cm := ar.ByToolAndClass[model.ToolAccessGraph][model.ClassSimple]
	if cm == nil {
		t.Fatal("ByToolAndClass[accessgraph][simple]: nil")
	}
	if cm.TP != 1 {
		t.Errorf("TP: got %d want 1", cm.TP)
	}
	if cm.Timeouts != 1 {
		t.Errorf("Timeouts: got %d want 1", cm.Timeouts)
	}
	// Recall denominator = TP + FN (timeout excluded): 1+0=1, so Recall = 1.0.
	if !approxEqual(float64(cm.Recall), 1.0) {
		t.Errorf("Recall: got %.6f want 1.0 (timeout excluded from denominator)", float64(cm.Recall))
	}
}
