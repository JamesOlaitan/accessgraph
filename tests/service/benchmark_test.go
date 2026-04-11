package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/config"
	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/service"
)

// TestBenchmarkAccessGraphSelfEval verifies that service.RunBenchmark with
// --tools accessgraph produces a TP result for a synthetic scenario whose
// starting principal has AdministratorAccess attached. This exercises the
// facade wiring and the IAM export loader.
func TestBenchmarkAccessGraphSelfEval(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	fixtureDir := filepath.Join(filepath.Dir(thisFile), "testdata", "benchmark-synthetic")

	cfg := config.Load()
	cfg.DBPath = filepath.Join(t.TempDir(), "bench-test.db")

	var buf bytes.Buffer
	err := service.RunBenchmark(context.Background(), service.BenchmarkInput{
		ScenariosDir: fixtureDir,
		Tools:        "accessgraph",
		Output:       "json",
		Cfg:          cfg,
	}, &buf)
	if err != nil {
		t.Fatalf("RunBenchmark returned error: %v", err)
	}

	var ar model.AggregationResult
	if err := json.Unmarshal(buf.Bytes(), &ar); err != nil {
		t.Fatalf("unmarshalling benchmark output: %v", err)
	}

	if len(ar.Results) == 0 {
		t.Fatal("expected at least one result from AccessGraph self-evaluation, got 0")
	}

	var found bool
	for _, r := range ar.Results {
		if r.ToolName != model.ToolAccessGraph {
			continue
		}
		found = true
		if r.DetectionLabel != model.LabelTP {
			t.Errorf("expected detection_label %q for scenario %q, got %q",
				model.LabelTP, r.ScenarioID, r.DetectionLabel)
		}
	}
	if !found {
		t.Error("no result with tool_name=accessgraph found in results")
	}
}
