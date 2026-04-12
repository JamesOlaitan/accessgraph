package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/benchmark"
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

// TestScenarioRegistryDirResolution verifies that constructing a
// NewScenarioRegistry with a non-nil scenarioDirFn correctly resolves
// scenario directories. The closure captures the scenarios root and
// joins it with the directory name derived from the scenario ID.
func TestScenarioRegistryDirResolution(t *testing.T) {
	scenariosRoot := "/tmp/benchmark/scenarios"

	var captured string
	dirFn := func(sc *model.Scenario) string {
		captured = filepath.Join(scenariosRoot, benchmark.ScenarioDirName(sc.ID))
		return captured
	}

	registry := benchmark.NewScenarioRegistry(benchmark.ToolConfig{}, dirFn)
	runner, ok := registry[model.ToolProwler]
	if !ok {
		t.Fatal("expected Prowler runner in registry")
	}

	sc := &model.Scenario{ID: "iamvulnerable-privesc-iam-CreateNewPolicyVersion"}
	// RunScenario will fail (no real tool binary), but the dirFn is invoked.
	_, _ = runner.RunScenario(context.Background(), sc)

	want := filepath.Join(scenariosRoot, "privesc-iam-CreateNewPolicyVersion")
	if captured != want {
		t.Errorf("scenarioDirFn resolved %q, want %q", captured, want)
	}
}
