package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/JamesOlaitan/accessgraph/internal/analyzer"
	"github.com/JamesOlaitan/accessgraph/internal/config"
	"github.com/JamesOlaitan/accessgraph/internal/graph"
	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/parser"
	"github.com/JamesOlaitan/accessgraph/internal/report"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// Input holds the parameters for the benchmark pipeline.
//
// Fields:
//   - ScenariosDir: directory containing IAMVulnerable scenario subdirectories.
//   - Tools: comma-separated tool list.
//   - OutputFormat: "terminal" or "json".
//   - Cfg: global configuration.
type Input struct {
	ScenariosDir string
	Tools        string
	OutputFormat string
	Cfg          *config.Config
}

// RunBenchmark executes the full benchmark pipeline:
//  1. Load scenarios.
//  2. Persist scenarios.
//  3. Run external tools against each scenario.
//  4. Run AccessGraph self-evaluation.
//  5. Persist all results.
//  6. Aggregate precision/recall metrics.
//  7. Render the comparison report.
//
// Parameters:
//   - ctx: context for cancellation.
//   - in: benchmark parameters.
//   - w: writer for the rendered output.
//
// Errors:
//   - Any store, runner, or rendering error.
func RunBenchmark(ctx context.Context, in Input, w io.Writer) error {
	// Validate format BEFORE any store access.
	validFormats := map[string]bool{"terminal": true, "json": true}
	if !validFormats[in.OutputFormat] {
		return fmt.Errorf("benchmark.RunBenchmark: unsupported format %q: %w", in.OutputFormat, ErrInvalidInput)
	}

	selectedTools := ParseToolList(in.Tools)
	if len(selectedTools) == 0 {
		return fmt.Errorf("benchmark.RunBenchmark: --tools produced an empty list")
	}

	scenarios, err := LoadScenarios(in.ScenariosDir)
	if err != nil {
		return fmt.Errorf("benchmark.RunBenchmark: load scenarios: %w", err)
	}
	if len(scenarios) == 0 {
		fmt.Fprintln(w, "warning: no scenarios found; nothing to benchmark")
		return nil
	}

	var ds store.DataStore
	sqliteStore, err := store.New(ctx, in.Cfg.DBPath)
	if err != nil {
		return fmt.Errorf("benchmark.RunBenchmark: open store: %w", err)
	}
	ds = sqliteStore
	defer sqliteStore.Close()

	for _, sc := range scenarios {
		if err := ds.SaveScenario(ctx, sc); err != nil {
			return fmt.Errorf("benchmark.RunBenchmark: save scenario %q: %w", sc.ID, err)
		}
	}

	runID := uuid.NewString()
	runner := newRunner(ToolConfig{})
	var allResults []*model.BenchmarkResult

	// External tool passes.
	for _, toolName := range selectedTools {
		if toolName == model.ToolAccessGraph {
			continue
		}
		for _, sc := range scenarios {
			scenarioDir := filepath.Join(in.ScenariosDir, ScenarioDirName(sc.ID))
			result, toolErr := runner.RunTool(ctx, toolName, scenarioDir, *sc)
			if toolErr != nil {
				fmt.Fprintf(w, "warning: tool %q scenario %q: %v (skipping)\n", toolName, sc.ID, toolErr)
				continue
			}
			result.ID = uuid.NewString()
			result.RunID = runID
			result.ResultID = model.ComputeResultID(runID, result.ScenarioID, result.ToolName)
			result.Category = sc.Category
			allResults = append(allResults, result)
		}
	}

	// AccessGraph self-evaluation pass.
	if ToolListContains(selectedTools, model.ToolAccessGraph) {
		for _, sc := range scenarios {
			agResult, agErr := runAccessGraphOnScenario(ctx, sc, in.ScenariosDir, in.Cfg)
			if agErr != nil {
				fmt.Fprintf(w, "warning: accessgraph scenario %q: %v (skipping)\n", sc.ID, agErr)
				continue
			}
			agResult.RunID = runID
			agResult.ResultID = model.ComputeResultID(runID, agResult.ScenarioID, agResult.ToolName)
			allResults = append(allResults, agResult)
		}
	}

	// Persist all results.
	for _, r := range allResults {
		if err := ds.SaveBenchmarkResult(ctx, r); err != nil {
			return fmt.Errorf("benchmark.RunBenchmark: save result %q: %w", r.ID, err)
		}
	}

	// Aggregate metrics.
	agg := NewAggregator()
	ar, err := agg.Aggregate(ctx, ds, runID, scenarios)
	if err != nil {
		return fmt.Errorf("benchmark.RunBenchmark: aggregate: %w", err)
	}

	// Populate metadata fields required by findings_schema.md.
	ar.SchemaVersion = "1.0.0"
	ar.Label = "run-" + ar.GeneratedAt.Format("20060102-150405")
	commitPath := filepath.Join(in.ScenariosDir, "..", "COMMIT")
	if data, err := os.ReadFile(commitPath); err == nil {
		ar.IAMVulnerableCommit = strings.TrimSpace(string(data))
	}

	// Save class metrics individually.
	for tool, classes := range ar.ByToolAndClass {
		for class, cm := range classes {
			if err := ds.SaveClassMetrics(ctx, runID, tool, class, cm); err != nil {
				return fmt.Errorf("benchmark.RunBenchmark: save class metrics %v/%v: %w", tool, class, err)
			}
		}
	}
	// Save tool metrics individually.
	for tool, tm := range ar.ByTool {
		if err := ds.SaveToolMetrics(ctx, runID, tool, tm); err != nil {
			return fmt.Errorf("benchmark.RunBenchmark: save tool metrics %v: %w", tool, err)
		}
	}
	// Save false positive rates individually.
	for tool, fpr := range ar.FPRByTool {
		if err := ds.SaveFalsePositiveRate(ctx, runID, tool, fpr); err != nil {
			return fmt.Errorf("benchmark.RunBenchmark: save FPR %v: %w", tool, err)
		}
	}

	// Render.
	reporter := report.NewReporter()
	switch in.OutputFormat {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(ar)
	default:
		return reporter.RenderAggregationResult(w, ar)
	}
}

// runAccessGraphOnScenario runs the full ingest+analyze pipeline for one scenario.
func runAccessGraphOnScenario(
	ctx context.Context,
	sc *model.Scenario,
	scenariosDir string,
	cfg *config.Config,
) (*model.BenchmarkResult, error) {
	start := time.Now()

	scenarioDir := filepath.Join(scenariosDir, ScenarioDirName(sc.ID))
	iamData, err := loadScenarioIAMData(scenarioDir)
	if err != nil {
		return nil, fmt.Errorf("loading IAM data for scenario %q: %w", sc.ID, err)
	}

	p := parser.NewAWSIAMParser()
	snapshot, err := p.ParseAWSIAM(ctx, iamData, sc.ID)
	if err != nil {
		return nil, fmt.Errorf("parsing IAM export: %w", err)
	}
	if err := analyzer.ClassifySensitiveResources(snapshot); err != nil {
		return nil, fmt.Errorf("classifying resources: %w", err)
	}

	engine, err := graph.NewEngine(snapshot)
	if err != nil {
		return nil, fmt.Errorf("building graph engine: %w", err)
	}
	if err := graph.SynthesizeEscalationEdges(engine, snapshot); err != nil {
		return nil, fmt.Errorf("synthesizing escalation edges: %w", err)
	}

	if len(sc.ExpectedAttackPath) == 0 {
		// TN scenarios have no expected attack path. Without a starting principal
		// AccessGraph cannot run BFS; treat as LabelTN (no false alarm possible).
		// Non-TN scenarios with no expected path are scored LabelFN.
		label := model.LabelFN
		if sc.IsTrueNegative {
			label = model.LabelTN
		}
		return &model.BenchmarkResult{
			ID:                 uuid.NewString(),
			ScenarioID:         sc.ID,
			ToolName:           model.ToolAccessGraph,
			DetectionLabel:     label,
			IsTrueNegative:     sc.IsTrueNegative,
			DetectionLatencyMs: time.Since(start).Milliseconds(),
			ChainLengthClass:   sc.ChainLength,
			Category:           sc.Category,
			TimeoutKind:        model.TimeoutNone,
			RunAt:              time.Now().UTC(),
		}, nil
	}

	fromARN := sc.ExpectedAttackPath[0]
	fromPrincipalID, err := resolvePrincipalByARN(snapshot, fromARN)
	if err != nil {
		// If we cannot resolve the starting principal, no paths can be found.
		// For TN scenarios this means no false alarm → LabelTN.
		label := model.LabelFN
		if sc.IsTrueNegative {
			label = model.LabelTN
		}
		return &model.BenchmarkResult{
			ID:                 uuid.NewString(),
			ScenarioID:         sc.ID,
			ToolName:           model.ToolAccessGraph,
			DetectionLabel:     label,
			IsTrueNegative:     sc.IsTrueNegative,
			DetectionLatencyMs: time.Since(start).Milliseconds(),
			ChainLengthClass:   sc.ChainLength,
			Category:           sc.Category,
			TimeoutKind:        model.TimeoutNone,
			RunAt:              time.Now().UTC(),
		}, nil
	}

	maxHops := cfg.MaxHops
	if maxHops < 1 {
		maxHops = 8
	}

	blastRadius, err := analyzer.NewAnalyzer().Analyze(ctx, engine, snapshot.ID, fromPrincipalID, maxHops)
	if err != nil {
		return nil, fmt.Errorf("blast-radius analysis: %w", err)
	}

	latency := time.Since(start).Milliseconds()
	label := classifyDetectionInternal(blastRadius, sc, snapshot)

	return &model.BenchmarkResult{
		ID:                 uuid.NewString(),
		ScenarioID:         sc.ID,
		ToolName:           model.ToolAccessGraph,
		DetectionLabel:     label,
		IsTrueNegative:     sc.IsTrueNegative,
		DetectionLatencyMs: latency,
		ChainLengthClass:   sc.ChainLength,
		Category:           sc.Category,
		TimeoutKind:        model.TimeoutNone,
		RunAt:              time.Now().UTC(),
	}, nil
}

func classifyDetectionInternal(br *model.BlastRadiusReport, sc *model.Scenario, snapshot *model.Snapshot) model.DetectionLabel {
	if sc.IsTrueNegative {
		if len(br.Paths) == 0 {
			return model.LabelTN
		}
		return model.LabelFP
	}
	if len(sc.ExpectedAttackPath) == 0 {
		return model.LabelFN
	}
	expectedTerminalARN := sc.ExpectedAttackPath[len(sc.ExpectedAttackPath)-1]
	resourceARNByID := make(map[string]string, len(snapshot.Resources))
	for _, r := range snapshot.Resources {
		if r != nil {
			resourceARNByID[r.ID] = r.ARN
		}
	}
	for _, path := range br.Paths {
		if path == nil {
			continue
		}
		if arn, ok := resourceARNByID[path.ToResourceID]; ok && arn == expectedTerminalARN {
			return model.LabelTP
		}
	}
	return model.LabelFN
}

func loadScenarioIAMData(scenarioDir string) ([]byte, error) {
	entries, err := os.ReadDir(scenarioDir)
	if err != nil {
		return nil, fmt.Errorf("reading scenario directory %q: %w", scenarioDir, err)
	}
	var candidates []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "manifest.json" || !strings.HasSuffix(name, ".json") {
			continue
		}
		candidates = append(candidates, name)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no IAM export JSON file found in %q", scenarioDir)
	}
	if len(candidates) > 1 {
		return nil, fmt.Errorf("ambiguous IAM export in %q: expected exactly one JSON file, found: %s",
			scenarioDir, strings.Join(candidates, ", "))
	}
	data, err := os.ReadFile(filepath.Join(scenarioDir, candidates[0]))
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", candidates[0], err)
	}
	return data, nil
}

// ScenarioDirName extracts the directory name component from a scenario ID.
func ScenarioDirName(scenarioID string) string {
	const prefix = "iamvulnerable-"
	if strings.HasPrefix(scenarioID, prefix) {
		return scenarioID[len(prefix):]
	}
	return scenarioID
}

// ParseToolList splits a comma-separated tool string into a slice of model.ToolName.
func ParseToolList(raw string) []model.ToolName {
	known := map[string]model.ToolName{
		string(model.ToolAccessGraph): model.ToolAccessGraph,
		string(model.ToolProwler):     model.ToolProwler,
		string(model.ToolPMapper):     model.ToolPMapper,
		string(model.ToolCheckov):     model.ToolCheckov,
		string(model.ToolSteampipe):   model.ToolSteampipe,
		string(model.ToolCloudSploit): model.ToolCloudSploit,
	}
	seen := make(map[model.ToolName]bool)
	var result []model.ToolName
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if tn, ok := known[part]; ok && !seen[tn] {
			seen[tn] = true
			result = append(result, tn)
		}
	}
	return result
}

// ToolListContains reports whether target appears in tools.
func ToolListContains(tools []model.ToolName, target model.ToolName) bool {
	for _, t := range tools {
		if t == target {
			return true
		}
	}
	return false
}

// resolvePrincipalByARN returns the internal principal ID for the given ARN
// within snapshot. It is a local copy of the same helper in the service package;
// duplicated here to avoid an import cycle between benchmark and service.
func resolvePrincipalByARN(snapshot *model.Snapshot, arn string) (string, error) {
	if arn == "" {
		return "", fmt.Errorf("ARN must not be empty")
	}
	for _, p := range snapshot.Principals {
		if p != nil && p.ARN == arn {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("no principal with ARN %q found in snapshot %q", arn, snapshot.ID)
}
