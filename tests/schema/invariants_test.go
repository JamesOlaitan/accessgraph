// Package schema_test validates the JSON schema invariants documented in
// docs/findings_schema.md section 3. All tests serialize through the renderer
// path (report.NewRendererRegistry()["json"].Render()), not via json.Marshal
// on model types directly.
package schema_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/JamesOlaitan/accessgraph/internal/benchmark"
	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/report"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// renderAnalysisJSON renders a model.Report through the JSON renderer and
// returns raw bytes.
func renderAnalysisJSON(t *testing.T, rpt *model.Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	renderer := report.NewRendererRegistry()["json"]
	if err := renderer.Render(&buf, rpt); err != nil {
		t.Fatalf("renderAnalysisJSON: %v", err)
	}
	return buf.Bytes()
}

// renderBenchmarkJSON wraps an AggregationResult in a Report and renders it
// through the JSON renderer, returning raw bytes.
func renderBenchmarkJSON(t *testing.T, ar *model.AggregationResult) []byte {
	t.Helper()
	rpt := &model.Report{AggregationResult: ar}
	var buf bytes.Buffer
	renderer := report.NewRendererRegistry()["json"]
	if err := renderer.Render(&buf, rpt); err != nil {
		t.Fatalf("renderBenchmarkJSON: %v", err)
	}
	return buf.Bytes()
}

// buildAnalysisFixture returns a realistic analysis report with 3 attack paths
// (hop counts 1, 2, 3) and 2 findings.
func buildAnalysisFixture(t *testing.T) *model.Report {
	t.Helper()
	return &model.Report{
		SchemaVersion:     "1.0.0",
		GeneratedAt:       time.Now().UTC(),
		PolicyEvalSkipped: false,
		Snapshot: &model.Snapshot{
			ID:    "snap-001",
			Label: "test-snapshot",
		},
		BlastRadius: &model.BlastRadiusReport{
			PrincipalID:             "arn:aws:iam::123456789012:user/alice",
			ReachableResourceCount:  5,
			PctEnvironmentReachable: model.MetricFloat(0.42),
			MinHopToAdmin:           2,
			DistinctPathCount:       3,
			Paths: []*model.AttackPath{
				{
					ID:                    "path-001",
					FromPrincipalID:       "arn:aws:iam::123456789012:user/alice",
					ToResourceID:          "arn:aws:iam::123456789012:role/admin",
					HopCount:              1,
					PathNodes:             []string{"alice", "admin"},
					PathEdges:             []string{"edge-1"},
					IsPrivilegeEscalation: true,
					ChainLengthClass:      model.ClassSimple,
				},
				{
					ID:                    "path-002",
					FromPrincipalID:       "arn:aws:iam::123456789012:user/alice",
					ToResourceID:          "arn:aws:iam::123456789012:role/deployer",
					HopCount:              2,
					PathNodes:             []string{"alice", "mid-role", "deployer"},
					PathEdges:             []string{"edge-2", "edge-3"},
					IsPrivilegeEscalation: true,
					ChainLengthClass:      model.ClassTwoHop,
				},
				{
					ID:                    "path-003",
					FromPrincipalID:       "arn:aws:iam::123456789012:user/alice",
					ToResourceID:          "arn:aws:iam::123456789012:role/root",
					HopCount:              3,
					PathNodes:             []string{"alice", "mid-1", "mid-2", "root"},
					PathEdges:             []string{"edge-4", "edge-5", "edge-6"},
					IsPrivilegeEscalation: true,
					ChainLengthClass:      model.ClassMultiHop,
				},
			},
		},
		Findings: []*model.Finding{
			{
				ID:          "finding-001",
				SnapshotID:  "snap-001",
				RuleID:      "IAM.WildcardAction",
				Severity:    model.SeverityHigh,
				EntityRef:   "arn:aws:iam::123456789012:user/alice",
				Reason:      "Wildcard action detected",
				Remediation: "Restrict actions to least privilege",
			},
			{
				ID:          "finding-002",
				SnapshotID:  "snap-001",
				RuleID:      "IAM.CrossAccountTrust",
				Severity:    model.SeverityCritical,
				EntityRef:   "arn:aws:iam::123456789012:role/admin",
				Reason:      "Cross-account trust allows external access",
				Remediation: "Remove external account from trust policy",
			},
		},
	}
}

// makeResult is a factory for benchmark results.
func makeResult(runID string, tool model.ToolName, scenarioID string, label model.DetectionLabel, cls model.ChainLengthClass, cat model.ScenarioCategory, isTN bool) *model.BenchmarkResult {
	stdout := "sample stdout"
	stderr := "sample stderr"
	tk := model.TimeoutNone
	if label == model.LabelTimeout {
		tk = model.TimeoutDeadline
	}
	return &model.BenchmarkResult{
		ID:                 fmt.Sprintf("res-%s-%s-%s", tool, scenarioID, runID[:8]),
		RunID:              runID,
		ResultID:           fmt.Sprintf("rid-%s-%s", tool, scenarioID),
		ScenarioID:         scenarioID,
		ToolName:           tool,
		DetectionLabel:     label,
		TimeoutKind:        tk,
		IsTrueNegative:     isTN,
		DetectionLatencyMs: 150,
		ChainLengthClass:   cls,
		Category:           cat,
		RunAt:              time.Now().UTC(),
		RawStdout:          &stdout,
		RawStderr:          &stderr,
	}
}

// scenarioFixtures returns the 6 scenarios used in the benchmark fixture.
func scenarioFixtures() []*model.Scenario {
	return []*model.Scenario{
		{ID: "sc-simple-1", Name: "Simple 1", ChainLength: model.ClassSimple, Category: model.CategoryDirectPolicy, IsTrueNegative: false},
		{ID: "sc-simple-2", Name: "Simple 2", ChainLength: model.ClassSimple, Category: model.CategoryCredentialManipulation, IsTrueNegative: false},
		{ID: "sc-two-hop-1", Name: "Two Hop 1", ChainLength: model.ClassTwoHop, Category: model.CategoryRoleTrust, IsTrueNegative: false},
		{ID: "sc-multi-hop-1", Name: "Multi Hop 1", ChainLength: model.ClassMultiHop, Category: model.CategoryPassRoleChain, IsTrueNegative: false},
		{ID: "tn-clean-001", Name: "TN Clean 1", ChainLength: model.ClassNone, Category: model.CategoryNone, IsTrueNegative: true},
		{ID: "tn-clean-002", Name: "TN Clean 2", ChainLength: model.ClassNone, Category: model.CategoryNone, IsTrueNegative: true},
	}
}

// buildBenchmarkFixture seeds a MemStore with 18 results (3 tools x 6
// scenarios), runs the Aggregator, and returns the AggregationResult with
// metadata populated.
func buildBenchmarkFixture(t *testing.T) *model.AggregationResult {
	t.Helper()
	ctx := context.Background()
	ms := store.NewMemStore()
	runID := "run-00000000-0000-0000-0000-000000000001"

	scenarios := scenarioFixtures()

	type entry struct {
		tool  model.ToolName
		sc    string
		label model.DetectionLabel
		cls   model.ChainLengthClass
		cat   model.ScenarioCategory
		isTN  bool
	}

	entries := []entry{
		{model.ToolAccessGraph, "sc-simple-1", model.LabelTP, model.ClassSimple, model.CategoryDirectPolicy, false},
		{model.ToolAccessGraph, "sc-simple-2", model.LabelTP, model.ClassSimple, model.CategoryCredentialManipulation, false},
		{model.ToolAccessGraph, "sc-two-hop-1", model.LabelTP, model.ClassTwoHop, model.CategoryRoleTrust, false},
		{model.ToolAccessGraph, "sc-multi-hop-1", model.LabelTimeout, model.ClassMultiHop, model.CategoryPassRoleChain, false},
		{model.ToolAccessGraph, "tn-clean-001", model.LabelTN, model.ClassNone, model.CategoryNone, true},
		{model.ToolAccessGraph, "tn-clean-002", model.LabelTN, model.ClassNone, model.CategoryNone, true},

		{model.ToolProwler, "sc-simple-1", model.LabelFN, model.ClassSimple, model.CategoryDirectPolicy, false},
		{model.ToolProwler, "sc-simple-2", model.LabelTP, model.ClassSimple, model.CategoryCredentialManipulation, false},
		{model.ToolProwler, "sc-two-hop-1", model.LabelFN, model.ClassTwoHop, model.CategoryRoleTrust, false},
		{model.ToolProwler, "sc-multi-hop-1", model.LabelFN, model.ClassMultiHop, model.CategoryPassRoleChain, false},
		{model.ToolProwler, "tn-clean-001", model.LabelFP, model.ClassNone, model.CategoryNone, true},
		{model.ToolProwler, "tn-clean-002", model.LabelTN, model.ClassNone, model.CategoryNone, true},

		{model.ToolPMapper, "sc-simple-1", model.LabelTP, model.ClassSimple, model.CategoryDirectPolicy, false},
		{model.ToolPMapper, "sc-simple-2", model.LabelTimeout, model.ClassSimple, model.CategoryCredentialManipulation, false},
		{model.ToolPMapper, "sc-two-hop-1", model.LabelTP, model.ClassTwoHop, model.CategoryRoleTrust, false},
		{model.ToolPMapper, "sc-multi-hop-1", model.LabelFN, model.ClassMultiHop, model.CategoryPassRoleChain, false},
		{model.ToolPMapper, "tn-clean-001", model.LabelTN, model.ClassNone, model.CategoryNone, true},
		{model.ToolPMapper, "tn-clean-002", model.LabelTimeout, model.ClassNone, model.CategoryNone, true},
	}

	for _, e := range entries {
		r := makeResult(runID, e.tool, e.sc, e.label, e.cls, e.cat, e.isTN)
		if err := ms.SaveBenchmarkResult(ctx, r); err != nil {
			t.Fatalf("SaveBenchmarkResult: %v", err)
		}
	}

	agg := benchmark.NewAggregator()
	ar, err := agg.Aggregate(ctx, ms, runID, scenarios)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	ar.SchemaVersion = "1.0.0"
	ar.IAMVulnerableCommit = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	ar.Label = "benchmark-test"

	return ar
}

// TestInvariant_FindingsEmptyWhenPolicySkipped verifies that findings is []
// (empty array), not null, when policy_eval_skipped is true.
func TestInvariant_FindingsEmptyWhenPolicySkipped(t *testing.T) {
	// Case 1: PolicyEvalSkipped=true, Findings=nil → must serialize as [].
	rpt := buildAnalysisFixture(t)
	rpt.PolicyEvalSkipped = true
	rpt.Findings = nil

	raw := renderAnalysisJSON(t, rpt)

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	findings := string(parsed["findings"])
	if findings != "[]" {
		t.Errorf("expected findings to be [] when policy_eval_skipped=true, got %s", findings)
	}

	// Case 2: PolicyEvalSkipped=false with 2 findings → must have length 2.
	rpt2 := buildAnalysisFixture(t)
	raw2 := renderAnalysisJSON(t, rpt2)

	var parsed2 struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw2, &parsed2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed2.Findings) != 2 {
		t.Errorf("expected 2 findings when not skipped, got %d", len(parsed2.Findings))
	}
}

// TestInvariant_MinHopToAdmin verifies min_hop_to_admin is -1 iff no admin
// path exists.
func TestInvariant_MinHopToAdmin(t *testing.T) {
	type blastRadius struct {
		MinHopToAdmin int `json:"min_hop_to_admin"`
	}
	type analysisJSON struct {
		BlastRadius blastRadius `json:"blast_radius"`
	}

	tests := []struct {
		name     string
		modify   func(*model.Report)
		expected int
	}{
		{
			name: "no paths",
			modify: func(rpt *model.Report) {
				rpt.BlastRadius.Paths = nil
				rpt.BlastRadius.MinHopToAdmin = -1
				rpt.BlastRadius.DistinctPathCount = 0
			},
			expected: -1,
		},
		{
			name: "paths without admin",
			modify: func(rpt *model.Report) {
				rpt.BlastRadius.MinHopToAdmin = -1
				for _, p := range rpt.BlastRadius.Paths {
					p.IsPrivilegeEscalation = false
				}
			},
			expected: -1,
		},
		{
			name: "paths with admin at hop 2",
			modify: func(rpt *model.Report) {
				rpt.BlastRadius.MinHopToAdmin = 2
			},
			expected: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rpt := buildAnalysisFixture(t)
			tc.modify(rpt)
			raw := renderAnalysisJSON(t, rpt)

			var out analysisJSON
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if out.BlastRadius.MinHopToAdmin != tc.expected {
				t.Errorf("min_hop_to_admin = %d, want %d", out.BlastRadius.MinHopToAdmin, tc.expected)
			}
		})
	}
}

// TestInvariant_DistinctPathCount verifies distinct_path_count == len(paths).
func TestInvariant_DistinctPathCount(t *testing.T) {
	rpt := buildAnalysisFixture(t)
	raw := renderAnalysisJSON(t, rpt)

	var out struct {
		BlastRadius struct {
			DistinctPathCount int               `json:"distinct_path_count"`
			Paths             []json.RawMessage `json:"paths"`
		} `json:"blast_radius"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.BlastRadius.DistinctPathCount != len(out.BlastRadius.Paths) {
		t.Errorf("distinct_path_count=%d but len(paths)=%d",
			out.BlastRadius.DistinctPathCount, len(out.BlastRadius.Paths))
	}
}

// TestInvariant_PathNodesLength verifies len(path_nodes) == hop_count+1 for
// each path.
func TestInvariant_PathNodesLength(t *testing.T) {
	rpt := buildAnalysisFixture(t)
	raw := renderAnalysisJSON(t, rpt)

	var out struct {
		BlastRadius struct {
			Paths []struct {
				HopCount  int      `json:"hop_count"`
				PathNodes []string `json:"path_nodes"`
			} `json:"paths"`
		} `json:"blast_radius"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for i, p := range out.BlastRadius.Paths {
		want := p.HopCount + 1
		if len(p.PathNodes) != want {
			t.Errorf("path[%d]: len(path_nodes)=%d, want hop_count+1=%d", i, len(p.PathNodes), want)
		}
	}
}

// TestInvariant_PathEdgesLength verifies len(path_edges) == hop_count for each
// path.
func TestInvariant_PathEdgesLength(t *testing.T) {
	rpt := buildAnalysisFixture(t)
	raw := renderAnalysisJSON(t, rpt)

	var out struct {
		BlastRadius struct {
			Paths []struct {
				HopCount  int      `json:"hop_count"`
				PathEdges []string `json:"path_edges"`
			} `json:"paths"`
		} `json:"blast_radius"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for i, p := range out.BlastRadius.Paths {
		if len(p.PathEdges) != p.HopCount {
			t.Errorf("path[%d]: len(path_edges)=%d, want hop_count=%d", i, len(p.PathEdges), p.HopCount)
		}
	}
}

// TestInvariant_FromPrincipalConsistency verifies from_principal_id on each
// path matches blast_radius.principal_id.
func TestInvariant_FromPrincipalConsistency(t *testing.T) {
	rpt := buildAnalysisFixture(t)
	raw := renderAnalysisJSON(t, rpt)

	var out struct {
		BlastRadius struct {
			PrincipalID string `json:"principal_id"`
			Paths       []struct {
				FromPrincipalID string `json:"from_principal_id"`
			} `json:"paths"`
		} `json:"blast_radius"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for i, p := range out.BlastRadius.Paths {
		if p.FromPrincipalID != out.BlastRadius.PrincipalID {
			t.Errorf("path[%d]: from_principal_id=%q != principal_id=%q",
				i, p.FromPrincipalID, out.BlastRadius.PrincipalID)
		}
	}
}

// TestInvariant_PathIDUniqueness verifies all path_id values are unique.
func TestInvariant_PathIDUniqueness(t *testing.T) {
	rpt := buildAnalysisFixture(t)
	raw := renderAnalysisJSON(t, rpt)

	var out struct {
		BlastRadius struct {
			Paths []struct {
				ID string `json:"path_id"`
			} `json:"paths"`
		} `json:"blast_radius"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	seen := make(map[string]bool)
	for _, p := range out.BlastRadius.Paths {
		if seen[p.ID] {
			t.Errorf("duplicate path_id: %q", p.ID)
		}
		seen[p.ID] = true
	}
}

// TestInvariant_FindingIDUniqueness verifies all finding_id values are unique.
func TestInvariant_FindingIDUniqueness(t *testing.T) {
	rpt := buildAnalysisFixture(t)
	raw := renderAnalysisJSON(t, rpt)

	var out struct {
		Findings []struct {
			ID string `json:"finding_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	seen := make(map[string]bool)
	for _, f := range out.Findings {
		if seen[f.ID] {
			t.Errorf("duplicate finding_id: %q", f.ID)
		}
		seen[f.ID] = true
	}
}

// TestInvariant_ResultCount verifies len(results) == tools * scenarios.
func TestInvariant_ResultCount(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	var out struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// 3 tools * 6 scenarios = 18
	if len(out.Results) != 18 {
		t.Errorf("len(results)=%d, want 18", len(out.Results))
	}
}

// TestInvariant_DetectionLabelTN verifies TN results have label in
// {FP, TN, TIMEOUT}.
func TestInvariant_DetectionLabelTN(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	var out struct {
		Results []struct {
			IsTrueNegative bool   `json:"is_true_negative"`
			Label          string `json:"detection_label"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	validTN := map[string]bool{"FP": true, "TN": true, "TIMEOUT": true}
	for i, r := range out.Results {
		if r.IsTrueNegative && !validTN[r.Label] {
			t.Errorf("result[%d]: is_true_negative=true but label=%q (want FP/TN/TIMEOUT)", i, r.Label)
		}
	}
}

// TestInvariant_DetectionLabelVulnerable verifies vulnerable results have label
// in {TP, FN, TIMEOUT}.
func TestInvariant_DetectionLabelVulnerable(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	var out struct {
		Results []struct {
			IsTrueNegative bool   `json:"is_true_negative"`
			Label          string `json:"detection_label"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	validVuln := map[string]bool{"TP": true, "FN": true, "TIMEOUT": true}
	for i, r := range out.Results {
		if !r.IsTrueNegative && !validVuln[r.Label] {
			t.Errorf("result[%d]: is_true_negative=false but label=%q (want TP/FN/TIMEOUT)", i, r.Label)
		}
	}
}

// TestInvariant_TNFieldValues verifies TN results have class="none" and
// category="none", and vulnerable results never have "none".
func TestInvariant_TNFieldValues(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	var out struct {
		Results []struct {
			IsTrueNegative   bool   `json:"is_true_negative"`
			ChainLengthClass string `json:"chain_length_class"`
			Category         string `json:"category"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for i, r := range out.Results {
		if r.IsTrueNegative {
			if r.ChainLengthClass != "none" {
				t.Errorf("result[%d]: TN but chain_length_class=%q, want none", i, r.ChainLengthClass)
			}
			if r.Category != "none" {
				t.Errorf("result[%d]: TN but category=%q, want none", i, r.Category)
			}
		} else {
			if r.ChainLengthClass == "none" {
				t.Errorf("result[%d]: vulnerable but chain_length_class=none", i)
			}
			if r.Category == "none" {
				t.Errorf("result[%d]: vulnerable but category=none", i)
			}
		}
	}
}

// TestInvariant_TPCountConsistency verifies by_tool[T].true_positives matches
// the count of TP results for T in the results array.
func TestInvariant_TPCountConsistency(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	var out struct {
		ByTool map[string]struct {
			TP int `json:"true_positives"`
		} `json:"by_tool"`
		Results []struct {
			ToolName string `json:"tool_name"`
			Label    string `json:"detection_label"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	counted := make(map[string]int)
	for _, r := range out.Results {
		if r.Label == "TP" {
			counted[r.ToolName]++
		}
	}

	for tool, tm := range out.ByTool {
		if tm.TP != counted[tool] {
			t.Errorf("by_tool[%s].true_positives=%d but counted %d TP results", tool, tm.TP, counted[tool])
		}
	}
}

// TestInvariant_PerToolScenarioCount verifies TP+FN+timeouts across classes
// equals vulnerable_scenarios_evaluated per tool.
func TestInvariant_PerToolScenarioCount(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	var out struct {
		ByTool map[string]struct {
			VulnEval int `json:"vulnerable_scenarios_evaluated"`
		} `json:"by_tool"`
		ByToolAndClass map[string]map[string]struct {
			TP       int `json:"true_positives"`
			FN       int `json:"false_negatives"`
			Timeouts int `json:"timeouts"`
		} `json:"by_tool_and_class"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for tool, classes := range out.ByToolAndClass {
		sum := 0
		for _, cm := range classes {
			sum += cm.TP + cm.FN + cm.Timeouts
		}
		vulnEval := out.ByTool[tool].VulnEval
		if sum != vulnEval {
			t.Errorf("tool %s: sum(TP+FN+timeouts across classes)=%d != vulnerable_scenarios_evaluated=%d", tool, sum, vulnEval)
		}
	}
}

// TestInvariant_PerClassCount verifies per-class TP+FN+timeouts equals the
// expected class size across all tools.
func TestInvariant_PerClassCount(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	// Expected scenario counts per class: simple=2, two_hop=1, multi_hop=1.
	expectedPerClass := map[string]int{
		"simple":    2,
		"two_hop":   1,
		"multi_hop": 1,
	}

	var out struct {
		ByToolAndClass map[string]map[string]struct {
			TP       int `json:"true_positives"`
			FN       int `json:"false_negatives"`
			Timeouts int `json:"timeouts"`
		} `json:"by_tool_and_class"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for tool, classes := range out.ByToolAndClass {
		for cls, cm := range classes {
			total := cm.TP + cm.FN + cm.Timeouts
			expected, ok := expectedPerClass[cls]
			if !ok {
				t.Errorf("tool %s: unexpected class %q in by_tool_and_class", tool, cls)
				continue
			}
			if total != expected {
				t.Errorf("tool %s class %s: TP+FN+timeouts=%d, want %d", tool, cls, total, expected)
			}
		}
	}
}

// TestInvariant_CommitFormat verifies iamvulnerable_commit is 40-char lowercase
// hex.
func TestInvariant_CommitFormat(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	var out struct {
		Commit string `json:"iamvulnerable_commit"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	re := regexp.MustCompile(`^[0-9a-f]{40}$`)
	if !re.MatchString(out.Commit) {
		t.Errorf("iamvulnerable_commit=%q does not match ^[0-9a-f]{40}$", out.Commit)
	}
}

// TestInvariant_RawFields verifies raw_stdout and raw_stderr are present in
// every result.
func TestInvariant_RawFields(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	var out struct {
		Results []map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for i, r := range out.Results {
		if _, ok := r["raw_stdout"]; !ok {
			t.Errorf("result[%d]: missing raw_stdout key", i)
		}
		if _, ok := r["raw_stderr"]; !ok {
			t.Errorf("result[%d]: missing raw_stderr key", i)
		}
	}
}

// TestInvariant_SchemaVersionPresent verifies schema_version is present in both
// analysis and benchmark report types.
func TestInvariant_SchemaVersionPresent(t *testing.T) {
	t.Run("analysis", func(t *testing.T) {
		rpt := buildAnalysisFixture(t)
		raw := renderAnalysisJSON(t, rpt)

		var out struct {
			SchemaVersion string `json:"schema_version"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out.SchemaVersion == "" {
			t.Error("schema_version is empty in analysis report")
		}
	})

	t.Run("benchmark", func(t *testing.T) {
		ar := buildBenchmarkFixture(t)
		raw := renderBenchmarkJSON(t, ar)

		var out struct {
			SchemaVersion string `json:"schema_version"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out.SchemaVersion == "" {
			t.Error("schema_version is empty in benchmark report")
		}
	})
}

// TestInvariant_FloatSixDecimalPlaces verifies all MetricFloat fields have
// exactly 6 decimal places in the serialized JSON.
func TestInvariant_FloatSixDecimalPlaces(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	// MetricFloat field names to check in the raw JSON.
	metricFields := []string{
		"precision", "recall", "f1",
		"precision_ci95_low", "precision_ci95_high",
		"recall_ci95_low", "recall_ci95_high",
		"fpr", "fpr_ci95_low", "fpr_ci95_high",
		"pct_environment_reachable",
	}

	// Match "field_name": <number> and extract the number.
	for _, field := range metricFields {
		pattern := fmt.Sprintf(`"%s":\s*(-?\d+\.\d+)`, regexp.QuoteMeta(field))
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(string(raw), -1)
		if len(matches) == 0 {
			// Not all fields appear in all reports; skip if absent.
			continue
		}
		sixDP := regexp.MustCompile(`^-?\d+\.\d{6}$`)
		for _, m := range matches {
			val := m[1]
			if !sixDP.MatchString(val) {
				t.Errorf("field %q has value %q which is not exactly 6 decimal places", field, val)
			}
		}
	}

	// Also check analysis report for pct_environment_reachable.
	rpt := buildAnalysisFixture(t)
	rawAnalysis := renderAnalysisJSON(t, rpt)
	pctPattern := regexp.MustCompile(`"pct_environment_reachable":\s*(-?\d+\.\d+)`)
	pctMatches := pctPattern.FindAllStringSubmatch(string(rawAnalysis), -1)
	sixDP := regexp.MustCompile(`^-?\d+\.\d{6}$`)
	for _, m := range pctMatches {
		if !sixDP.MatchString(m[1]) {
			t.Errorf("pct_environment_reachable=%q is not exactly 6 decimal places", m[1])
		}
	}
}

// TestInvariant_WilsonScoreBounds verifies 0 <= ci_low <= metric <= ci_high <= 1
// for precision/recall fields in by_tool and recall fields in by_tool_and_class.
func TestInvariant_WilsonScoreBounds(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	checkBounds := func(t *testing.T, label, name string, low, val, high float64) {
		t.Helper()
		if low < 0 || low > val || val > high || high > 1 {
			t.Errorf("%s %s: bounds violated: 0 <= %.6f <= %.6f <= %.6f <= 1",
				label, name, low, val, high)
		}
	}

	// by_tool has precision and recall.
	type toolMetrics struct {
		Precision     float64 `json:"precision"`
		PrecisionLow  float64 `json:"precision_ci95_low"`
		PrecisionHigh float64 `json:"precision_ci95_high"`
		Recall        float64 `json:"recall"`
		RecallLow     float64 `json:"recall_ci95_low"`
		RecallHigh    float64 `json:"recall_ci95_high"`
	}

	// by_tool_and_class has recall only.
	type classMetrics struct {
		Recall     float64 `json:"recall"`
		RecallLow  float64 `json:"recall_ci95_low"`
		RecallHigh float64 `json:"recall_ci95_high"`
	}

	var out struct {
		ByTool         map[string]toolMetrics             `json:"by_tool"`
		ByToolAndClass map[string]map[string]classMetrics `json:"by_tool_and_class"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for tool, m := range out.ByTool {
		label := "by_tool[" + tool + "]"
		checkBounds(t, label, "precision", m.PrecisionLow, m.Precision, m.PrecisionHigh)
		checkBounds(t, label, "recall", m.RecallLow, m.Recall, m.RecallHigh)
	}
	for tool, classes := range out.ByToolAndClass {
		for cls, m := range classes {
			label := fmt.Sprintf("by_tool_and_class[%s][%s]", tool, cls)
			checkBounds(t, label, "recall", m.RecallLow, m.Recall, m.RecallHigh)
		}
	}
}

// TestInvariant_NoneClassNotInByToolAndClass verifies that the class "none"
// never appears in by_tool_and_class (§3 invariant).
func TestInvariant_NoneClassNotInByToolAndClass(t *testing.T) {
	ar := buildBenchmarkFixture(t)
	raw := renderBenchmarkJSON(t, ar)

	var out struct {
		ByToolAndClass map[string]map[string]json.RawMessage `json:"by_tool_and_class"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for tool, classes := range out.ByToolAndClass {
		if _, ok := classes["none"]; ok {
			t.Errorf("by_tool_and_class[%s] contains class \"none\" — must be excluded", tool)
		}
	}
}
