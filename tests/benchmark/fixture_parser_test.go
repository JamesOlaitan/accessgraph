//go:build integration

package benchmark_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/benchmark"
	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// TestProwlerParseRealOCSFSample exercises the Prowler adapter's Parse method
// against a real Prowler 5.20.0 json-ocsf capture from LocalStack.
func TestProwlerParseRealOCSFSample(t *testing.T) {
	data, err := os.ReadFile("testdata/prowler-sample-ocsf.json")
	if err != nil {
		t.Fatalf("reading prowler fixture: %v", err)
	}

	// Verify the file is valid JSON and is a non-empty array.
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("fixture is not valid JSON array: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("fixture contains zero findings")
	}

	// Verify the parser extracts findings. The fixture was captured against
	// LocalStack with a role that has AdministratorAccess attached, so a
	// FAIL finding on arn:aws:iam::000000000000:role/test-role should exist.
	scenario := model.Scenario{
		ID:                 "prowler-fixture-test",
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:role/test-role"},
	}

	adapter := benchmark.NewProwlerAdapter()
	detected, err := adapter.Parse(data, scenario)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("Parse() did not detect expected ARN in OCSF fixture")
	}

	// Verify that a non-existent ARN is not detected.
	noMatchScenario := model.Scenario{
		ID:                 "prowler-fixture-nomatch",
		ExpectedAttackPath: []string{"arn:aws:iam::999999999999:user/nonexistent"},
	}
	detected, err = adapter.Parse(data, noMatchScenario)
	if err != nil {
		t.Fatalf("Parse() error on no-match scenario: %v", err)
	}
	if detected {
		t.Error("Parse() should not detect non-existent ARN")
	}
}

// TestProwlerParseOCSFFieldNames verifies that the OCSF schema fields the
// parser depends on (status_code, resources[].uid) actually exist in the
// captured fixture.
func TestProwlerParseOCSFFieldNames(t *testing.T) {
	data, err := os.ReadFile("testdata/prowler-sample-ocsf.json")
	if err != nil {
		t.Fatalf("reading prowler fixture: %v", err)
	}

	var findings []map[string]any
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for i, f := range findings {
		if _, ok := f["status_code"]; !ok {
			t.Errorf("finding[%d] missing status_code field", i)
		}
		resources, ok := f["resources"]
		if !ok {
			t.Errorf("finding[%d] missing resources field", i)
			continue
		}
		resSlice, ok := resources.([]any)
		if !ok {
			t.Errorf("finding[%d] resources is not an array", i)
			continue
		}
		for j, r := range resSlice {
			rm, ok := r.(map[string]any)
			if !ok {
				t.Errorf("finding[%d].resources[%d] is not an object", i, j)
				continue
			}
			if _, ok := rm["uid"]; !ok {
				t.Errorf("finding[%d].resources[%d] missing uid field", i, j)
			}
		}
	}
}

// TestPMapperParseRealSample exercises the PMapper adapter's Parse method
// against a real PMapper 1.1.5 analysis capture from LocalStack.
func TestPMapperParseRealSample(t *testing.T) {
	data, err := os.ReadFile("testdata/pmapper-sample-analysis.json")
	if err != nil {
		t.Fatalf("reading pmapper fixture: %v", err)
	}

	// Verify the file is valid JSON with the expected top-level fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("fixture is not valid JSON object: %v", err)
	}
	for _, key := range []string{"account", "findings"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("fixture missing expected top-level field %q", key)
		}
	}

	// The fixture was captured with user/escalation-user able to assume
	// role/admin-role in account 000000000000.
	scenario := model.Scenario{
		ID:                 "pmapper-fixture-test",
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:user/escalation-user"},
	}

	adapter := benchmark.NewPMapperAdapter()
	detected, err := adapter.Parse(data, scenario)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("Parse() did not detect expected principal in analysis fixture")
	}

	// Also verify the admin role is detected.
	roleScenario := model.Scenario{
		ID:                 "pmapper-fixture-role",
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:role/admin-role"},
	}
	detected, err = adapter.Parse(data, roleScenario)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("Parse() did not detect admin-role in analysis fixture")
	}

	// Non-existent principal should not be detected.
	noMatchScenario := model.Scenario{
		ID:                 "pmapper-fixture-nomatch",
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:user/nonexistent"},
	}
	detected, err = adapter.Parse(data, noMatchScenario)
	if err != nil {
		t.Fatalf("Parse() error on no-match scenario: %v", err)
	}
	if detected {
		t.Error("Parse() should not detect non-existent principal")
	}
}

// TestPMapperParseFieldNames verifies that the analysis output schema fields
// the parser depends on (account, findings[].description) actually exist in
// the captured fixture.
func TestPMapperParseFieldNames(t *testing.T) {
	data, err := os.ReadFile("testdata/pmapper-sample-analysis.json")
	if err != nil {
		t.Fatalf("reading pmapper fixture: %v", err)
	}

	var analysis map[string]any
	if err := json.Unmarshal(data, &analysis); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, ok := analysis["account"]; !ok {
		t.Error("fixture missing account field")
	}

	findings, ok := analysis["findings"]
	if !ok {
		t.Fatal("fixture missing findings field")
	}
	fSlice, ok := findings.([]any)
	if !ok {
		t.Fatal("findings is not an array")
	}
	for i, f := range fSlice {
		fm, ok := f.(map[string]any)
		if !ok {
			t.Errorf("findings[%d] is not an object", i)
			continue
		}
		if _, ok := fm["description"]; !ok {
			t.Errorf("findings[%d] missing description field", i)
		}
	}
}
