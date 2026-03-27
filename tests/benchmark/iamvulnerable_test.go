// Package benchmark_test exercises the IAMVulnerable scenario loader.
//
// Tests use only the standard library and temporary directories so they run
// offline without any external dependencies.
package benchmark_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/benchmark"
	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// writeManifest writes a ScenarioManifest as JSON into dir/manifest.json.
func writeManifest(t *testing.T, dir string, m benchmark.ScenarioManifest) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// writeIAMExport writes a minimal placeholder IAM export JSON file so that the
// scenario directory passes the "has at least one *.json file" check.
func writeIAMExport(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "iam_export.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write iam export: %v", err)
	}
}

// TestLoadScenariosEmpty verifies that LoadScenarios returns an empty slice
// (not an error) when rootDir contains no subdirectories.
func TestLoadScenariosEmpty(t *testing.T) {
	root := t.TempDir()

	scenarios, err := benchmark.LoadScenarios(root)
	if err != nil {
		t.Fatalf("LoadScenarios on empty dir: unexpected error: %v", err)
	}
	if len(scenarios) != 0 {
		t.Errorf("expected 0 scenarios, got %d", len(scenarios))
	}
}

// TestLoadScenariosBasic creates two scenario directories with valid manifests
// and asserts that LoadScenarios returns two correctly populated *model.Scenario
// values.
func TestLoadScenariosBasic(t *testing.T) {
	root := t.TempDir()

	dirs := []struct {
		name     string
		manifest benchmark.ScenarioManifest
	}{
		{
			name: "scenario-01",
			manifest: benchmark.ScenarioManifest{
				Name:               "CreatePolicyVersion",
				Description:        "Attach a new policy version",
				ChainLengthClass:   "simple",
				ExpectedAttackPath: []string{"arn:aws:iam::123:user/attacker", "arn:aws:iam::aws:policy/AdministratorAccess"},
				Category:           "direct_policy",
			},
		},
		{
			name: "scenario-02",
			manifest: benchmark.ScenarioManifest{
				Name:               "PassRoleLambda",
				Description:        "PassRole to Lambda then invoke",
				ChainLengthClass:   "two_hop",
				ExpectedAttackPath: []string{"arn:aws:iam::123:user/attacker", "arn:aws:lambda::123:function/escalate"},
				Category:           "passrole_chain",
			},
		},
	}

	for _, d := range dirs {
		dir := filepath.Join(root, d.name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d.name, err)
		}
		writeManifest(t, dir, d.manifest)
		writeIAMExport(t, dir)
	}

	scenarios, err := benchmark.LoadScenarios(root)
	if err != nil {
		t.Fatalf("LoadScenarios: unexpected error: %v", err)
	}
	if len(scenarios) != 2 {
		t.Fatalf("expected 2 scenarios, got %d", len(scenarios))
	}

	// Verify IDs follow the "iamvulnerable-<dirname>" convention.
	ids := map[string]bool{}
	for _, sc := range scenarios {
		ids[sc.ID] = true
	}
	for _, d := range dirs {
		expected := "iamvulnerable-" + d.name
		if !ids[expected] {
			t.Errorf("expected scenario ID %q not found in results", expected)
		}
	}

	// Spot-check first scenario fields.
	var sc01 *model.Scenario
	for _, sc := range scenarios {
		if sc.ID == "iamvulnerable-scenario-01" {
			sc01 = sc
			break
		}
	}
	if sc01 == nil {
		t.Fatal("scenario-01 not found in results")
	}
	if sc01.Name != "CreatePolicyVersion" {
		t.Errorf("Name: got %q want %q", sc01.Name, "CreatePolicyVersion")
	}
	if sc01.ChainLength != model.ClassSimple {
		t.Errorf("ChainLength: got %q want %q", sc01.ChainLength, model.ClassSimple)
	}
	if sc01.Category != model.CategoryDirectPolicy {
		t.Errorf("Category: got %q want %q", sc01.Category, model.CategoryDirectPolicy)
	}
	if len(sc01.ExpectedAttackPath) != 2 {
		t.Errorf("ExpectedAttackPath length: got %d want 2", len(sc01.ExpectedAttackPath))
	}
}

// TestLoadScenariosSkipsMissingManifest places one directory without a
// manifest.json alongside one with a valid manifest and asserts that the
// former is skipped (no error) while the latter is loaded.
func TestLoadScenariosSkipsMissingManifest(t *testing.T) {
	root := t.TempDir()

	// Directory without manifest.
	noManifest := filepath.Join(root, "no-manifest")
	if err := os.MkdirAll(noManifest, 0o755); err != nil {
		t.Fatalf("mkdir no-manifest: %v", err)
	}

	// Directory with a valid manifest.
	withManifest := filepath.Join(root, "with-manifest")
	if err := os.MkdirAll(withManifest, 0o755); err != nil {
		t.Fatalf("mkdir with-manifest: %v", err)
	}
	writeManifest(t, withManifest, benchmark.ScenarioManifest{
		Name:             "TestScenario",
		ChainLengthClass: "simple",
	})
	writeIAMExport(t, withManifest)

	scenarios, err := benchmark.LoadScenarios(root)
	if err != nil {
		t.Fatalf("LoadScenarios: unexpected error: %v", err)
	}
	if len(scenarios) != 1 {
		t.Errorf("expected 1 scenario (skipped missing manifest), got %d", len(scenarios))
	}
	if scenarios[0].ID != "iamvulnerable-with-manifest" {
		t.Errorf("unexpected scenario ID: %q", scenarios[0].ID)
	}
}

// TestLoadScenariosInvalidManifestJSON verifies that LoadScenarios returns a
// non-nil error when a manifest.json file contains invalid JSON.
func TestLoadScenariosInvalidManifestJSON(t *testing.T) {
	root := t.TempDir()

	bad := filepath.Join(root, "bad-scenario")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatalf("mkdir bad-scenario: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bad, "manifest.json"), []byte(`{not valid json}`), 0o644); err != nil {
		t.Fatalf("write bad manifest: %v", err)
	}

	_, err := benchmark.LoadScenarios(root)
	if err == nil {
		t.Error("LoadScenarios: expected error for invalid JSON manifest, got nil")
	}
}

// TestLoadScenariosEmptyRootDir verifies that passing an empty string returns
// a wrapped ErrInvalidInput error.
func TestLoadScenariosEmptyRootDir(t *testing.T) {
	_, err := benchmark.LoadScenarios("")
	if err == nil {
		t.Fatal("expected error for empty rootDir, got nil")
	}
	if !errors.Is(err, benchmark.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

// TestLoadScenariosNonexistentDir verifies that passing a path that does not
// exist returns a wrapped ErrInvalidInput error.
func TestLoadScenariosNonexistentDir(t *testing.T) {
	_, err := benchmark.LoadScenarios("/tmp/this-path-does-not-exist-accessgraph-test")
	if err == nil {
		t.Fatal("expected error for nonexistent rootDir, got nil")
	}
	if !errors.Is(err, benchmark.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

// TestLoadScenariosUnknownChainLengthClass verifies that an unrecognized
// chain_length_class in a manifest is coerced to ChainLengthSimple rather
// than causing an error.
func TestLoadScenariosUnknownChainLengthClass(t *testing.T) {
	root := t.TempDir()

	dir := filepath.Join(root, "unknown-chain")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeManifest(t, dir, benchmark.ScenarioManifest{
		Name:             "UnknownChain",
		ChainLengthClass: "not_a_real_class",
	})
	writeIAMExport(t, dir)

	scenarios, err := benchmark.LoadScenarios(root)
	if err != nil {
		t.Fatalf("LoadScenarios: unexpected error: %v", err)
	}
	if len(scenarios) != 1 {
		t.Fatalf("expected 1 scenario, got %d", len(scenarios))
	}
	if scenarios[0].ChainLength != model.ClassSimple {
		t.Errorf("ChainLength: got %q; want %q (should coerce unknown to simple)",
			scenarios[0].ChainLength, model.ClassSimple)
	}
}

// TestScenarioDirName verifies that ScenarioDirName strips the
// "iamvulnerable-" prefix and leaves non-prefixed IDs unchanged.
func TestScenarioDirName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"iamvulnerable-scenario-01", "scenario-01"},
		{"iamvulnerable-passrole", "passrole"},
		{"other-scenario", "other-scenario"},
		{"", ""},
	}
	for _, tc := range cases {
		got := benchmark.ScenarioDirName(tc.input)
		if got != tc.want {
			t.Errorf("ScenarioDirName(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}
