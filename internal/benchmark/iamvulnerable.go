package benchmark

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// ScenarioManifest is the JSON structure expected in a scenario's manifest.json
// file that lives at the root of each IAMVulnerable scenario directory.
// Fields correspond to the SCENARIO schema in docs/ARCHITECTURE.md.
//
// Fields:
//   - Name: the canonical scenario name as published in IAMVulnerable.
//   - Description: narrative description of the vulnerability being demonstrated.
//   - ChainLengthClass: one of "simple", "two_hop", "multi_hop", or "none" (for TN).
//   - ExpectedAttackPath: ordered sequence of ARNs that form the ground-truth path.
//   - StartingPrincipalARN: ARN of the BFS starting principal.
//   - Category: the IAMVulnerable escalation category (e.g., "direct_policy").
//   - IsTrueNegative: true if this scenario expects no escalation path.
type ScenarioManifest struct {
	Name                 string   `json:"name"`
	Description          string   `json:"description"`
	ChainLengthClass     string   `json:"chain_length_class"`
	ExpectedAttackPath   []string `json:"expected_attack_path"`
	StartingPrincipalARN string   `json:"starting_principal_arn"`
	Category             string   `json:"category"`
	IsTrueNegative       bool     `json:"is_true_negative"`
}

// LoadScenarios reads all IAMVulnerable scenarios from the given root directory.
//
// Each immediate subdirectory of rootDir that contains a manifest.json file is
// treated as one scenario. Directories missing a manifest.json are skipped with
// a slog.Warn log entry. Scenario IDs are assigned as "iamvulnerable-<dirname>".
//
// A valid scenario directory must contain:
//   - manifest.json   — parsed into a ScenarioManifest.
//   - One or more *.json files (IAM policy documents).
//
// Parameters:
//   - rootDir: path to the IAMVulnerable root directory containing scenario
//     subdirectories. Must be a non-empty string pointing at an existing directory.
//
// Returns a slice of *model.Scenario in the order returned by os.ReadDir.
//
// Errors:
//   - ErrInvalidInput if rootDir is empty or does not refer to an existing directory.
//   - A wrapped os or json error if reading or parsing the manifest fails for any
//     non-skipped directory.
func LoadScenarios(rootDir string) ([]*model.Scenario, error) {
	if rootDir == "" {
		return nil, fmt.Errorf("%w: rootDir must not be empty", ErrInvalidInput)
	}

	info, err := os.Stat(rootDir)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot stat rootDir %q: %v", ErrInvalidInput, rootDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: rootDir %q is not a directory", ErrInvalidInput, rootDir)
	}

	entries, err := os.ReadDir(rootDir)
	if err != nil {
		return nil, fmt.Errorf("reading rootDir %q: %w", rootDir, err)
	}

	var scenarios []*model.Scenario

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		scenarioDir := filepath.Join(rootDir, entry.Name())
		manifestPath := filepath.Join(scenarioDir, "manifest.json")

		if _, statErr := os.Stat(manifestPath); os.IsNotExist(statErr) {
			slog.Warn("skipping scenario directory: manifest.json not found",
				"dir", scenarioDir)
			continue
		}

		manifest, parseErr := parseManifest(manifestPath)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing manifest in %q: %w", scenarioDir, parseErr)
		}

		scenario := &model.Scenario{
			ID:                   "iamvulnerable-" + entry.Name(),
			Name:                 manifest.Name,
			Source:               "iamvulnerable",
			ChainLength:          chainLengthClass(manifest.ChainLengthClass, scenarioDir),
			ExpectedAttackPath:   manifest.ExpectedAttackPath,
			StartingPrincipalARN: manifest.StartingPrincipalARN,
			Description:          manifest.Description,
			Category:             scenarioCategory(manifest.Category, scenarioDir),
			IsTrueNegative:       manifest.IsTrueNegative,
		}

		scenarios = append(scenarios, scenario)
	}

	return scenarios, nil
}

// parseManifest reads and unmarshals a manifest.json file at the given path.
//
// Parameters:
//   - path: absolute or relative path to the manifest.json file.
//
// Returns the decoded ScenarioManifest.
//
// Errors: wrapped os or json error on read/parse failure.
func parseManifest(path string) (*ScenarioManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}

	var m ScenarioManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshalling %q: %w", path, err)
	}

	return &m, nil
}

// scenarioCategory converts the raw category string from a manifest into the
// typed model.ScenarioCategory constant. Unrecognised strings are coerced to
// ScenarioCategoryUnknown so that downstream aggregation always has a valid
// value. A warning is logged when an unrecognised value is encountered.
//
// Parameters:
//   - raw: the category string from the manifest.
//   - dir: the scenario directory path, used for diagnostic log output.
//
// Returns the corresponding model.ScenarioCategory.
func scenarioCategory(raw, dir string) model.ScenarioCategory {
	switch raw {
	case string(model.CategoryDirectPolicy):
		return model.CategoryDirectPolicy
	case string(model.CategoryCredentialManipulation):
		return model.CategoryCredentialManipulation
	case string(model.CategoryRoleTrust):
		return model.CategoryRoleTrust
	case string(model.CategoryPassRoleChain):
		return model.CategoryPassRoleChain
	case string(model.CategoryServiceAbuse):
		return model.CategoryServiceAbuse
	case string(model.CategoryNone):
		return model.CategoryNone
	default:
		slog.Warn("iamvulnerable: unrecognized category; defaulting to none",
			slog.String("value", raw),
			slog.String("scenario_dir", dir),
		)
		return model.CategoryNone
	}
}

// chainLengthClass converts the raw string from a manifest into the typed
// model.ChainLengthClass constant. Unrecognised strings are coerced to
// ChainLengthSimple so that downstream aggregation always has a valid value.
// A warning is logged when an unrecognised value is encountered.
//
// Parameters:
//   - raw: the chain_length_class string from the manifest.
//   - dir: the scenario directory path, used for diagnostic log output.
//
// Returns the corresponding model.ChainLengthClass.
func chainLengthClass(raw, dir string) model.ChainLengthClass {
	switch raw {
	case string(model.ClassSimple):
		return model.ClassSimple
	case string(model.ClassTwoHop):
		return model.ClassTwoHop
	case string(model.ClassMultiHop):
		return model.ClassMultiHop
	case string(model.ClassNone):
		return model.ClassNone
	default:
		slog.Warn("iamvulnerable: unrecognized chain_length_class; defaulting to simple",
			slog.String("value", raw),
			slog.String("scenario_dir", dir),
		)
		return model.ClassSimple
	}
}
