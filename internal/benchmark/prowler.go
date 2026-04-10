//go:build integration

// Package benchmark -- Prowler adapter.
//
// The benchmark execution model for Prowler is replay-from-captured-output:
// the adapter reads a captured json-ocsf file from the scenario fixture
// directory rather than invoking the Prowler binary. See
// docs/benchmark_methodology.md §3.2 and §7.0.
package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// prowlerOCSFResource is a single resource entry in a Prowler OCSF finding.
type prowlerOCSFResource struct {
	// UID is the resource identifier, typically an ARN.
	UID string `json:"uid"`
}

// prowlerOCSFFinding is the minimal subset of a Prowler json-ocsf output record
// required for ground-truth comparison.
//
// Prowler 5.20.0's --output-formats json-ocsf produces an array of OCSF
// Detection Finding objects. The status_code field contains "FAIL" or "PASS".
// Resource ARNs are in resources[].uid.
type prowlerOCSFFinding struct {
	// StatusCode is "FAIL" for a detected issue or "PASS" for a compliant check.
	StatusCode string `json:"status_code"`

	// Resources is the list of resources associated with this finding.
	Resources []prowlerOCSFResource `json:"resources"`
}

// prowlerAdapter implements ToolAdapter for the Prowler AWS security scanner.
type prowlerAdapter struct{}

// Compile-time assertion that *prowlerAdapter satisfies ToolAdapter.
var _ ToolAdapter = (*prowlerAdapter)(nil)

// Invoke reads captured Prowler json-ocsf output from the scenario fixture
// directory. Prowler cannot be re-executed offline; its AWS provider requires
// live API access. The captured output file is the canonical fixture.
//
// The adapter looks for a file matching *.ocsf.json in scenarioDir.
// If no such file exists, it returns ErrToolFailed.
func (a *prowlerAdapter) Invoke(_ context.Context, _, scenarioDir string) (stdout, stderr []byte, err error) {
	data, readErr := readProwlerFixture(scenarioDir)
	if readErr != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrToolFailed, readErr)
	}
	return data, nil, nil
}

// Parse interprets Prowler's json-ocsf output to determine whether the expected
// attack path was detected.
//
// The output is parsed as []prowlerOCSFFinding. Each finding has a status_code
// field ("FAIL" or "PASS") and a resources array where each resource has a uid
// field (the resource ARN).
//
// Returns true if any expected path node exactly matches a resource UID from a
// FAIL finding.
func (a *prowlerAdapter) Parse(stdout []byte, expected model.Scenario) (bool, error) {
	var findings []prowlerOCSFFinding
	if parseErr := json.Unmarshal(stdout, &findings); parseErr != nil {
		return false, fmt.Errorf("%w: parsing prowler JSON: %v", ErrToolFailed, parseErr)
	}

	failARNs := make(map[string]bool)
	for _, f := range findings {
		if strings.EqualFold(f.StatusCode, "FAIL") {
			for _, r := range f.Resources {
				if r.UID != "" {
					failARNs[r.UID] = true
				}
			}
		}
	}
	for _, node := range expected.ExpectedAttackPath {
		if node != "" && failARNs[node] {
			return true, nil
		}
	}
	return false, nil
}

// readProwlerFixture reads the first *.ocsf.json file from dir.
func readProwlerFixture(dir string) ([]byte, error) {
	pattern := filepath.Join(dir, "*.ocsf.json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("globbing for prowler fixture in %q: %v", dir, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no *.ocsf.json file found in %q", dir)
	}
	return os.ReadFile(matches[0])
}

// isExitError reports whether err is an *exec.ExitError and, if so, sets *out.
func isExitError(err error, out **exec.ExitError) bool {
	if err == nil {
		return false
	}
	var ee *exec.ExitError
	if ok := errors.As(err, &ee); ok {
		if out != nil {
			*out = ee
		}
		return true
	}
	return false
}

// readFirstJSONFile returns the contents of the first *.json file found in dir.
func readFirstJSONFile(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			return os.ReadFile(filepath.Join(dir, e.Name()))
		}
	}
	return nil, fmt.Errorf("no JSON output file found in %q", dir)
}

// containsAny reports whether any element of expected appears as a substring of stdout.
func containsAny(stdout []byte, expected []string) bool {
	for _, e := range expected {
		if e != "" && bytes.Contains(stdout, []byte(e)) {
			return true
		}
	}
	return false
}
