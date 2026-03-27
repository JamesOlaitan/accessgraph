//go:build integration

// Package benchmark — Prowler adapter.
//
// Prowler exits non-zero when findings are detected. A non-zero exit code is
// NOT treated as an error — it means findings were found. Only process errors
// (timeout, not found) are returned as errors.
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

// prowlerFinding is the minimal subset of a Prowler JSON output record that
// is required for ground-truth comparison.
//
// Prowler's --output-formats json produces an array of finding objects; each
// object contains at minimum a "resource_arn" field and a "status" field.
type prowlerFinding struct {
	// ResourceARN is the ARN of the resource that triggered the finding.
	ResourceARN string `json:"resource_arn"`

	// Status is "FAIL" for a detected issue or "PASS" for a compliant check.
	Status string `json:"status"`
}

// prowlerAdapter implements ToolAdapter for the Prowler AWS security scanner.
type prowlerAdapter struct{}

// Compile-time assertion that *prowlerAdapter satisfies ToolAdapter.
var _ ToolAdapter = (*prowlerAdapter)(nil)

// Invoke runs Prowler against the scenario directory.
func (a *prowlerAdapter) Invoke(ctx context.Context, binaryPath, scenarioDir string) (stdout, stderr []byte, err error) {
	return runProwler(ctx, binaryPath, scenarioDir)
}

// Parse interprets Prowler's JSON output to determine whether the expected
// attack path was detected.
//
// Parameters:
//   - stdout: combined stdout from the prowler invocation (may be empty if
//     Prowler wrote its JSON to the output directory instead).
//   - expected: the scenario being evaluated.
//
// Returns:
//   - true if any expected path node exactly matches a FAIL resource ARN.
//
// Errors:
//   - ErrToolFailed if the output cannot be parsed as JSON.
func (a *prowlerAdapter) Parse(stdout []byte, expected model.Scenario) (bool, error) {
	var findings []prowlerFinding
	if parseErr := json.Unmarshal(stdout, &findings); parseErr != nil {
		return false, fmt.Errorf("%w: parsing prowler JSON: %v", ErrToolFailed, parseErr)
	}

	failARNs := make(map[string]bool, len(findings))
	for _, f := range findings {
		if strings.EqualFold(f.Status, "FAIL") {
			failARNs[f.ResourceARN] = true
		}
	}
	for _, node := range expected.ExpectedAttackPath {
		if node != "" && failARNs[node] {
			return true, nil
		}
	}
	return false, nil
}

// runProwler invokes the Prowler binary against the scenario directory and
// returns stdout and stderr separately.
//
// Prowler is invoked as:
//
//	prowler aws --output-formats json --output-directory <tmpdir> --input-file <scenarioDir>
//
// If Prowler writes its output to a file rather than stdout, the first .json
// file in the temp output directory is read and returned as stdout.
//
// Parameters:
//   - ctx: context for timeout and cancellation.
//   - binaryPath: path to the Prowler binary.
//   - scenarioDir: path to the directory containing the scenario's policy JSON files.
//
// Returns stdout and stderr as separate byte slices.
//
// Errors:
//   - ErrToolNotFound if the Prowler binary cannot be located.
//   - ErrToolFailed if Prowler exits with an unexpected status.
func runProwler(ctx context.Context, binaryPath, scenarioDir string) ([]byte, []byte, error) {
	if _, err := exec.LookPath(binaryPath); err != nil {
		return nil, nil, fmt.Errorf("%w: %q: %v", ErrToolNotFound, binaryPath, err)
	}

	tmpDir, err := os.MkdirTemp("", "prowler-out-*")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: creating temp dir: %v", ErrToolFailed, err)
	}
	defer os.RemoveAll(tmpDir)

	args := []string{
		"aws",
		"--output-formats", "json",
		"--output-directory", tmpDir,
		"--input-file", scenarioDir,
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, binaryPath, args...) //nolint:gosec
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err = cmd.Run()

	if err != nil {
		// Prowler returns non-zero when it finds issues; treat exit code 3
		// (findings present) as a successful run with output, but treat other
		// non-zero codes as failures.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if ee.ExitCode() != 3 {
				return nil, nil, fmt.Errorf("%w: prowler exited %d: %s", ErrToolFailed, ee.ExitCode(), strings.TrimSpace(stderrBuf.String()))
			}
		} else {
			return nil, nil, fmt.Errorf("%w: running prowler: %v", ErrToolFailed, err)
		}
	}

	// Prowler may write JSON to stdout or to a file in tmpDir.
	// Prefer stdout; fall back to the first .json file in tmpDir.
	stdout := stdoutBuf.Bytes()
	if len(bytes.TrimSpace(stdout)) == 0 {
		stdout, err = readFirstJSONFile(tmpDir)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: reading prowler output: %v", ErrToolFailed, err)
		}
	}

	return stdout, stderrBuf.Bytes(), nil
}

// isExitError reports whether err is an *exec.ExitError and, if so, sets *out.
//
// Parameters:
//   - err: the error to inspect.
//   - out: pointer that receives the *exec.ExitError if the assertion succeeds.
//
// Returns true when err is an *exec.ExitError.
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
//
// Parameters:
//   - dir: directory to search.
//
// Returns the raw bytes of the first JSON file found.
//
// Errors: wrapped os error if the directory cannot be read or no JSON file exists.
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
//
// Parameters:
//   - stdout: the haystack bytes to search within.
//   - expected: the slice of needle strings to search for.
//
// Returns true if at least one element of expected is a substring of stdout.
func containsAny(stdout []byte, expected []string) bool {
	for _, e := range expected {
		if e != "" && bytes.Contains(stdout, []byte(e)) {
			return true
		}
	}
	return false
}
