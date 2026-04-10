//go:build integration

// Package benchmark — Checkov adapter.
//
// Checkov exits non-zero when violations are found. Non-zero exit is not an error.
package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// checkovResult is the top-level structure of Checkov's JSON output when
// invoked with --output json.
type checkovResult struct {
	// Results holds the per-check outcome lists.
	Results checkovResults `json:"results"`
}

// checkovResults separates passing checks from failing checks.
type checkovResults struct {
	// FailedChecks is the list of checks that did not pass.
	FailedChecks []checkovCheck `json:"failed_checks"`
}

// checkovCheck represents a single failed Checkov check.
type checkovCheck struct {
	// CheckID is the Checkov rule identifier (e.g., "CKV_AWS_40").
	CheckID string `json:"check_id"`

	// Severity is the risk level reported by Checkov ("HIGH", "CRITICAL", etc.).
	// Note: older Checkov versions may leave this field empty.
	Severity string `json:"severity"`

	// Resource is the logical resource name or ARN that failed the check.
	Resource string `json:"resource"`
}

// checkovAdapter implements ToolAdapter for the Checkov infrastructure-as-code scanner.
type checkovAdapter struct{}

// Compile-time assertion that *checkovAdapter satisfies ToolAdapter.
var _ ToolAdapter = (*checkovAdapter)(nil)

// Invoke runs Checkov against the scenario directory.
func (a *checkovAdapter) Invoke(ctx context.Context, binaryPath, scenarioDir string) (stdout, stderr []byte, err error) {
	return runCheckov(ctx, binaryPath, scenarioDir)
}

// Parse interprets Checkov's JSON output to determine whether the expected
// attack path was detected.
//
// Parameters:
//   - stdout: combined stdout from the checkov invocation.
//   - expected: the scenario being evaluated.
//
// Returns:
//   - true if any expected path node exactly matches a resource ID from a HIGH or
//     CRITICAL failed check.
//
// Errors:
//   - ErrToolFailed if the output cannot be parsed as JSON.
func (a *checkovAdapter) Parse(stdout []byte, expected model.Scenario) (bool, error) {
	var result checkovResult
	if parseErr := json.Unmarshal(stdout, &result); parseErr != nil {
		return false, fmt.Errorf("%w: parsing checkov JSON: %v", ErrToolFailed, parseErr)
	}

	resourceIDs := make(map[string]bool, len(result.Results.FailedChecks))
	for _, check := range result.Results.FailedChecks {
		sev := strings.ToUpper(check.Severity)
		if sev == "HIGH" || sev == "CRITICAL" || sev == "" {
			// Include checks with empty severity to handle older Checkov
			// versions that do not emit severity in their JSON output.
			resourceIDs[check.Resource] = true
		}
	}
	for _, node := range expected.ExpectedAttackPath {
		if node != "" && resourceIDs[node] {
			return true, nil
		}
	}
	return false, nil
}

// runCheckov invokes the Checkov binary against the scenario directory and
// returns stdout and stderr separately.
//
// Checkov is invoked as:
//
//	checkov -d <scenarioDir> --framework terraform --output json
//
// Parameters:
//   - ctx: context for timeout and cancellation.
//   - binaryPath: path to the Checkov binary.
//   - scenarioDir: path to the directory containing the scenario's policy JSON files.
//
// Returns stdout and stderr as separate byte slices.
//
// Errors:
//   - ErrToolNotFound if the Checkov binary cannot be located.
//   - ErrToolFailed if Checkov exits with an unexpected status.
func runCheckov(ctx context.Context, binaryPath, scenarioDir string) ([]byte, []byte, error) {
	if _, err := exec.LookPath(binaryPath); err != nil {
		return nil, nil, fmt.Errorf("%w: %q: %v", ErrToolNotFound, binaryPath, err)
	}

	args := []string{
		"-d", scenarioDir,
		"--framework", "terraform",
		"--output", "json",
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, binaryPath, args...) //nolint:gosec
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()

	if err != nil {
		// Checkov exits 1 when checks fail (findings present); this is expected.
		// Any other non-zero exit code is treated as an execution failure.
		var ee *exec.ExitError
		if isExitError(err, &ee) {
			if ee.ExitCode() != 1 {
				return nil, nil, fmt.Errorf("%w: checkov exited %d: %s",
					ErrToolFailed, ee.ExitCode(), strings.TrimSpace(stderrBuf.String()))
			}
		} else {
			return nil, nil, fmt.Errorf("%w: running checkov: %v", ErrToolFailed, err)
		}
	}

	return stdoutBuf.Bytes(), stderrBuf.Bytes(), nil
}
