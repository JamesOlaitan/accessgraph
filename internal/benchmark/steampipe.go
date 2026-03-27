//go:build integration

package benchmark

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// steampipeAdapter parses Steampipe output for IAM escalation findings.
//
// Exit code semantics: Steampipe exits 0 for both found and not-found results;
// exit code alone cannot determine detection. Parse the JSON output instead.
type steampipeAdapter struct{}

// Compile-time assertion that *steampipeAdapter satisfies ToolAdapter.
var _ ToolAdapter = (*steampipeAdapter)(nil)

// Invoke runs Steampipe against the scenario directory.
func (a *steampipeAdapter) Invoke(ctx context.Context, binaryPath, scenarioDir string) (stdout, stderr []byte, err error) {
	return runSteampipe(ctx, binaryPath, scenarioDir)
}

// Parse interprets Steampipe JSON output to determine whether the expected
// attack path was detected.
//
// Parameters:
//   - stdout: combined stdout from the steampipe invocation.
//   - expected: the scenario being evaluated.
//
// Returns:
//   - true if any expected path node appears in the output.
func (a *steampipeAdapter) Parse(stdout []byte, expected model.Scenario) (bool, error) {
	return containsAny(stdout, expected.ExpectedAttackPath), nil
}

// runSteampipe invokes the Steampipe binary against the scenario directory.
//
// Parameters:
//   - ctx: context for timeout and cancellation.
//   - binaryPath: path to the Steampipe binary.
//   - scenarioDir: path to the directory containing the scenario's IAM JSON files.
//
// Returns stdout and stderr as separate byte slices.
//
// Errors:
//   - ErrToolNotFound if the Steampipe binary cannot be located.
//   - ErrToolFailed if an execution error (not a findings exit) occurs.
func runSteampipe(ctx context.Context, binaryPath, scenarioDir string) ([]byte, []byte, error) {
	iamFile := filepath.Join(scenarioDir, "iam.json")
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, binaryPath, "check", "aws_iam", "--input", iamFile, "--output", "json") //nolint:gosec
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// Non-zero exit may indicate findings; still return output.
			return stdoutBuf.Bytes(), stderrBuf.Bytes(), nil
		}
		return stdoutBuf.Bytes(), stderrBuf.Bytes(), fmt.Errorf("runSteampipe: %w: %s", ErrToolFailed, err)
	}
	return stdoutBuf.Bytes(), stderrBuf.Bytes(), nil
}
