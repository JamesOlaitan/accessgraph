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

// cloudsploitAdapter parses CloudSploit output for IAM escalation findings.
//
// Exit code semantics: CloudSploit exits non-zero when findings are detected.
// A non-zero exit code indicates findings were found, not an execution error.
type cloudsploitAdapter struct{}

// Compile-time assertion that *cloudsploitAdapter satisfies ToolAdapter.
var _ ToolAdapter = (*cloudsploitAdapter)(nil)

// Invoke runs CloudSploit against the scenario directory.
func (a *cloudsploitAdapter) Invoke(ctx context.Context, binaryPath, scenarioDir string) (stdout, stderr []byte, err error) {
	return runCloudSploit(ctx, binaryPath, scenarioDir)
}

// Parse interprets CloudSploit output to determine whether the expected attack
// path was detected.
//
// Parameters:
//   - stdout: combined stdout from the cloudsploit invocation.
//   - expected: the scenario being evaluated.
//
// Returns:
//   - true if any expected path node appears in the output.
func (a *cloudsploitAdapter) Parse(stdout []byte, expected model.Scenario) (bool, error) {
	return containsAny(stdout, expected.ExpectedAttackPath), nil
}

// runCloudSploit invokes the CloudSploit binary against the scenario directory.
//
// Parameters:
//   - ctx: context for timeout and cancellation.
//   - binaryPath: path to the CloudSploit binary.
//   - scenarioDir: path to the directory containing the scenario's config files.
//
// Returns stdout and stderr as separate byte slices.
//
// Errors:
//   - ErrToolNotFound if the CloudSploit binary cannot be located.
//   - ErrToolFailed if an execution error (not a findings exit) occurs.
func runCloudSploit(ctx context.Context, binaryPath, scenarioDir string) ([]byte, []byte, error) {
	configFile := filepath.Join(scenarioDir, "config.js")
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, binaryPath, "--config", configFile, "--json") //nolint:gosec
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// Non-zero exit indicates findings; return output for parsing.
			return stdoutBuf.Bytes(), stderrBuf.Bytes(), nil
		}
		return stdoutBuf.Bytes(), stderrBuf.Bytes(), fmt.Errorf("runCloudSploit: %w: %s", ErrToolFailed, err)
	}
	return stdoutBuf.Bytes(), stderrBuf.Bytes(), nil
}
