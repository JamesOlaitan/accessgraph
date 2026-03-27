//go:build integration

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

// pmapperNode is the minimal representation of a node in PMapper's graph output.
//
// PMapper's "graph create" command produces a JSON graph where each node carries
// an ARN and type. The "analysis" subcommand produces privilege-escalation paths
// as sequences of node ARNs.
type pmapperNode struct {
	// ARN is the IAM principal ARN for this graph node.
	ARN string `json:"arn"`
}

// pmapperPath represents one privilege-escalation path reported by PMapper's
// analysis output.
//
// Each path is a sequence of node ARNs from the starting principal to the
// privilege-escalation target.
type pmapperPath struct {
	// Nodes is the ordered list of principal ARNs on this escalation path.
	Nodes []pmapperNode `json:"nodes"`
}

// pmapperAnalysis is the top-level structure of PMapper's JSON analysis output.
type pmapperAnalysis struct {
	// Paths is the list of discovered privilege-escalation paths.
	Paths []pmapperPath `json:"paths"`
}

// pmapperAdapter implements ToolAdapter for the PMapper IAM privilege escalation
// analysis tool.
type pmapperAdapter struct{}

// Compile-time assertion that *pmapperAdapter satisfies ToolAdapter.
var _ ToolAdapter = (*pmapperAdapter)(nil)

// Invoke runs PMapper against the scenario directory.
func (a *pmapperAdapter) Invoke(ctx context.Context, binaryPath, scenarioDir string) (stdout, stderr []byte, err error) {
	return runPMapper(ctx, binaryPath, scenarioDir)
}

// Parse interprets PMapper's JSON analysis output to determine whether the
// expected attack path was detected.
//
// Parameters:
//   - stdout: combined stdout from the pmapper analysis invocation.
//   - expected: the scenario being evaluated.
//
// Returns:
//   - true if any expected path node exactly matches a node ARN in the reported paths.
//
// Errors:
//   - ErrToolFailed if the output cannot be parsed as JSON.
func (a *pmapperAdapter) Parse(stdout []byte, expected model.Scenario) (bool, error) {
	var analysis pmapperAnalysis
	if parseErr := json.Unmarshal(stdout, &analysis); parseErr != nil {
		return false, fmt.Errorf("%w: parsing pmapper JSON: %v", ErrToolFailed, parseErr)
	}

	nodeARNs := make(map[string]bool)
	for _, p := range analysis.Paths {
		for _, n := range p.Nodes {
			nodeARNs[n.ARN] = true
		}
	}
	for _, node := range expected.ExpectedAttackPath {
		if node != "" && nodeARNs[node] {
			return true, nil
		}
	}
	return false, nil
}

// runPMapper invokes PMapper against exported IAM JSON and returns stdout and
// stderr separately.
//
// PMapper is invoked in two sequential steps:
//
//  1. Graph creation:
//     pmapper --input-dir <scenarioDir> graph create
//
//  2. Analysis:
//     pmapper --input-dir <scenarioDir> analysis --output json
//
// Parameters:
//   - ctx: context for timeout and cancellation.
//   - binaryPath: path to the PMapper binary.
//   - scenarioDir: path to the directory containing the scenario's IAM JSON files.
//
// Returns stdout and stderr as separate byte slices from PMapper's analysis output.
//
// Errors:
//   - ErrToolNotFound if the PMapper binary cannot be located.
//   - ErrToolFailed if PMapper exits non-zero or its output cannot be parsed.
func runPMapper(ctx context.Context, binaryPath, scenarioDir string) ([]byte, []byte, error) {
	if _, err := exec.LookPath(binaryPath); err != nil {
		return nil, nil, fmt.Errorf("%w: %q: %v", ErrToolNotFound, binaryPath, err)
	}

	// Step 1: build the graph from the offline scenario directory.
	createArgs := []string{
		"--input-dir", scenarioDir,
		"graph", "create",
	}
	var createStderr bytes.Buffer
	createCmd := exec.CommandContext(ctx, binaryPath, createArgs...) //nolint:gosec
	createCmd.Stderr = &createStderr
	// pmapper writes results to a JSON file; stdout is diagnostic only.
	if createErr := createCmd.Run(); createErr != nil {
		var ee *exec.ExitError
		if isExitError(createErr, &ee) {
			return nil, nil, fmt.Errorf("%w: pmapper graph create exited %d: %s",
				ErrToolFailed, ee.ExitCode(), strings.TrimSpace(createStderr.String()))
		}
		return nil, nil, fmt.Errorf("%w: running pmapper graph create: %v", ErrToolFailed, createErr)
	}

	// Step 2: run analysis and collect JSON output.
	analysisArgs := []string{
		"--input-dir", scenarioDir,
		"analysis",
		"--output", "json",
	}
	var stdoutBuf, stderrBuf bytes.Buffer
	analysisCmd := exec.CommandContext(ctx, binaryPath, analysisArgs...) //nolint:gosec
	analysisCmd.Stdout = &stdoutBuf
	analysisCmd.Stderr = &stderrBuf
	if err := analysisCmd.Run(); err != nil {
		var ee *exec.ExitError
		if isExitError(err, &ee) {
			return nil, nil, fmt.Errorf("%w: pmapper analysis exited %d: %s",
				ErrToolFailed, ee.ExitCode(), strings.TrimSpace(stderrBuf.String()))
		}
		return nil, nil, fmt.Errorf("%w: running pmapper analysis: %v", ErrToolFailed, err)
	}

	return stdoutBuf.Bytes(), stderrBuf.Bytes(), nil
}
