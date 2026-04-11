//go:build integration

package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// privescFindingTitle is the exact finding title produced by PMapper's
// gen_privesc_findings() in principalmapper/analysis/find_risks.py. The parser
// filters on this title because pmapper analysis --output-type json bundles
// privilege escalation findings alongside unrelated finding types (circular
// access, overprivileged functions, MFA issues, etc.) that may mention the same
// principals incidentally. Extracting principal references from non-privesc
// findings would conflate "principal mentioned" with "escalation detected."
const privescFindingTitle = "IAM Principal Can Escalate Privileges"

// principalRefRe matches IAM principal references in PMapper's analysis
// description text. PMapper emits principals as type/name pairs such as
// "user/escalation-user" or "role/admin-role".
var principalRefRe = regexp.MustCompile(`(?:user|role|group)/[\w.+=,@-]+`)

// pmapperFinding is one entry in PMapper's analysis JSON output.
type pmapperFinding struct {
	// Title describes the class of finding (e.g., "IAM Principal Can Escalate Privileges").
	Title string `json:"title"`

	// Severity is the finding severity ("High", "Low", etc.).
	Severity string `json:"severity"`

	// Description contains the finding narrative, including principal names
	// in type/name format (e.g., "user/escalation-user", "role/admin-role").
	Description string `json:"description"`
}

// pmapperAnalysis is the top-level structure of PMapper's JSON analysis output
// from `pmapper --account <id> analysis --output-type json`.
type pmapperAnalysis struct {
	// Account is the AWS account ID of the analyzed graph.
	Account string `json:"account"`

	// Findings is the list of identified issues.
	Findings []pmapperFinding `json:"findings"`
}

// pmapperAdapter implements ToolAdapter for the PMapper IAM privilege escalation
// analysis tool.
type pmapperAdapter struct{}

// Compile-time assertion that *pmapperAdapter satisfies ToolAdapter.
var _ ToolAdapter = (*pmapperAdapter)(nil)

// Invoke reads PMapper's analysis output from the captured graph storage
// directory. The benchmark execution model for PMapper is replay-against-
// captured-fixture: the live `pmapper graph create` step is performed by the
// orchestration layer at capture time, and this adapter runs only the offline
// analysis step.
//
// The scenarioDir parameter points to the captured $PMAPPER_STORAGE directory
// (the parent of the <account-id>/ subdirectory). The adapter reads the account
// ID from the directory listing and runs:
//
//	PMAPPER_STORAGE=<scenarioDir> pmapper --account <id> analysis --output-type json
func (a *pmapperAdapter) Invoke(ctx context.Context, binaryPath, scenarioDir string) (stdout, stderr []byte, err error) {
	return runPMapper(ctx, binaryPath, scenarioDir)
}

// Parse interprets PMapper's JSON analysis output to determine whether the
// expected attack path was detected.
//
// PMapper's analysis output contains a flat findings array with multiple finding
// types. The parser filters to only findings with title privescFindingTitle
// ("IAM Principal Can Escalate Privileges") before extracting principal
// references. Other finding types (circular access, overprivileged instance
// profiles, MFA issues) may mention the same principals incidentally without
// indicating a detected escalation path.
//
// From each retained finding, the parser extracts principal references in
// type/name format (e.g., "user/escalation-user", "role/admin-role"),
// constructs full ARNs using the account ID from the analysis output, and
// checks for intersection with ExpectedAttackPath.
//
// Returns true if any constructed ARN matches any element of ExpectedAttackPath.
func (a *pmapperAdapter) Parse(stdout []byte, expected model.Scenario) (bool, error) {
	var analysis pmapperAnalysis
	if parseErr := json.Unmarshal(stdout, &analysis); parseErr != nil {
		return false, fmt.Errorf("%w: parsing pmapper JSON: %v", ErrToolFailed, parseErr)
	}

	principalARNs := make(map[string]bool)
	for _, f := range analysis.Findings {
		if f.Title != privescFindingTitle {
			continue
		}
		refs := principalRefRe.FindAllString(f.Description, -1)
		for _, ref := range refs {
			arn := fmt.Sprintf("arn:aws:iam::%s:%s", analysis.Account, ref)
			principalARNs[arn] = true
		}
	}

	for _, node := range expected.ExpectedAttackPath {
		if node != "" && principalARNs[node] {
			return true, nil
		}
	}
	return false, nil
}

// runPMapper invokes PMapper's offline analysis step against a captured graph
// storage directory and returns stdout and stderr separately.
//
// PMapper is invoked as:
//
//	PMAPPER_STORAGE=<scenarioDir> pmapper --account <accountID> analysis --output-type json
//
// The account ID is discovered by listing the subdirectories of scenarioDir;
// PMapper stores graph data in $PMAPPER_STORAGE/<account-id>/.
func runPMapper(ctx context.Context, binaryPath, scenarioDir string) ([]byte, []byte, error) {
	if scenarioDir == "" {
		return nil, nil, fmt.Errorf("%w: empty scenario directory", ErrToolFailed)
	}

	accountID, err := discoverPMapperAccountID(scenarioDir)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrToolFailed, err)
	}

	args := []string{
		"--account", accountID,
		"analysis",
		"--output-type", "json",
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, binaryPath, args...) //nolint:gosec
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	cmd.Env = append(os.Environ(), "PMAPPER_STORAGE="+scenarioDir)

	if runErr := cmd.Run(); runErr != nil {
		var ee *exec.ExitError
		if isExitError(runErr, &ee) {
			return nil, nil, fmt.Errorf("%w: pmapper analysis exited %d: %s",
				ErrToolFailed, ee.ExitCode(), strings.TrimSpace(stderrBuf.String()))
		}
		return nil, nil, fmt.Errorf("%w: running pmapper analysis: %v", ErrToolFailed, runErr)
	}

	return stdoutBuf.Bytes(), stderrBuf.Bytes(), nil
}

// discoverPMapperAccountID reads the first subdirectory name under storageDir.
// PMapper stores graph data in $PMAPPER_STORAGE/<account-id>/, so the
// subdirectory name is the account ID.
func discoverPMapperAccountID(storageDir string) (string, error) {
	entries, err := os.ReadDir(storageDir)
	if err != nil {
		return "", fmt.Errorf("reading pmapper storage dir %q: %v", storageDir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			return e.Name(), nil
		}
	}
	return "", fmt.Errorf("no account directory found in pmapper storage %q", storageDir)
}
