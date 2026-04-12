//go:build integration

// Package benchmark — Checkov adapter.
//
// The benchmark execution model for Checkov is replay-from-captured-output:
// the adapter reads a captured checkov.json file from the scenario fixture
// directory rather than invoking the Checkov binary. The live Checkov scan
// is performed at capture time by capture_scenario.sh. See
// docs/benchmark_methodology.md §3.3 and §7.0.
package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// CheckovFixtureFilename is the canonical filename for the captured Checkov
// output within each scenario directory.
const CheckovFixtureFilename = "checkov.json"

// checkovPrivescCheckIDs lists Checkov check IDs whose failed findings
// indicate a privilege escalation risk. The adapter filters to this set
// before matching against ExpectedAttackPath. Without this filter, unrelated
// failed checks (SSO enforcement, wildcard statements, policy attachment
// hygiene) inflate recall.
//
// Check IDs verified against Checkov 3.2.509 (bridgecrewio/checkov).
// Source: https://www.checkov.io/5.Policy%20Index/terraform.html
var checkovPrivescCheckIDs = map[string]bool{
	"CKV_AWS_286": true, // IAM policies do not allow privilege escalation
	"CKV_AWS_287": true, // IAM policies do not allow credentials exposure
	"CKV_AWS_289": true, // IAM policies do not allow permissions management without constraints
}

// checkovTFResourceToARNSuffix maps Terraform IAM resource types to the
// corresponding IAM ARN type/name suffix. Checkov outputs Terraform resource
// labels (e.g., "aws_iam_policy.my-policy") rather than AWS ARNs. The adapter
// uses this mapping to construct ARN suffixes for matching against
// ExpectedAttackPath.
var checkovTFResourceToARNSuffix = map[string]string{
	"aws_iam_policy": "policy/",
	"aws_iam_user":   "user/",
	"aws_iam_role":   "role/",
	"aws_iam_group":  "group/",
}

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

// Invoke reads captured Checkov JSON output from the scenario fixture directory.
// Checkov cannot be meaningfully re-executed offline against IAM export JSON; its
// Terraform framework scanner operates on .tf source files, which are only
// available inside the Docker image at capture time. The captured output file is
// the canonical fixture.
func (a *checkovAdapter) Invoke(_ context.Context, _, scenarioDir string) (stdout, stderr []byte, err error) {
	data, readErr := readCheckovFixture(scenarioDir)
	if readErr != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrToolFailed, readErr)
	}
	return data, nil, nil
}

// Parse interprets Checkov's JSON output to determine whether the expected
// attack path was detected.
//
// Checkov outputs Terraform resource labels (e.g., "aws_iam_policy.my-policy")
// as the resource identifier, not AWS ARNs. The parser converts these to ARN
// suffixes and checks whether any ExpectedAttackPath element ends with that
// suffix. Only findings whose check ID appears in checkovPrivescCheckIDs are
// considered.
//
// Returns true if any expected path node matches a converted resource from a
// filtered failed check.
func (a *checkovAdapter) Parse(stdout []byte, expected model.Scenario) (bool, error) {
	var result checkovResult
	if parseErr := json.Unmarshal(stdout, &result); parseErr != nil {
		return false, fmt.Errorf("%w: parsing checkov JSON: %v", ErrToolFailed, parseErr)
	}

	arnSuffixes := make(map[string]bool)
	for _, check := range result.Results.FailedChecks {
		if !checkovPrivescCheckIDs[check.CheckID] {
			continue
		}
		suffix := checkovResourceToARNSuffix(check.Resource)
		if suffix != "" {
			arnSuffixes[suffix] = true
		}
	}
	for _, node := range expected.ExpectedAttackPath {
		if node == "" {
			continue
		}
		for suffix := range arnSuffixes {
			if strings.HasSuffix(node, suffix) {
				return true, nil
			}
		}
	}
	return false, nil
}

// checkovResourceToARNSuffix converts a Terraform resource label to the
// corresponding IAM ARN suffix. For example:
//
//	"aws_iam_policy.my-policy" -> ":policy/my-policy"
//
// Returns an empty string if the resource type is not a recognized IAM type.
func checkovResourceToARNSuffix(resource string) string {
	parts := strings.SplitN(resource, ".", 2)
	if len(parts) != 2 {
		return ""
	}
	prefix, ok := checkovTFResourceToARNSuffix[parts[0]]
	if !ok {
		return ""
	}
	return ":" + prefix + parts[1]
}

// readCheckovFixture reads the checkov.json file from dir.
func readCheckovFixture(dir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, CheckovFixtureFilename))
}
