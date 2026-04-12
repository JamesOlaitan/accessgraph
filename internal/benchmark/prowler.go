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

// prowlerPrivescCheckIDs lists Prowler check IDs whose FAIL findings indicate
// a privilege escalation risk. The adapter filters to this set before matching
// against ExpectedAttackPath. Without this filter, unrelated FAIL findings
// (MFA checks, password policy, CloudTrail logging, etc.) whose
// resources[].uid happens to match an ExpectedAttackPath ARN produce false
// matches that inflate Prowler's recall.
//
// Check IDs are the short names extracted from the OCSF finding_info.uid
// field (e.g., "iam_policy_allows_privilege_escalation" from
// "prowler-aws-iam_policy_allows_privilege_escalation-000000000000-...").
// Verified against Prowler 5.20.0 (prowler aws --list-checks).
var prowlerPrivescCheckIDs = map[string]bool{
	"iam_policy_allows_privilege_escalation":                    true,
	"iam_inline_policy_allows_privilege_escalation":             true,
	"iam_no_custom_policy_permissive_role_assumption":           true,
	"iam_customer_attached_policy_no_administrative_privileges": true,
	"iam_inline_policy_no_administrative_privileges":            true,
	"iam_role_administratoraccess_policy":                       true,
	"iam_user_administrator_access_policy":                      true,
	"iam_group_administrator_access_policy":                     true,
}

// prowlerOCSFResource is a single resource entry in a Prowler OCSF finding.
type prowlerOCSFResource struct {
	// UID is the resource identifier, typically an ARN.
	UID string `json:"uid"`
}

// prowlerOCSFFindingInfo holds the finding_info sub-object of an OCSF record.
type prowlerOCSFFindingInfo struct {
	// UID encodes the check name, account, region, and resource as a composite
	// string. Format: "prowler-aws-<check_name>-<account_id>-<region>-<resource>".
	UID string `json:"uid"`
}

// prowlerOCSFFinding is the minimal subset of a Prowler json-ocsf output record
// required for ground-truth comparison.
//
// Prowler 5.20.0's --output-formats json-ocsf produces an array of OCSF
// Detection Finding objects. The status_code field contains "FAIL" or "PASS".
// Resource ARNs are in resources[].uid. The check name is embedded in
// finding_info.uid.
type prowlerOCSFFinding struct {
	// StatusCode is "FAIL" for a detected issue or "PASS" for a compliant check.
	StatusCode string `json:"status_code"`

	// FindingInfo contains the finding UID from which the check name is extracted.
	FindingInfo prowlerOCSFFindingInfo `json:"finding_info"`

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
// field ("FAIL" or "PASS"), a finding_info.uid field encoding the check name,
// and a resources array where each resource has a uid field (the resource ARN).
//
// Only findings whose check name appears in prowlerPrivescCheckIDs are
// considered. This prevents unrelated compliance findings (MFA, password
// policy, CloudTrail logging) from matching ExpectedAttackPath ARNs.
//
// Returns true if any expected path node exactly matches a resource UID from a
// filtered FAIL finding.
func (a *prowlerAdapter) Parse(stdout []byte, expected model.Scenario) (bool, error) {
	var findings []prowlerOCSFFinding
	if parseErr := json.Unmarshal(stdout, &findings); parseErr != nil {
		return false, fmt.Errorf("%w: parsing prowler JSON: %v", ErrToolFailed, parseErr)
	}

	failARNs := make(map[string]bool)
	for _, f := range findings {
		if !strings.EqualFold(f.StatusCode, "FAIL") {
			continue
		}
		checkName := extractProwlerCheckName(f.FindingInfo.UID)
		if !prowlerPrivescCheckIDs[checkName] {
			continue
		}
		for _, r := range f.Resources {
			if r.UID != "" {
				failARNs[r.UID] = true
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

// extractProwlerCheckName extracts the Prowler check name from an OCSF
// finding_info.uid string. The UID format is
// "prowler-aws-<check_name>-<account_id>-<region>-<resource>". The check name
// uses underscores while the other components use hyphens, so splitting on the
// first account ID occurrence reliably isolates it.
func extractProwlerCheckName(uid string) string {
	const prefix = "prowler-aws-"
	if !strings.HasPrefix(uid, prefix) {
		return ""
	}
	rest := uid[len(prefix):]
	// Account IDs in LocalStack are "000000000000"; real accounts are 12 digits.
	// Split on the first occurrence of "-" followed by 12 digits.
	for i := 0; i < len(rest); i++ {
		if rest[i] == '-' && i+13 <= len(rest) {
			allDigits := true
			for j := i + 1; j <= i+12; j++ {
				if rest[j] < '0' || rest[j] > '9' {
					allDigits = false
					break
				}
			}
			if allDigits && (i+13 == len(rest) || rest[i+13] == '-') {
				return rest[:i]
			}
		}
	}
	return rest
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
