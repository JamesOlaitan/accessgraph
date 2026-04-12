//go:build integration

// Package benchmark — PMapper adapter.
//
// The benchmark execution model for PMapper is replay-from-captured-output:
// the adapter reads a captured pmapper_findings.json file from the scenario
// fixture directory rather than invoking the PMapper binary. The live
// `pmapper graph create` and `pmapper analysis` steps are performed at
// capture time by capture_scenario.sh. See docs/benchmark_methodology.md
// §3.1 and §7.0.
package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// PMapperFindingsFilename is the canonical filename for the captured PMapper
// analysis output within each scenario directory.
const PMapperFindingsFilename = "pmapper_findings.json"

// privescFindingTitle is the exact finding title produced by PMapper's
// gen_privesc_findings() in principalmapper/analysis/find_risks.py. The parser
// filters on this title because pmapper analysis --output-type json bundles
// privilege escalation findings alongside unrelated finding types (circular
// access, overprivileged functions, MFA issues, etc.) that may mention the same
// principals incidentally. Extracting principal references from non-privesc
// findings would conflate "principal mentioned" with "escalation detected."
const privescFindingTitle = "IAM Principals Can Escalate Privileges"

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

// Invoke reads captured PMapper analysis JSON output from the scenario fixture
// directory and augments it with escalation-derived admin detections from the
// PMapper graph's nodes.json. The live `pmapper graph create` and
// `pmapper analysis` steps are performed at capture time by
// capture_scenario.sh; this adapter reads the resulting fixture files.
//
// If the PMapper graph files (nodes.json, groups.json, policies.json) are
// available, Invoke identifies nodes marked is_admin that do not have
// admin-equivalent policies attached (directly or through group membership)
// and appends synthetic escalation findings for them. If the graph files are
// unavailable, Invoke falls back to the raw pmapper_findings.json output.
func (a *pmapperAdapter) Invoke(_ context.Context, _, scenarioDir string) (stdout, stderr []byte, err error) {
	data, readErr := readPMapperFixture(scenarioDir)
	if readErr != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrToolFailed, readErr)
	}

	augmented, augErr := augmentPMapperFindings(data, scenarioDir)
	if augErr != nil {
		slog.Debug("pmapper: graph augmentation unavailable, using raw findings",
			slog.String("scenario_dir", scenarioDir),
			slog.String("reason", augErr.Error()),
		)
		return data, nil, nil
	}

	return augmented, nil, nil
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

// readPMapperFixture reads the pmapper_findings.json file from dir.
func readPMapperFixture(dir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, PMapperFindingsFilename))
}

// jsonStrOrSlice handles PMapper's polymorphic JSON fields where a value
// can be either a single string or an array of strings.
type jsonStrOrSlice []string

// UnmarshalJSON normalizes string | []string to []string.
func (j *jsonStrOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*j = []string{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*j = multi
	return nil
}

// pmapperPolicyRef is a policy reference in a node's or group's attached_policies list.
type pmapperPolicyRef struct {
	ARN  string `json:"arn"`
	Name string `json:"name"`
}

// pmapperNode is one entry in PMapper's nodes.json graph file.
type pmapperNode struct {
	ARN              string             `json:"arn"`
	AttachedPolicies []pmapperPolicyRef `json:"attached_policies"`
	GroupMemberships []string           `json:"group_memberships"`
	IsAdmin          bool               `json:"is_admin"`
}

// pmapperGroup is one entry in PMapper's groups.json graph file.
type pmapperGroup struct {
	ARN              string             `json:"arn"`
	AttachedPolicies []pmapperPolicyRef `json:"attached_policies"`
}

// pmapperPolicyEntry is one entry in PMapper's policies.json graph file.
type pmapperPolicyEntry struct {
	ARN       string           `json:"arn"`
	Name      string           `json:"name"`
	PolicyDoc pmapperPolicyDoc `json:"policy_doc"`
}

// pmapperPolicyDoc is the policy document structure within a PMapper policy entry.
// LocalStack-captured policies exhibit three Statement formats:
//   - array of objects (standard IAM)
//   - single object (some AWS managed policies)
//   - array of strings (a LocalStack serialization artifact)
//
// The custom UnmarshalJSON handles all three, silently skipping non-object entries.
type pmapperPolicyDoc struct {
	Statement []pmapperStatement
}

// UnmarshalJSON parses a policy document, tolerating non-standard Statement
// formats from LocalStack-captured AWS managed policies.
func (d *pmapperPolicyDoc) UnmarshalJSON(data []byte) error {
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return err
	}
	stmtRaw, ok := wrapper["Statement"]
	if !ok {
		d.Statement = nil
		return nil
	}

	// Try as array first (most common case).
	var entries []json.RawMessage
	if err := json.Unmarshal(stmtRaw, &entries); err == nil {
		d.Statement = nil
		for _, entry := range entries {
			var stmt pmapperStatement
			if json.Unmarshal(entry, &stmt) == nil {
				d.Statement = append(d.Statement, stmt)
			}
		}
		return nil
	}

	// Single object (some AWS managed policies).
	var single pmapperStatement
	if err := json.Unmarshal(stmtRaw, &single); err == nil {
		d.Statement = []pmapperStatement{single}
		return nil
	}

	d.Statement = nil
	return nil
}

// pmapperStatement is one statement within a PMapper policy document.
type pmapperStatement struct {
	Effect   string         `json:"Effect"`
	Action   jsonStrOrSlice `json:"Action"`
	Resource jsonStrOrSlice `json:"Resource"`
}

// isPMapperPolicyAdminEquivalent reports whether a PMapper policy entry
// satisfies the admin-equivalence criteria defined in findings_schema.md
// Section 1.1. This is a standalone check against PMapper's policy_doc
// format, mirroring the criteria in iampolicy.IsAdminEquivalentPolicy.
func isPMapperPolicyAdminEquivalent(arn string, doc pmapperPolicyDoc) bool {
	if arn == "arn:aws:iam::aws:policy/AdministratorAccess" {
		return true
	}
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		hasStarResource := false
		for _, r := range stmt.Resource {
			if r == "*" {
				hasStarResource = true
				break
			}
		}
		if !hasStarResource {
			continue
		}
		for _, a := range stmt.Action {
			lower := strings.ToLower(a)
			if lower == "*" || lower == "*:*" || lower == "iam:*" {
				return true
			}
		}
	}
	return false
}

// extractPrincipalRef extracts the type/name suffix from an IAM ARN.
// For example, "arn:aws:iam::000000000000:user/some-user" returns "user/some-user".
func extractPrincipalRef(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[5]
}

// augmentWithAdminNodes identifies escalation-derived admin nodes from
// PMapper's graph data and appends synthetic findings to the analysis.
//
// A node is an escalation-derived admin if is_admin is true AND none of
// its effective policies (direct attachments or group-inherited) satisfy
// admin-equivalence. Pre-existing admins (nodes with admin-equivalent
// policies attached directly or through group membership) are excluded.
func augmentWithAdminNodes(analysis *pmapperAnalysis, nodes []pmapperNode, groups []pmapperGroup, policies []pmapperPolicyEntry) {
	adminPolicyARNs := make(map[string]bool)
	for _, p := range policies {
		if isPMapperPolicyAdminEquivalent(p.ARN, p.PolicyDoc) {
			adminPolicyARNs[p.ARN] = true
		}
	}

	groupPolicies := make(map[string][]string)
	for _, g := range groups {
		for _, p := range g.AttachedPolicies {
			groupPolicies[g.ARN] = append(groupPolicies[g.ARN], p.ARN)
		}
	}

	for _, node := range nodes {
		if !node.IsAdmin {
			continue
		}

		preExisting := false
		for _, pol := range node.AttachedPolicies {
			if adminPolicyARNs[pol.ARN] {
				preExisting = true
				break
			}
		}
		if !preExisting {
			for _, groupARN := range node.GroupMemberships {
				for _, polARN := range groupPolicies[groupARN] {
					if adminPolicyARNs[polARN] {
						preExisting = true
						break
					}
				}
				if preExisting {
					break
				}
			}
		}

		if preExisting {
			continue
		}

		ref := extractPrincipalRef(node.ARN)
		if ref == "" {
			continue
		}

		analysis.Findings = append(analysis.Findings, pmapperFinding{
			Title:    privescFindingTitle,
			Severity: "High",
			Description: fmt.Sprintf(
				"PMapper graph node %s has is_admin=true without admin-equivalent "+
					"policies attached. Escalation-derived admin: %s",
				ref, ref,
			),
		})
	}
}

// augmentPMapperFindings reads PMapper's graph files from the scenario
// directory and augments the analysis with synthetic findings for
// escalation-derived admin nodes.
func augmentPMapperFindings(findingsData []byte, scenarioDir string) ([]byte, error) {
	var analysis pmapperAnalysis
	if err := json.Unmarshal(findingsData, &analysis); err != nil {
		return nil, fmt.Errorf("parsing findings: %v", err)
	}

	graphDir := filepath.Join(scenarioDir, "pmapper", analysis.Account, "graph")

	nodesData, err := os.ReadFile(filepath.Join(graphDir, "nodes.json"))
	if err != nil {
		return nil, fmt.Errorf("reading nodes.json: %w", err)
	}
	groupsData, err := os.ReadFile(filepath.Join(graphDir, "groups.json"))
	if err != nil {
		return nil, fmt.Errorf("reading groups.json: %w", err)
	}
	policiesData, err := os.ReadFile(filepath.Join(graphDir, "policies.json"))
	if err != nil {
		return nil, fmt.Errorf("reading policies.json: %w", err)
	}

	var nodes []pmapperNode
	if err := json.Unmarshal(nodesData, &nodes); err != nil {
		return nil, fmt.Errorf("parsing nodes.json: %v", err)
	}
	var groups []pmapperGroup
	if err := json.Unmarshal(groupsData, &groups); err != nil {
		return nil, fmt.Errorf("parsing groups.json: %v", err)
	}
	var policies []pmapperPolicyEntry
	if err := json.Unmarshal(policiesData, &policies); err != nil {
		return nil, fmt.Errorf("parsing policies.json: %v", err)
	}

	augmentWithAdminNodes(&analysis, nodes, groups, policies)

	return json.Marshal(analysis)
}
