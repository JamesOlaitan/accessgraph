//go:build integration

package benchmark_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/benchmark"
	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// TestProwlerParseRealOCSFSample exercises the Prowler adapter's Parse method
// against a real Prowler 5.20.0 json-ocsf capture from LocalStack.
func TestProwlerParseRealOCSFSample(t *testing.T) {
	data, err := os.ReadFile("testdata/prowler-sample-ocsf.json")
	if err != nil {
		t.Fatalf("reading prowler fixture: %v", err)
	}

	// Verify the file is valid JSON and is a non-empty array.
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("fixture is not valid JSON array: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("fixture contains zero findings")
	}

	// Verify the parser extracts findings. The fixture was captured against
	// LocalStack with a role that has AdministratorAccess attached, so a
	// FAIL finding on arn:aws:iam::000000000000:role/test-role should exist.
	scenario := model.Scenario{
		ID:                 "prowler-fixture-test",
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:role/test-role"},
	}

	adapter := benchmark.NewProwlerAdapter()
	detected, err := adapter.Parse(data, scenario)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("Parse() did not detect expected ARN in OCSF fixture")
	}

	// Verify that a non-existent ARN is not detected.
	noMatchScenario := model.Scenario{
		ID:                 "prowler-fixture-nomatch",
		ExpectedAttackPath: []string{"arn:aws:iam::999999999999:user/nonexistent"},
	}
	detected, err = adapter.Parse(data, noMatchScenario)
	if err != nil {
		t.Fatalf("Parse() error on no-match scenario: %v", err)
	}
	if detected {
		t.Error("Parse() should not detect non-existent ARN")
	}
}

// TestProwlerParseOCSFFieldNames verifies that the OCSF schema fields the
// parser depends on (status_code, resources[].uid) actually exist in the
// captured fixture.
func TestProwlerParseOCSFFieldNames(t *testing.T) {
	data, err := os.ReadFile("testdata/prowler-sample-ocsf.json")
	if err != nil {
		t.Fatalf("reading prowler fixture: %v", err)
	}

	var findings []map[string]any
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for i, f := range findings {
		if _, ok := f["status_code"]; !ok {
			t.Errorf("finding[%d] missing status_code field", i)
		}
		resources, ok := f["resources"]
		if !ok {
			t.Errorf("finding[%d] missing resources field", i)
			continue
		}
		resSlice, ok := resources.([]any)
		if !ok {
			t.Errorf("finding[%d] resources is not an array", i)
			continue
		}
		for j, r := range resSlice {
			rm, ok := r.(map[string]any)
			if !ok {
				t.Errorf("finding[%d].resources[%d] is not an object", i, j)
				continue
			}
			if _, ok := rm["uid"]; !ok {
				t.Errorf("finding[%d].resources[%d] missing uid field", i, j)
			}
		}
	}
}

// TestPMapperParseRealSample exercises the PMapper adapter's Parse method
// against a real PMapper 1.1.5 analysis capture from LocalStack.
func TestPMapperParseRealSample(t *testing.T) {
	data, err := os.ReadFile("testdata/pmapper-sample-analysis.json")
	if err != nil {
		t.Fatalf("reading pmapper fixture: %v", err)
	}

	// Verify the file is valid JSON with the expected top-level fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("fixture is not valid JSON object: %v", err)
	}
	for _, key := range []string{"account", "findings"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("fixture missing expected top-level field %q", key)
		}
	}

	// The fixture was captured with user/escalation-user able to assume
	// role/admin-role in account 000000000000.
	scenario := model.Scenario{
		ID:                 "pmapper-fixture-test",
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:user/escalation-user"},
	}

	adapter := benchmark.NewPMapperAdapter()
	detected, err := adapter.Parse(data, scenario)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("Parse() did not detect expected principal in analysis fixture")
	}

	// Also verify the admin role is detected.
	roleScenario := model.Scenario{
		ID:                 "pmapper-fixture-role",
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:role/admin-role"},
	}
	detected, err = adapter.Parse(data, roleScenario)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("Parse() did not detect admin-role in analysis fixture")
	}

	// Non-existent principal should not be detected.
	noMatchScenario := model.Scenario{
		ID:                 "pmapper-fixture-nomatch",
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:user/nonexistent"},
	}
	detected, err = adapter.Parse(data, noMatchScenario)
	if err != nil {
		t.Fatalf("Parse() error on no-match scenario: %v", err)
	}
	if detected {
		t.Error("Parse() should not detect non-existent principal")
	}
}

// TestPMapperParseFieldNames verifies that the analysis output schema fields
// the parser depends on (account, findings[].description) actually exist in
// the captured fixture.
func TestPMapperParseFieldNames(t *testing.T) {
	data, err := os.ReadFile("testdata/pmapper-sample-analysis.json")
	if err != nil {
		t.Fatalf("reading pmapper fixture: %v", err)
	}

	var analysis map[string]any
	if err := json.Unmarshal(data, &analysis); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, ok := analysis["account"]; !ok {
		t.Error("fixture missing account field")
	}

	findings, ok := analysis["findings"]
	if !ok {
		t.Fatal("fixture missing findings field")
	}
	fSlice, ok := findings.([]any)
	if !ok {
		t.Fatal("findings is not an array")
	}
	for i, f := range fSlice {
		fm, ok := f.(map[string]any)
		if !ok {
			t.Errorf("findings[%d] is not an object", i)
			continue
		}
		if _, ok := fm["description"]; !ok {
			t.Errorf("findings[%d] missing description field", i)
		}
	}
}

// TestPMapperFixtureReplayInvoke verifies the PMapper adapter's full
// Invoke-then-Parse path against a synthetic pmapper_findings.json written
// to a temporary scenario directory.
func TestPMapperFixtureReplayInvoke(t *testing.T) {
	const accountID = "000000000000"
	attackerARN := "arn:aws:iam::" + accountID + ":user/escalation-user"

	analysis := map[string]any{
		"account": accountID,
		"findings": []map[string]any{
			{
				"title":       "IAM Principals Can Escalate Privileges",
				"severity":    "High",
				"description": "* user/escalation-user can escalate privileges by accessing role/admin-role\n",
			},
		},
	}

	data, err := json.Marshal(analysis)
	if err != nil {
		t.Fatalf("marshalling synthetic fixture: %v", err)
	}

	scenarioDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(scenarioDir, benchmark.PMapperFindingsFilename), data, 0o644); err != nil {
		t.Fatalf("writing synthetic fixture: %v", err)
	}

	adapter := benchmark.NewPMapperAdapter()
	stdout, _, err := adapter.Invoke(context.Background(), "", scenarioDir)
	if err != nil {
		t.Fatalf("Invoke() error: %v", err)
	}

	scenario := model.Scenario{
		ID:                 "pmapper-replay-test",
		ExpectedAttackPath: []string{attackerARN},
	}
	detected, err := adapter.Parse(stdout, scenario)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("fixture-replay Invoke+Parse failed to detect expected principal; expected TP, got FN")
	}

	// Verify a non-matching principal is not detected.
	noMatch := model.Scenario{
		ID:                 "pmapper-replay-nomatch",
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:user/nonexistent"},
	}
	detected, err = adapter.Parse(stdout, noMatch)
	if err != nil {
		t.Fatalf("Parse() error on no-match: %v", err)
	}
	if detected {
		t.Error("fixture-replay Invoke+Parse detected non-existent principal; expected FN, got TP")
	}
}

// TestCheckovFixtureReplayInvoke verifies the Checkov adapter's full
// Invoke-then-Parse path against a synthetic checkov.json written to a
// temporary scenario directory. The resource uses a terraform label format
// which the parser converts to an ARN suffix for matching.
func TestCheckovFixtureReplayInvoke(t *testing.T) {
	const (
		targetTFLabel = "aws_iam_policy.privesc7-AttachUserPolicy"
		targetARN     = "arn:aws:iam::000000000000:policy/privesc7-AttachUserPolicy"
	)

	result := map[string]any{
		"results": map[string]any{
			"failed_checks": []map[string]any{
				{
					"check_id": "CKV_AWS_286",
					"severity": "HIGH",
					"resource": targetTFLabel,
				},
			},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshalling synthetic fixture: %v", err)
	}

	scenarioDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(scenarioDir, benchmark.CheckovFixtureFilename), data, 0o644); err != nil {
		t.Fatalf("writing synthetic fixture: %v", err)
	}

	adapter := benchmark.NewCheckovAdapter()
	stdout, _, err := adapter.Invoke(context.Background(), "", scenarioDir)
	if err != nil {
		t.Fatalf("Invoke() error: %v", err)
	}

	scenario := model.Scenario{
		ID:                 "checkov-replay-test",
		ExpectedAttackPath: []string{targetARN},
	}
	detected, err := adapter.Parse(stdout, scenario)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("fixture-replay Invoke+Parse failed to detect expected resource; expected TP, got FN")
	}
}

// writePMapperGraph writes synthetic PMapper graph files (nodes.json,
// groups.json, policies.json) and pmapper_findings.json into a temporary
// scenario directory. Returns the scenario directory path.
func writePMapperGraph(t *testing.T, accountID string, findings []map[string]any, nodes, groups, policies any) string {
	t.Helper()
	scenarioDir := t.TempDir()

	analysisJSON, err := json.Marshal(map[string]any{
		"account":  accountID,
		"findings": findings,
	})
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scenarioDir, benchmark.PMapperFindingsFilename), analysisJSON, 0o644); err != nil {
		t.Fatalf("write findings: %v", err)
	}

	graphDir := filepath.Join(scenarioDir, "pmapper", accountID, "graph")
	if err := os.MkdirAll(graphDir, 0o755); err != nil {
		t.Fatalf("mkdir graph: %v", err)
	}

	for name, data := range map[string]any{
		"nodes.json":    nodes,
		"groups.json":   groups,
		"policies.json": policies,
	} {
		b, err := json.Marshal(data)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(graphDir, name), b, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	return scenarioDir
}

// TestPMapperAdminNodeAugmentation verifies the full Invoke+Parse path
// correctly identifies escalation-derived admins from nodes.json while
// excluding pre-existing admins.
func TestPMapperAdminNodeAugmentation(t *testing.T) {
	const accountID = "000000000000"

	nodes := []map[string]any{
		{
			"arn":               "arn:aws:iam::000000000000:user/escalation-user",
			"attached_policies": []map[string]string{{"arn": "arn:aws:iam::000000000000:policy/narrow-policy", "name": "narrow-policy"}},
			"group_memberships": []string{},
			"is_admin":          true,
		},
		{
			"arn":               "arn:aws:iam::000000000000:user/real-admin",
			"attached_policies": []map[string]string{{"arn": "arn:aws:iam::aws:policy/AdministratorAccess", "name": "AdministratorAccess"}},
			"group_memberships": []string{},
			"is_admin":          true,
		},
		{
			"arn":               "arn:aws:iam::000000000000:user/non-admin",
			"attached_policies": []map[string]string{{"arn": "arn:aws:iam::000000000000:policy/narrow-policy", "name": "narrow-policy"}},
			"group_memberships": []string{},
			"is_admin":          false,
		},
	}

	groups := []map[string]any{}

	policies := []map[string]any{
		{
			"arn":  "arn:aws:iam::aws:policy/AdministratorAccess",
			"name": "AdministratorAccess",
			"policy_doc": map[string]any{
				"Statement": []map[string]any{
					{"Effect": "Allow", "Action": "*", "Resource": "*"},
				},
			},
		},
		{
			"arn":  "arn:aws:iam::000000000000:policy/narrow-policy",
			"name": "narrow-policy",
			"policy_doc": map[string]any{
				"Statement": []map[string]any{
					{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
				},
			},
		},
	}

	scenarioDir := writePMapperGraph(t, accountID, []map[string]any{}, nodes, groups, policies)

	adapter := benchmark.NewPMapperAdapter()
	stdout, _, err := adapter.Invoke(context.Background(), "", scenarioDir)
	if err != nil {
		t.Fatalf("Invoke() error: %v", err)
	}

	// Escalation-derived admin should be detected.
	detected, err := adapter.Parse(stdout, model.Scenario{
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:user/escalation-user"},
	})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("escalation-derived admin not detected; expected TP, got FN")
	}

	// Pre-existing admin (AdministratorAccess) should NOT be detected.
	detected, err = adapter.Parse(stdout, model.Scenario{
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:user/real-admin"},
	})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if detected {
		t.Error("pre-existing admin (AdministratorAccess) detected as escalation; expected FN, got TP")
	}

	// Non-admin node should NOT be detected.
	detected, err = adapter.Parse(stdout, model.Scenario{
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:user/non-admin"},
	})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if detected {
		t.Error("non-admin node detected as escalation; expected FN, got TP")
	}
}

// TestPMapperAdminNodeExclusion_SREPattern verifies that privesc-sre-user
// (admin through group membership to a group with admin-equivalent policy)
// is NOT reported as an escalation-derived admin.
func TestPMapperAdminNodeExclusion_SREPattern(t *testing.T) {
	const accountID = "000000000000"

	nodes := []map[string]any{
		{
			"arn":               "arn:aws:iam::000000000000:user/privesc-sre-user",
			"attached_policies": []map[string]string{},
			"group_memberships": []string{"arn:aws:iam::000000000000:group/privesc-sre-group"},
			"is_admin":          true,
		},
		{
			"arn":               "arn:aws:iam::000000000000:role/privesc-sre-role",
			"attached_policies": []map[string]string{{"arn": "arn:aws:iam::000000000000:policy/privesc-sre-admin-policy", "name": "privesc-sre-admin-policy"}},
			"group_memberships": []string{},
			"is_admin":          true,
		},
	}

	groups := []map[string]any{
		{
			"arn":               "arn:aws:iam::000000000000:group/privesc-sre-group",
			"attached_policies": []map[string]string{{"arn": "arn:aws:iam::000000000000:policy/privesc-sre-admin-policy", "name": "privesc-sre-admin-policy"}},
		},
	}

	policies := []map[string]any{
		{
			"arn":  "arn:aws:iam::000000000000:policy/privesc-sre-admin-policy",
			"name": "privesc-sre-admin-policy",
			"policy_doc": map[string]any{
				"Statement": []map[string]any{
					{"Effect": "Allow", "Action": []string{"iam:*", "ec2:*", "s3:*"}, "Resource": "*"},
				},
			},
		},
	}

	scenarioDir := writePMapperGraph(t, accountID, []map[string]any{}, nodes, groups, policies)

	adapter := benchmark.NewPMapperAdapter()
	stdout, _, err := adapter.Invoke(context.Background(), "", scenarioDir)
	if err != nil {
		t.Fatalf("Invoke() error: %v", err)
	}

	// privesc-sre-user: admin through group -> admin-equiv policy. Must NOT be detected.
	detected, err := adapter.Parse(stdout, model.Scenario{
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:user/privesc-sre-user"},
	})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if detected {
		t.Error("privesc-sre-user (pre-existing admin through group) detected as escalation; expected FN, got TP")
	}

	// privesc-sre-role: admin through direct admin-equiv policy. Must NOT be detected.
	detected, err = adapter.Parse(stdout, model.Scenario{
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:role/privesc-sre-role"},
	})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if detected {
		t.Error("privesc-sre-role (pre-existing admin direct policy) detected as escalation; expected FN, got TP")
	}
}

// TestPMapperAdminNodeDetection_CreatePolicyVersion verifies the privesc1
// pattern: node with non-admin-equivalent policy and is_admin=true is
// correctly identified as an escalation-derived admin.
func TestPMapperAdminNodeDetection_CreatePolicyVersion(t *testing.T) {
	const accountID = "000000000000"

	nodes := []map[string]any{
		{
			"arn":               "arn:aws:iam::000000000000:user/privesc1-CreateNewPolicyVersion-user",
			"attached_policies": []map[string]string{{"arn": "arn:aws:iam::000000000000:policy/privesc1-CreateNewPolicyVersion", "name": "privesc1-CreateNewPolicyVersion"}},
			"group_memberships": []string{},
			"is_admin":          true,
		},
		{
			"arn":               "arn:aws:iam::000000000000:user/privesc-sre-user",
			"attached_policies": []map[string]string{},
			"group_memberships": []string{"arn:aws:iam::000000000000:group/privesc-sre-group"},
			"is_admin":          true,
		},
		{
			"arn":               "arn:aws:iam::000000000000:role/privesc-sre-role",
			"attached_policies": []map[string]string{{"arn": "arn:aws:iam::000000000000:policy/privesc-sre-admin-policy", "name": "privesc-sre-admin-policy"}},
			"group_memberships": []string{},
			"is_admin":          true,
		},
	}

	groups := []map[string]any{
		{
			"arn":               "arn:aws:iam::000000000000:group/privesc-sre-group",
			"attached_policies": []map[string]string{{"arn": "arn:aws:iam::000000000000:policy/privesc-sre-admin-policy", "name": "privesc-sre-admin-policy"}},
		},
	}

	policies := []map[string]any{
		{
			"arn":  "arn:aws:iam::000000000000:policy/privesc-sre-admin-policy",
			"name": "privesc-sre-admin-policy",
			"policy_doc": map[string]any{
				"Statement": []map[string]any{
					{"Effect": "Allow", "Action": []string{"iam:*", "ec2:*", "s3:*"}, "Resource": "*"},
				},
			},
		},
		{
			"arn":  "arn:aws:iam::000000000000:policy/privesc1-CreateNewPolicyVersion",
			"name": "privesc1-CreateNewPolicyVersion",
			"policy_doc": map[string]any{
				"Statement": []map[string]any{
					{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
				},
			},
		},
	}

	scenarioDir := writePMapperGraph(t, accountID, []map[string]any{}, nodes, groups, policies)

	adapter := benchmark.NewPMapperAdapter()
	stdout, _, err := adapter.Invoke(context.Background(), "", scenarioDir)
	if err != nil {
		t.Fatalf("Invoke() error: %v", err)
	}

	// privesc1 user: is_admin=true with non-admin policy. Must be detected.
	detected, err := adapter.Parse(stdout, model.Scenario{
		ExpectedAttackPath: []string{
			"arn:aws:iam::000000000000:user/privesc1-CreateNewPolicyVersion-user",
			"arn:aws:iam::000000000000:policy/privesc-sre-admin-policy",
		},
	})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("privesc1 user not detected as escalation-derived admin; expected TP, got FN")
	}

	// privesc-sre-user: must NOT be detected.
	detected, err = adapter.Parse(stdout, model.Scenario{
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:user/privesc-sre-user"},
	})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if detected {
		t.Error("privesc-sre-user detected as escalation; expected FN, got TP")
	}

	// privesc-sre-role: must NOT be detected.
	detected, err = adapter.Parse(stdout, model.Scenario{
		ExpectedAttackPath: []string{"arn:aws:iam::000000000000:role/privesc-sre-role"},
	})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if detected {
		t.Error("privesc-sre-role detected as escalation; expected FN, got TP")
	}
}

// TestPMapperAdminNodeAugmentation_NoGraph verifies graceful degradation
// when the PMapper graph directory does not exist.
func TestPMapperAdminNodeAugmentation_NoGraph(t *testing.T) {
	const accountID = "000000000000"
	attackerARN := "arn:aws:iam::" + accountID + ":user/escalation-user"

	analysis := map[string]any{
		"account": accountID,
		"findings": []map[string]any{
			{
				"title":       "IAM Principals Can Escalate Privileges",
				"severity":    "High",
				"description": "* user/escalation-user can escalate privileges\n",
			},
		},
	}

	data, err := json.Marshal(analysis)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	scenarioDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(scenarioDir, benchmark.PMapperFindingsFilename), data, 0o644); err != nil {
		t.Fatalf("write findings: %v", err)
	}
	// No pmapper/ graph directory created.

	adapter := benchmark.NewPMapperAdapter()
	stdout, _, err := adapter.Invoke(context.Background(), "", scenarioDir)
	if err != nil {
		t.Fatalf("Invoke() error (should degrade gracefully): %v", err)
	}

	// Parse should still work with the raw findings.
	detected, err := adapter.Parse(stdout, model.Scenario{
		ExpectedAttackPath: []string{attackerARN},
	})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("graceful degradation failed: findings-based detection should still work without graph")
	}
}
