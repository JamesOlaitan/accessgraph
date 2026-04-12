//go:build integration

// Package benchmark_test exercises each external tool adapter's Parse method
// using stub stdout data. No real tool binaries are required.
package benchmark_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/benchmark"
	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// mustMarshal marshals v to JSON and fails the test on error.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("mustMarshal: %v", err)
	}
	return b
}

// prowlerOCSFResourceStub mirrors prowlerOCSFResource.
type prowlerOCSFResourceStub struct {
	UID string `json:"uid"`
}

// prowlerOCSFFindingInfoStub mirrors prowlerOCSFFindingInfo.
type prowlerOCSFFindingInfoStub struct {
	UID string `json:"uid"`
}

// prowlerOCSFFindingStub mirrors prowlerOCSFFinding so we can construct test
// JSON without importing the unexported type.
type prowlerOCSFFindingStub struct {
	StatusCode  string                     `json:"status_code"`
	FindingInfo prowlerOCSFFindingInfoStub `json:"finding_info"`
	Resources   []prowlerOCSFResourceStub  `json:"resources"`
}

// prowlerFindingUID builds a Prowler-format finding_info.uid from a check name.
func prowlerFindingUID(checkName string) string {
	return "prowler-aws-" + checkName + "-000000000000-us-east-1-test"
}

func TestProwlerAdapterParse(t *testing.T) {
	const (
		targetARN   = "arn:aws:iam::123456789012:user/attacker"
		otherARN    = "arn:aws:iam::123456789012:user/other"
		startingARN = "arn:aws:iam::123456789012:user/attacker"
	)

	baseScenario := model.Scenario{
		ID:                   "iamvulnerable-prowler-test",
		Name:                 "CreatePolicyVersion",
		StartingPrincipalARN: startingARN,
		ExpectedAttackPath:   []string{targetARN, "arn:aws:iam::aws:policy/AdministratorAccess"},
	}

	privescUID := prowlerFindingUID("iam_policy_allows_privilege_escalation")

	cases := []struct {
		name        string
		stdout      []byte
		scenario    model.Scenario
		wantDetect  bool
		wantErrWrap error
	}{
		{
			name: "true_positive_exact_match",
			stdout: mustMarshal(t, []prowlerOCSFFindingStub{
				{StatusCode: "FAIL", FindingInfo: prowlerOCSFFindingInfoStub{UID: privescUID}, Resources: []prowlerOCSFResourceStub{{UID: targetARN}}},
				{StatusCode: "PASS", FindingInfo: prowlerOCSFFindingInfoStub{UID: privescUID}, Resources: []prowlerOCSFResourceStub{{UID: otherARN}}},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "true_positive_status_code_case_insensitive",
			stdout: mustMarshal(t, []prowlerOCSFFindingStub{
				{StatusCode: "fail", FindingInfo: prowlerOCSFFindingInfoStub{UID: privescUID}, Resources: []prowlerOCSFResourceStub{{UID: targetARN}}},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "false_negative_no_matching_arn",
			stdout: mustMarshal(t, []prowlerOCSFFindingStub{
				{StatusCode: "FAIL", FindingInfo: prowlerOCSFFindingInfoStub{UID: privescUID}, Resources: []prowlerOCSFResourceStub{{UID: otherARN}}},
			}),
			scenario:   baseScenario,
			wantDetect: false,
		},
		{
			name: "false_negative_matching_arn_is_pass",
			stdout: mustMarshal(t, []prowlerOCSFFindingStub{
				{StatusCode: "PASS", FindingInfo: prowlerOCSFFindingInfoStub{UID: privescUID}, Resources: []prowlerOCSFResourceStub{{UID: targetARN}}},
			}),
			scenario:   baseScenario,
			wantDetect: false,
		},
		{
			name:        "malformed_json_returns_error",
			stdout:      []byte(`not valid json`),
			scenario:    baseScenario,
			wantDetect:  false,
			wantErrWrap: benchmark.ErrToolFailed,
		},
		{
			name:       "empty_findings_array",
			stdout:     []byte(`[]`),
			scenario:   baseScenario,
			wantDetect: false,
		},
		{
			name: "empty_expected_attack_path_never_detects",
			stdout: mustMarshal(t, []prowlerOCSFFindingStub{
				{StatusCode: "FAIL", FindingInfo: prowlerOCSFFindingInfoStub{UID: privescUID}, Resources: []prowlerOCSFResourceStub{{UID: targetARN}}},
			}),
			scenario: model.Scenario{
				ID:                   "no-path",
				ExpectedAttackPath:   []string{},
				StartingPrincipalARN: startingARN,
			},
			wantDetect: false,
		},
		{
			name: "multiple_resources_per_finding",
			stdout: mustMarshal(t, []prowlerOCSFFindingStub{
				{StatusCode: "FAIL", FindingInfo: prowlerOCSFFindingInfoStub{UID: privescUID}, Resources: []prowlerOCSFResourceStub{
					{UID: otherARN},
					{UID: targetARN},
				}},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
	}

	adapter := benchmark.NewProwlerAdapter()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := adapter.Parse(tc.stdout, tc.scenario)
			if tc.wantErrWrap != nil {
				if !errors.Is(err, tc.wantErrWrap) {
					t.Fatalf("Parse() error = %v; want wrapping %v", err, tc.wantErrWrap)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() unexpected error: %v", err)
			}
			if got != tc.wantDetect {
				t.Errorf("Parse() detected = %v; want %v", got, tc.wantDetect)
			}
		})
	}
}

// TestProwlerParseCheckIDAllowlist verifies that the allowlist filter excludes
// non-privesc FAIL findings whose resources match ExpectedAttackPath. A
// privesc-relevant finding and an MFA finding both target the same ARN; only
// the privesc finding should count.
func TestProwlerParseCheckIDAllowlist(t *testing.T) {
	const targetARN = "arn:aws:iam::000000000000:user/test-user"

	scenario := model.Scenario{
		ID:                 "iamvulnerable-allowlist-test",
		ExpectedAttackPath: []string{targetARN},
	}

	t.Run("privesc_finding_matches", func(t *testing.T) {
		stdout := mustMarshal(t, []prowlerOCSFFindingStub{
			{
				StatusCode:  "FAIL",
				FindingInfo: prowlerOCSFFindingInfoStub{UID: prowlerFindingUID("iam_policy_allows_privilege_escalation")},
				Resources:   []prowlerOCSFResourceStub{{UID: targetARN}},
			},
		})
		adapter := benchmark.NewProwlerAdapter()
		got, err := adapter.Parse(stdout, scenario)
		if err != nil {
			t.Fatalf("Parse() error: %v", err)
		}
		if !got {
			t.Error("privesc finding should match; got FN, want TP")
		}
	})

	t.Run("mfa_finding_excluded", func(t *testing.T) {
		stdout := mustMarshal(t, []prowlerOCSFFindingStub{
			{
				StatusCode:  "FAIL",
				FindingInfo: prowlerOCSFFindingInfoStub{UID: prowlerFindingUID("iam_user_hardware_mfa_enabled")},
				Resources:   []prowlerOCSFResourceStub{{UID: targetARN}},
			},
		})
		adapter := benchmark.NewProwlerAdapter()
		got, err := adapter.Parse(stdout, scenario)
		if err != nil {
			t.Fatalf("Parse() error: %v", err)
		}
		if got {
			t.Error("MFA finding should be excluded by allowlist; got TP, want FN")
		}
	})

	t.Run("mixed_only_privesc_counts", func(t *testing.T) {
		stdout := mustMarshal(t, []prowlerOCSFFindingStub{
			{
				StatusCode:  "FAIL",
				FindingInfo: prowlerOCSFFindingInfoStub{UID: prowlerFindingUID("iam_user_hardware_mfa_enabled")},
				Resources:   []prowlerOCSFResourceStub{{UID: targetARN}},
			},
			{
				StatusCode:  "FAIL",
				FindingInfo: prowlerOCSFFindingInfoStub{UID: prowlerFindingUID("iam_policy_no_full_access_to_kms")},
				Resources:   []prowlerOCSFResourceStub{{UID: targetARN}},
			},
		})
		adapter := benchmark.NewProwlerAdapter()
		got, err := adapter.Parse(stdout, scenario)
		if err != nil {
			t.Fatalf("Parse() error: %v", err)
		}
		if got {
			t.Error("no privesc findings present; got TP, want FN")
		}
	})
}

// pmapperFindingStub mirrors the pmapperFinding type.
type pmapperFindingStub struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// pmapperAnalysisStub mirrors the pmapperAnalysis type.
type pmapperAnalysisStub struct {
	Account  string               `json:"account"`
	Findings []pmapperFindingStub `json:"findings"`
}

func TestPMapperAdapterParse(t *testing.T) {
	const (
		accountID    = "123456789012"
		attackerARN  = "arn:aws:iam::123456789012:user/attacker"
		adminRoleARN = "arn:aws:iam::123456789012:role/AdminRole"
		unrelatedARN = "arn:aws:iam::123456789012:user/irrelevant"
	)

	baseScenario := model.Scenario{
		ID:                   "iamvulnerable-pmapper-test",
		Name:                 "PassRoleLambda",
		StartingPrincipalARN: attackerARN,
		ExpectedAttackPath:   []string{attackerARN, adminRoleARN},
	}

	cases := []struct {
		name        string
		stdout      []byte
		scenario    model.Scenario
		wantDetect  bool
		wantErrWrap error
	}{
		{
			name: "true_positive_principal_in_description",
			stdout: mustMarshal(t, pmapperAnalysisStub{
				Account: accountID,
				Findings: []pmapperFindingStub{
					{
						Title:       "IAM Principals Can Escalate Privileges",
						Severity:    "High",
						Description: "* user/attacker can escalate privileges by accessing the administrative principal role/AdminRole:\n   * user/attacker can access via sts:AssumeRole role/AdminRole\n",
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "true_positive_only_terminal_node_present",
			stdout: mustMarshal(t, pmapperAnalysisStub{
				Account: accountID,
				Findings: []pmapperFindingStub{
					{
						Title:       "IAM Principals Can Escalate Privileges",
						Severity:    "High",
						Description: "* user/irrelevant can access role/AdminRole\n",
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "false_negative_no_matching_principals",
			stdout: mustMarshal(t, pmapperAnalysisStub{
				Account: accountID,
				Findings: []pmapperFindingStub{
					{
						Title:       "IAM Principals Can Escalate Privileges",
						Severity:    "High",
						Description: "* user/irrelevant can access role/SomeOtherRole\n",
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: false,
		},
		{
			name: "false_negative_empty_findings",
			stdout: mustMarshal(t, pmapperAnalysisStub{
				Account:  accountID,
				Findings: []pmapperFindingStub{},
			}),
			scenario:   baseScenario,
			wantDetect: false,
		},
		{
			name:        "malformed_json_returns_error",
			stdout:      []byte(`{"findings": [`),
			scenario:    baseScenario,
			wantDetect:  false,
			wantErrWrap: benchmark.ErrToolFailed,
		},
		{
			name: "wrong_account_id_no_match",
			stdout: mustMarshal(t, pmapperAnalysisStub{
				Account: "999999999999",
				Findings: []pmapperFindingStub{
					{
						Title:       "IAM Principals Can Escalate Privileges",
						Severity:    "High",
						Description: "* user/attacker can access role/AdminRole\n",
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: false,
		},
	}

	adapter := benchmark.NewPMapperAdapter()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := adapter.Parse(tc.stdout, tc.scenario)
			if tc.wantErrWrap != nil {
				if !errors.Is(err, tc.wantErrWrap) {
					t.Fatalf("Parse() error = %v; want wrapping %v", err, tc.wantErrWrap)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() unexpected error: %v", err)
			}
			if got != tc.wantDetect {
				t.Errorf("Parse() detected = %v; want %v", got, tc.wantDetect)
			}
		})
	}
}

// TestPMapperParseFiltersByTitle verifies that the parser ignores principals
// mentioned in non-privesc findings. Without the title filter, the circular
// access finding below would produce a false TP because it mentions
// user/target-principal, which is in ExpectedAttackPath.
func TestPMapperParseFiltersByTitle(t *testing.T) {
	stdout := mustMarshal(t, pmapperAnalysisStub{
		Account: "123456789012",
		Findings: []pmapperFindingStub{
			{
				Title:       "IAM Principals Can Escalate Privileges",
				Severity:    "High",
				Description: "* user/unrelated-attacker can escalate privileges by accessing role/unrelated-target\n",
			},
			{
				Title:       "IAM Principals with Circular Access",
				Severity:    "Low",
				Description: "* user/target-principal -> role/target-role -> user/target-principal\n",
			},
		},
	})

	adapter := benchmark.NewPMapperAdapter()
	detected, err := adapter.Parse(stdout, model.Scenario{
		ExpectedAttackPath: []string{
			"arn:aws:iam::123456789012:user/target-principal",
		},
	})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if detected {
		t.Error("parser extracted principals from non-privesc finding; expected FN, got TP")
	}
}

// TestPMapperParsePrivescMatch verifies that the parser still correctly detects
// principals mentioned in privesc findings after the title filter was added.
func TestPMapperParsePrivescMatch(t *testing.T) {
	stdout := mustMarshal(t, pmapperAnalysisStub{
		Account: "123456789012",
		Findings: []pmapperFindingStub{
			{
				Title:       "IAM Principals Can Escalate Privileges",
				Severity:    "High",
				Description: "* user/escalation-user can escalate privileges by accessing role/admin-role\n",
			},
		},
	})

	adapter := benchmark.NewPMapperAdapter()
	detected, err := adapter.Parse(stdout, model.Scenario{
		ExpectedAttackPath: []string{
			"arn:aws:iam::123456789012:user/escalation-user",
		},
	})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if !detected {
		t.Error("parser failed to detect principal in privesc finding; expected TP, got FN")
	}
}

// checkovResultStub mirrors the unexported checkovResult hierarchy.
type checkovResultStub struct {
	Results checkovResultsStub `json:"results"`
}

type checkovResultsStub struct {
	FailedChecks []checkovCheckStub `json:"failed_checks"`
}

type checkovCheckStub struct {
	CheckID  string `json:"check_id"`
	Severity string `json:"severity"`
	Resource string `json:"resource"`
}

func TestCheckovAdapterParse(t *testing.T) {
	const (
		targetTFLabel = "aws_iam_user.attacker"
		otherTFLabel  = "aws_iam_user.nobody"
		targetARN     = "arn:aws:iam::123456789012:user/attacker"
		startingARN   = "arn:aws:iam::123456789012:user/attacker"
	)

	baseScenario := model.Scenario{
		ID:                   "iamvulnerable-checkov-test",
		Name:                 "AttachUserPolicy",
		StartingPrincipalARN: startingARN,
		ExpectedAttackPath:   []string{targetARN},
	}

	cases := []struct {
		name        string
		stdout      []byte
		scenario    model.Scenario
		wantDetect  bool
		wantErrWrap error
	}{
		{
			name: "true_positive_privesc_check",
			stdout: mustMarshal(t, checkovResultStub{
				Results: checkovResultsStub{
					FailedChecks: []checkovCheckStub{
						{CheckID: "CKV_AWS_286", Severity: "HIGH", Resource: targetTFLabel},
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "true_positive_credentials_exposure_check",
			stdout: mustMarshal(t, checkovResultStub{
				Results: checkovResultsStub{
					FailedChecks: []checkovCheckStub{
						{CheckID: "CKV_AWS_287", Severity: "CRITICAL", Resource: targetTFLabel},
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "true_positive_permissions_management_check",
			stdout: mustMarshal(t, checkovResultStub{
				Results: checkovResultsStub{
					FailedChecks: []checkovCheckStub{
						{CheckID: "CKV_AWS_289", Severity: "", Resource: targetTFLabel},
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "false_negative_non_privesc_check_excluded",
			stdout: mustMarshal(t, checkovResultStub{
				Results: checkovResultsStub{
					FailedChecks: []checkovCheckStub{
						{CheckID: "CKV_AWS_40", Severity: "HIGH", Resource: targetTFLabel},
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: false,
		},
		{
			name: "false_negative_no_matching_resource",
			stdout: mustMarshal(t, checkovResultStub{
				Results: checkovResultsStub{
					FailedChecks: []checkovCheckStub{
						{CheckID: "CKV_AWS_286", Severity: "HIGH", Resource: otherTFLabel},
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: false,
		},
		{
			name: "false_negative_no_failed_checks",
			stdout: mustMarshal(t, checkovResultStub{
				Results: checkovResultsStub{
					FailedChecks: []checkovCheckStub{},
				},
			}),
			scenario:   baseScenario,
			wantDetect: false,
		},
		{
			name:        "malformed_json_returns_error",
			stdout:      []byte(`{"results": `),
			scenario:    baseScenario,
			wantDetect:  false,
			wantErrWrap: benchmark.ErrToolFailed,
		},
	}

	adapter := benchmark.NewCheckovAdapter()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := adapter.Parse(tc.stdout, tc.scenario)
			if tc.wantErrWrap != nil {
				if !errors.Is(err, tc.wantErrWrap) {
					t.Fatalf("Parse() error = %v; want wrapping %v", err, tc.wantErrWrap)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() unexpected error: %v", err)
			}
			if got != tc.wantDetect {
				t.Errorf("Parse() detected = %v; want %v", got, tc.wantDetect)
			}
		})
	}
}

// TestCheckovParseCheckIDAllowlist verifies that the allowlist filter excludes
// non-privesc failed checks even when the resource matches ExpectedAttackPath.
// CKV_AWS_286 on aws_iam_policy.test-policy should produce a TP; an unrelated
// check on the same resource should not.
func TestCheckovParseCheckIDAllowlist(t *testing.T) {
	const targetARN = "arn:aws:iam::000000000000:policy/test-policy"

	scenario := model.Scenario{
		ID:                 "iamvulnerable-checkov-allowlist",
		ExpectedAttackPath: []string{targetARN},
	}

	t.Run("privesc_check_matches", func(t *testing.T) {
		stdout := mustMarshal(t, checkovResultStub{
			Results: checkovResultsStub{
				FailedChecks: []checkovCheckStub{
					{CheckID: "CKV_AWS_286", Severity: "HIGH", Resource: "aws_iam_policy.test-policy"},
				},
			},
		})
		adapter := benchmark.NewCheckovAdapter()
		got, err := adapter.Parse(stdout, scenario)
		if err != nil {
			t.Fatalf("Parse() error: %v", err)
		}
		if !got {
			t.Error("CKV_AWS_286 finding should match; got FN, want TP")
		}
	})

	t.Run("unrelated_check_excluded", func(t *testing.T) {
		stdout := mustMarshal(t, checkovResultStub{
			Results: checkovResultsStub{
				FailedChecks: []checkovCheckStub{
					{CheckID: "CKV_AWS_40", Severity: "HIGH", Resource: "aws_iam_policy.test-policy"},
				},
			},
		})
		adapter := benchmark.NewCheckovAdapter()
		got, err := adapter.Parse(stdout, scenario)
		if err != nil {
			t.Fatalf("Parse() error: %v", err)
		}
		if got {
			t.Error("CKV_AWS_40 should be excluded by allowlist; got TP, want FN")
		}
	})

	t.Run("mixed_only_privesc_counts", func(t *testing.T) {
		stdout := mustMarshal(t, checkovResultStub{
			Results: checkovResultsStub{
				FailedChecks: []checkovCheckStub{
					{CheckID: "CKV_AWS_286", Severity: "HIGH", Resource: "aws_iam_policy.test-policy"},
					{CheckID: "CKV_AWS_40", Severity: "HIGH", Resource: "aws_iam_policy.test-policy"},
				},
			},
		})
		adapter := benchmark.NewCheckovAdapter()
		got, err := adapter.Parse(stdout, scenario)
		if err != nil {
			t.Fatalf("Parse() error: %v", err)
		}
		if !got {
			t.Error("CKV_AWS_286 should match despite CKV_AWS_40 also present; got FN, want TP")
		}
	})
}
