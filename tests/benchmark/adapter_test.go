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

// prowlerOCSFFindingStub mirrors prowlerOCSFFinding so we can construct test
// JSON without importing the unexported type.
type prowlerOCSFFindingStub struct {
	StatusCode string                    `json:"status_code"`
	Resources  []prowlerOCSFResourceStub `json:"resources"`
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
				{StatusCode: "FAIL", Resources: []prowlerOCSFResourceStub{{UID: targetARN}}},
				{StatusCode: "PASS", Resources: []prowlerOCSFResourceStub{{UID: otherARN}}},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "true_positive_status_code_case_insensitive",
			stdout: mustMarshal(t, []prowlerOCSFFindingStub{
				{StatusCode: "fail", Resources: []prowlerOCSFResourceStub{{UID: targetARN}}},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "false_negative_no_matching_arn",
			stdout: mustMarshal(t, []prowlerOCSFFindingStub{
				{StatusCode: "FAIL", Resources: []prowlerOCSFResourceStub{{UID: otherARN}}},
			}),
			scenario:   baseScenario,
			wantDetect: false,
		},
		{
			name: "false_negative_matching_arn_is_pass",
			stdout: mustMarshal(t, []prowlerOCSFFindingStub{
				{StatusCode: "PASS", Resources: []prowlerOCSFResourceStub{{UID: targetARN}}},
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
				{StatusCode: "FAIL", Resources: []prowlerOCSFResourceStub{{UID: targetARN}}},
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
				{StatusCode: "FAIL", Resources: []prowlerOCSFResourceStub{
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
						Title:       "IAM Principal Can Escalate Privileges",
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
						Title:       "IAM Principal Can Escalate Privileges",
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
						Title:       "IAM Principal Can Escalate Privileges",
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
						Title:       "IAM Principal Can Escalate Privileges",
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
		targetResource = "arn:aws:iam::123456789012:user/attacker"
		otherResource  = "arn:aws:iam::123456789012:user/nobody"
		startingARN    = "arn:aws:iam::123456789012:user/attacker"
	)

	baseScenario := model.Scenario{
		ID:                   "iamvulnerable-checkov-test",
		Name:                 "AttachUserPolicy",
		StartingPrincipalARN: startingARN,
		ExpectedAttackPath:   []string{targetResource},
	}

	cases := []struct {
		name        string
		stdout      []byte
		scenario    model.Scenario
		wantDetect  bool
		wantErrWrap error
	}{
		{
			name: "true_positive_high_severity",
			stdout: mustMarshal(t, checkovResultStub{
				Results: checkovResultsStub{
					FailedChecks: []checkovCheckStub{
						{CheckID: "CKV_AWS_40", Severity: "HIGH", Resource: targetResource},
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "true_positive_critical_severity",
			stdout: mustMarshal(t, checkovResultStub{
				Results: checkovResultsStub{
					FailedChecks: []checkovCheckStub{
						{CheckID: "CKV_AWS_40", Severity: "CRITICAL", Resource: targetResource},
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "true_positive_empty_severity_older_checkov",
			stdout: mustMarshal(t, checkovResultStub{
				Results: checkovResultsStub{
					FailedChecks: []checkovCheckStub{
						{CheckID: "CKV_AWS_40", Severity: "", Resource: targetResource},
					},
				},
			}),
			scenario:   baseScenario,
			wantDetect: true,
		},
		{
			name: "false_negative_low_severity_excluded",
			stdout: mustMarshal(t, checkovResultStub{
				Results: checkovResultsStub{
					FailedChecks: []checkovCheckStub{
						{CheckID: "CKV_AWS_40", Severity: "LOW", Resource: targetResource},
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
						{CheckID: "CKV_AWS_40", Severity: "HIGH", Resource: otherResource},
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
