package iamexport_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/JamesOlaitan/accessgraph/internal/iamexport"
)

type mockIAM struct {
	pages []*iam.GetAccountAuthorizationDetailsOutput
	err   error
	calls int
}

func (m *mockIAM) GetAccountAuthorizationDetails(
	_ context.Context,
	_ *iam.GetAccountAuthorizationDetailsInput,
	_ ...func(*iam.Options),
) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.calls >= len(m.pages) {
		return &iam.GetAccountAuthorizationDetailsOutput{}, nil
	}
	page := m.pages[m.calls]
	m.calls++
	return page, nil
}

type mockSTS struct {
	account string
	err     error
}

func (m *mockSTS) GetCallerIdentity(
	_ context.Context,
	_ *sts.GetCallerIdentityInput,
	_ ...func(*sts.Options),
) (*sts.GetCallerIdentityOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &sts.GetCallerIdentityOutput{
		Account: aws.String(m.account),
	}, nil
}

func TestExportIAMSuccess(t *testing.T) {
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}]}`

	mock := &mockIAM{
		pages: []*iam.GetAccountAuthorizationDetailsOutput{
			{
				UserDetailList: []iamtypes.UserDetail{
					{
						UserName: aws.String("alice"),
						UserId:   aws.String("AIDAEXAMPLE1"),
						Arn:      aws.String("arn:aws:iam::111111111111:user/alice"),
						AttachedManagedPolicies: []iamtypes.AttachedPolicy{
							{PolicyArn: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess"), PolicyName: aws.String("ReadOnlyAccess")},
						},
						GroupList: []string{"developers"},
					},
				},
				RoleDetailList: []iamtypes.RoleDetail{
					{
						RoleName:                 aws.String("LambdaExec"),
						RoleId:                   aws.String("AROAEXAMPLE1"),
						Arn:                      aws.String("arn:aws:iam::111111111111:role/LambdaExec"),
						AssumeRolePolicyDocument: aws.String(policyDoc),
						RolePolicyList: []iamtypes.PolicyDetail{
							{PolicyName: aws.String("inline-1"), PolicyDocument: aws.String(policyDoc)},
						},
					},
				},
				GroupDetailList: []iamtypes.GroupDetail{
					{
						GroupName: aws.String("developers"),
						GroupId:   aws.String("AGPAEXAMPLE1"),
						Arn:       aws.String("arn:aws:iam::111111111111:group/developers"),
					},
				},
				Policies: []iamtypes.ManagedPolicyDetail{
					{
						PolicyName: aws.String("ReadOnlyAccess"),
						Arn:        aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess"),
						PolicyVersionList: []iamtypes.PolicyVersion{
							{VersionId: aws.String("v1"), IsDefaultVersion: true, Document: aws.String(policyDoc)},
						},
					},
				},
				IsTruncated: false,
			},
		},
	}

	exp := &iamexport.Exporter{
		IAM: mock,
		STS: &mockSTS{account: "111111111111"},
	}

	var buf bytes.Buffer
	stats, err := exp.Export(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	if stats.Users != 1 {
		t.Errorf("Users = %d, want 1", stats.Users)
	}
	if stats.Roles != 1 {
		t.Errorf("Roles = %d, want 1", stats.Roles)
	}
	if stats.Groups != 1 {
		t.Errorf("Groups = %d, want 1", stats.Groups)
	}
	if stats.Policies != 1 {
		t.Errorf("Policies = %d, want 1", stats.Policies)
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	for _, key := range []string{"account_id", "users", "roles", "groups", "policies"} {
		if _, ok := result[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}

	var parsed struct {
		AccountID string `json:"account_id"`
		Users     []struct {
			UserName     string   `json:"UserName"`
			GroupList    []string `json:"GroupList"`
			UserPolicies []struct {
				PolicyName string `json:"PolicyName"`
			} `json:"UserPolicies"`
			AttachedManagedPolicies []struct {
				PolicyArn string `json:"PolicyArn"`
			} `json:"AttachedManagedPolicies"`
		} `json:"users"`
		Roles []struct {
			RoleName                 string          `json:"RoleName"`
			AssumeRolePolicyDocument json.RawMessage `json:"AssumeRolePolicyDocument"`
			RolePolicyList           []struct {
				PolicyName string `json:"PolicyName"`
			} `json:"RolePolicyList"`
		} `json:"roles"`
		Policies []struct {
			PolicyName     string          `json:"PolicyName"`
			PolicyArn      string          `json:"PolicyArn"`
			PolicyDocument json.RawMessage `json:"PolicyDocument"`
		} `json:"policies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal structured output: %v", err)
	}

	if parsed.AccountID != "111111111111" {
		t.Errorf("account_id = %q, want %q", parsed.AccountID, "111111111111")
	}
	if len(parsed.Users) != 1 || parsed.Users[0].UserName != "alice" {
		t.Errorf("unexpected users: %+v", parsed.Users)
	}
	if len(parsed.Users[0].GroupList) != 1 || parsed.Users[0].GroupList[0] != "developers" {
		t.Errorf("unexpected GroupList: %v", parsed.Users[0].GroupList)
	}
	if len(parsed.Users[0].AttachedManagedPolicies) != 1 {
		t.Errorf("unexpected AttachedManagedPolicies count: %d", len(parsed.Users[0].AttachedManagedPolicies))
	}
	if len(parsed.Roles) != 1 || parsed.Roles[0].RoleName != "LambdaExec" {
		t.Errorf("unexpected roles: %+v", parsed.Roles)
	}
	if parsed.Roles[0].AssumeRolePolicyDocument == nil {
		t.Error("AssumeRolePolicyDocument is nil")
	}
	if len(parsed.Roles[0].RolePolicyList) != 1 {
		t.Errorf("unexpected RolePolicyList count: %d", len(parsed.Roles[0].RolePolicyList))
	}
	if len(parsed.Policies) != 1 || parsed.Policies[0].PolicyArn != "arn:aws:iam::aws:policy/ReadOnlyAccess" {
		t.Errorf("unexpected policies: %+v", parsed.Policies)
	}
	if parsed.Policies[0].PolicyDocument == nil {
		t.Error("PolicyDocument is nil on managed policy")
	}
}

func TestExportIAMPagination(t *testing.T) {
	mock := &mockIAM{
		pages: []*iam.GetAccountAuthorizationDetailsOutput{
			{
				UserDetailList: []iamtypes.UserDetail{
					{UserName: aws.String("user1"), UserId: aws.String("U1"), Arn: aws.String("arn:aws:iam::111111111111:user/user1")},
				},
				IsTruncated: true,
				Marker:      aws.String("page2marker"),
			},
			{
				UserDetailList: []iamtypes.UserDetail{
					{UserName: aws.String("user2"), UserId: aws.String("U2"), Arn: aws.String("arn:aws:iam::111111111111:user/user2")},
				},
				IsTruncated: false,
			},
		},
	}

	exp := &iamexport.Exporter{
		IAM: mock,
		STS: &mockSTS{account: "111111111111"},
	}

	var buf bytes.Buffer
	stats, err := exp.Export(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	if stats.Users != 2 {
		t.Errorf("Users = %d, want 2", stats.Users)
	}
	if mock.calls != 2 {
		t.Errorf("API calls = %d, want 2", mock.calls)
	}

	var parsed struct {
		Users []struct {
			UserName string `json:"UserName"`
		} `json:"users"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Users) != 2 {
		t.Fatalf("users count = %d, want 2", len(parsed.Users))
	}
	if parsed.Users[0].UserName != "user1" || parsed.Users[1].UserName != "user2" {
		t.Errorf("unexpected user names: %v, %v", parsed.Users[0].UserName, parsed.Users[1].UserName)
	}
}

func TestExportIAMAPIError(t *testing.T) {
	exp := &iamexport.Exporter{
		IAM: &mockIAM{err: fmt.Errorf("AccessDenied: not authorized")},
		STS: &mockSTS{account: "111111111111"},
	}

	var buf bytes.Buffer
	_, err := exp.Export(context.Background(), &buf)
	if err == nil {
		t.Fatal("Export() should return error")
	}
	if got := err.Error(); got == "" {
		t.Error("error message should not be empty")
	}
}

func TestExportIAMSTSError(t *testing.T) {
	exp := &iamexport.Exporter{
		IAM: &mockIAM{},
		STS: &mockSTS{err: fmt.Errorf("STS error")},
	}

	var buf bytes.Buffer
	_, err := exp.Export(context.Background(), &buf)
	if err == nil {
		t.Fatal("Export() should return error on STS failure")
	}
}

func TestExportIAMEmptyAccount(t *testing.T) {
	mock := &mockIAM{
		pages: []*iam.GetAccountAuthorizationDetailsOutput{
			{IsTruncated: false},
		},
	}

	exp := &iamexport.Exporter{
		IAM: mock,
		STS: &mockSTS{account: "222222222222"},
	}

	var buf bytes.Buffer
	stats, err := exp.Export(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	if stats.Users != 0 || stats.Roles != 0 || stats.Groups != 0 || stats.Policies != 0 {
		t.Errorf("stats should be all zeros: %+v", stats)
	}

	var parsed struct {
		AccountID string            `json:"account_id"`
		Users     []json.RawMessage `json:"users"`
		Roles     []json.RawMessage `json:"roles"`
		Groups    []json.RawMessage `json:"groups"`
		Policies  []json.RawMessage `json:"policies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if parsed.AccountID != "222222222222" {
		t.Errorf("account_id = %q, want %q", parsed.AccountID, "222222222222")
	}
	if parsed.Users == nil {
		t.Error("users should be empty array, not null")
	}
	if len(parsed.Users) != 0 {
		t.Errorf("users length = %d, want 0", len(parsed.Users))
	}
	if parsed.Roles == nil {
		t.Error("roles should be empty array, not null")
	}
	if parsed.Groups == nil {
		t.Error("groups should be empty array, not null")
	}
	if parsed.Policies == nil {
		t.Error("policies should be empty array, not null")
	}
}

func TestExportIAMURLEncodedPolicyDocument(t *testing.T) {
	// AWS returns policy documents URL-encoded.
	urlEncoded := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D"

	mock := &mockIAM{
		pages: []*iam.GetAccountAuthorizationDetailsOutput{
			{
				RoleDetailList: []iamtypes.RoleDetail{
					{
						RoleName:                 aws.String("TestRole"),
						RoleId:                   aws.String("R1"),
						Arn:                      aws.String("arn:aws:iam::111111111111:role/TestRole"),
						AssumeRolePolicyDocument: aws.String(urlEncoded),
					},
				},
				IsTruncated: false,
			},
		},
	}

	exp := &iamexport.Exporter{
		IAM: mock,
		STS: &mockSTS{account: "111111111111"},
	}

	var buf bytes.Buffer
	_, err := exp.Export(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Export() error: %v", err)
	}

	var parsed struct {
		Roles []struct {
			AssumeRolePolicyDocument struct {
				Version string `json:"Version"`
			} `json:"AssumeRolePolicyDocument"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Roles) != 1 {
		t.Fatalf("roles count = %d, want 1", len(parsed.Roles))
	}
	if parsed.Roles[0].AssumeRolePolicyDocument.Version != "2012-10-17" {
		t.Errorf("decoded Version = %q, want %q", parsed.Roles[0].AssumeRolePolicyDocument.Version, "2012-10-17")
	}
}
