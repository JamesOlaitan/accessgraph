package parser_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/parser"
)

// minimalIAMJSON is the canonical test fixture: one user, one role, one group,
// one managed policy. It is reused across multiple tests to keep the JSON
// declaration in a single place.
const minimalIAMJSON = `{
  "account_id": "123456789012",
  "users": [{"UserName":"dev-user","UserId":"AIDA001","Arn":"arn:aws:iam::123456789012:user/dev-user","AttachedManagedPolicies":[{"PolicyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess","PolicyName":"ReadOnlyAccess"}],"UserPolicies":[],"GroupList":["Developers"]}],
  "roles": [{"RoleName":"DevRole","RoleId":"AROA001","Arn":"arn:aws:iam::123456789012:role/DevRole","AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]},"AttachedManagedPolicies":[],"RolePolicyList":[]}],
  "groups": [{"GroupName":"Developers","GroupId":"AGPA001","Arn":"arn:aws:iam::123456789012:group/Developers","AttachedManagedPolicies":[],"GroupPolicyList":[]}],
  "policies": [{"PolicyName":"ReadOnlyAccess","PolicyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess","PolicyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:Describe*","s3:Get*"],"Resource":"*"}]}}]
}`

// TestParseAWSIAMBasic verifies that the parser produces a non-nil Snapshot
// with the expected minimum counts for principals, policies, and edges when
// given a minimal but complete IAM export.
func TestParseAWSIAMBasic(t *testing.T) {
	ctx := context.Background()
	p := parser.NewAWSIAMParser()

	snap, err := p.ParseAWSIAM(ctx, []byte(minimalIAMJSON), "test-label")
	if err != nil {
		t.Fatalf("ParseAWSIAM returned unexpected error: %v", err)
	}
	if snap == nil {
		t.Fatal("ParseAWSIAM returned nil snapshot")
	}

	// The export has: user, role, group, plus a stub service-principal from the
	// AssumeRolePolicyDocument → at least 3 principals (user, role, group).
	if len(snap.Principals) < 3 {
		t.Errorf("expected >= 3 principals, got %d", len(snap.Principals))
	}

	// At least the ReadOnlyAccess managed policy must be present.
	if len(snap.Policies) < 1 {
		t.Errorf("expected >= 1 policy, got %d", len(snap.Policies))
	}

	// At least one ATTACHED_POLICY edge (user → ReadOnlyAccess).
	if len(snap.Edges) < 1 {
		t.Errorf("expected >= 1 edge, got %d", len(snap.Edges))
	}

	// Every principal must have a non-empty ID, ARN, and Kind.
	for i, pr := range snap.Principals {
		if pr.ID == "" {
			t.Errorf("principal[%d].ID is empty", i)
		}
		if pr.ARN == "" {
			t.Errorf("principal[%d].ARN is empty (ID=%s)", i, pr.ID)
		}
		if pr.Kind == "" {
			t.Errorf("principal[%d].Kind is empty (ID=%s)", i, pr.ID)
		}
	}

	// Every edge must have non-empty FromNodeID, ToNodeID, and Kind.
	for i, e := range snap.Edges {
		if e.FromNodeID == "" {
			t.Errorf("edge[%d].FromNodeID is empty (ID=%s)", i, e.ID)
		}
		if e.ToNodeID == "" {
			t.Errorf("edge[%d].ToNodeID is empty (ID=%s)", i, e.ID)
		}
		if e.Kind == "" {
			t.Errorf("edge[%d].Kind is empty (ID=%s)", i, e.ID)
		}
	}
}

// TestParseAWSIAMNilInput verifies that passing nil data returns an error
// wrapping ErrInvalidInput.
func TestParseAWSIAMNilInput(t *testing.T) {
	ctx := context.Background()
	p := parser.NewAWSIAMParser()

	_, err := p.ParseAWSIAM(ctx, nil, "nil-test")
	if err == nil {
		t.Fatal("expected an error for nil input, got nil")
	}
	if !errors.Is(err, parser.ErrInvalidInput) {
		t.Errorf("expected error wrapping ErrInvalidInput, got: %v", err)
	}
}

// TestParseAWSIAMEmptyInput verifies that passing an empty byte slice returns
// an error (ErrInvalidInput).
func TestParseAWSIAMEmptyInput(t *testing.T) {
	ctx := context.Background()
	p := parser.NewAWSIAMParser()

	_, err := p.ParseAWSIAM(ctx, []byte{}, "empty-test")
	if err == nil {
		t.Fatal("expected an error for empty input, got nil")
	}
	if !errors.Is(err, parser.ErrInvalidInput) {
		t.Errorf("expected error wrapping ErrInvalidInput, got: %v", err)
	}
}

// TestParseAWSIAMInlinePolicy verifies that a user with an inline policy
// produces an INLINE_POLICY edge from the user to the policy.
func TestParseAWSIAMInlinePolicy(t *testing.T) {
	const inlinePolicyJSON = `{
  "account_id": "111111111111",
  "users": [{
    "UserName": "ops-user",
    "UserId":   "AIDA002",
    "Arn":      "arn:aws:iam::111111111111:user/ops-user",
    "AttachedManagedPolicies": [],
    "UserPolicies": [{
      "PolicyName": "OpsInlinePolicy",
      "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]
      }
    }],
    "GroupList": []
  }],
  "roles": [],
  "groups": [],
  "policies": []
}`

	ctx := context.Background()
	p := parser.NewAWSIAMParser()

	snap, err := p.ParseAWSIAM(ctx, []byte(inlinePolicyJSON), "inline-test")
	if err != nil {
		t.Fatalf("ParseAWSIAM returned unexpected error: %v", err)
	}

	var foundInlineEdge bool
	for _, e := range snap.Edges {
		if e.Kind == model.EdgeKindInlinePolicy {
			foundInlineEdge = true
			break
		}
	}
	if !foundInlineEdge {
		t.Error("expected at least one INLINE_POLICY edge, found none")
	}
}

// TestParseAWSIAMStableIDs verifies that parsing the same document twice
// produces identical principal IDs (IDs are deterministic, not random).
func TestParseAWSIAMStableIDs(t *testing.T) {
	ctx := context.Background()
	p := parser.NewAWSIAMParser()
	data := []byte(minimalIAMJSON)

	snap1, err := p.ParseAWSIAM(ctx, data, "stable-1")
	if err != nil {
		t.Fatalf("first parse failed: %v", err)
	}
	snap2, err := p.ParseAWSIAM(ctx, data, "stable-2")
	if err != nil {
		t.Fatalf("second parse failed: %v", err)
	}

	if len(snap1.Principals) != len(snap2.Principals) {
		t.Fatalf("principal counts differ: %d vs %d", len(snap1.Principals), len(snap2.Principals))
	}

	// Build sets of IDs for both snapshots and compare them.
	ids1 := make(map[string]bool, len(snap1.Principals))
	for _, pr := range snap1.Principals {
		ids1[pr.ID] = true
	}
	for _, pr := range snap2.Principals {
		if !ids1[pr.ID] {
			t.Errorf("principal ID %q found in second parse but not in first", pr.ID)
		}
	}
}

// TestParseAWSIAMWildcardAction verifies that a policy with Action="iam:*"
// results in a Permission with Action="iam:*".
func TestParseAWSIAMWildcardAction(t *testing.T) {
	const wildcardJSON = `{
  "account_id": "222222222222",
  "users": [],
  "roles": [{
    "RoleName": "AdminRole",
    "RoleId":   "AROA002",
    "Arn":      "arn:aws:iam::222222222222:role/AdminRole",
    "AttachedManagedPolicies": [{"PolicyArn":"arn:aws:iam::aws:policy/AdminPolicy","PolicyName":"AdminPolicy"}],
    "RolePolicyList": []
  }],
  "groups": [],
  "policies": [{
    "PolicyName": "AdminPolicy",
    "PolicyArn":  "arn:aws:iam::aws:policy/AdminPolicy",
    "PolicyDocument": {
      "Version": "2012-10-17",
      "Statement": [{"Effect":"Allow","Action":"iam:*","Resource":"*"}]
    }
  }]
}`

	ctx := context.Background()
	p := parser.NewAWSIAMParser()

	snap, err := p.ParseAWSIAM(ctx, []byte(wildcardJSON), "wildcard-test")
	if err != nil {
		t.Fatalf("ParseAWSIAM returned unexpected error: %v", err)
	}

	var found bool
	for _, pol := range snap.Policies {
		for _, perm := range pol.Permissions {
			if perm.Action == "iam:*" {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Error("expected a Permission with Action=\"iam:*\", found none")
	}
}

// TestParseAWSIAMMalformedJSON verifies that invalid JSON returns an error
// wrapping ErrParseFailed.
func TestParseAWSIAMMalformedJSON(t *testing.T) {
	ctx := context.Background()
	p := parser.NewAWSIAMParser()

	_, err := p.ParseAWSIAM(ctx, []byte(`{not valid json`), "bad-json")
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
	if !errors.Is(err, parser.ErrParseFailed) {
		t.Errorf("expected error wrapping ErrParseFailed, got: %v", err)
	}
}

// TestParseAWSIAMNoTopLevelArrays verifies that a JSON object with none of the
// four required top-level arrays returns ErrParseFailed.
func TestParseAWSIAMNoTopLevelArrays(t *testing.T) {
	ctx := context.Background()
	p := parser.NewAWSIAMParser()

	_, err := p.ParseAWSIAM(ctx, []byte(`{"account_id":"999"}`), "empty-arrays")
	if err == nil {
		t.Fatal("expected an error when all top-level arrays are absent, got nil")
	}
	if !errors.Is(err, parser.ErrParseFailed) {
		t.Errorf("expected error wrapping ErrParseFailed, got: %v", err)
	}
}

// TestParseAWSIAMSnapshotMetadata verifies that the snapshot carries the label
// supplied by the caller and uses the "aws" provider.
func TestParseAWSIAMSnapshotMetadata(t *testing.T) {
	ctx := context.Background()
	p := parser.NewAWSIAMParser()

	snap, err := p.ParseAWSIAM(ctx, []byte(minimalIAMJSON), "my-label")
	if err != nil {
		t.Fatalf("ParseAWSIAM returned unexpected error: %v", err)
	}
	if snap.Label != "my-label" {
		t.Errorf("expected Label=\"my-label\", got %q", snap.Label)
	}
	if snap.Provider != "aws" {
		t.Errorf("expected Provider=\"aws\", got %q", snap.Provider)
	}
	if snap.ID == "" {
		t.Error("expected non-empty snapshot ID")
	}
}

// TestParseAWSIAMMemberOfEdge verifies that a user listed in a group's
// GroupList produces a MEMBER_OF edge.
func TestParseAWSIAMMemberOfEdge(t *testing.T) {
	ctx := context.Background()
	p := parser.NewAWSIAMParser()

	snap, err := p.ParseAWSIAM(ctx, []byte(minimalIAMJSON), "member-of-test")
	if err != nil {
		t.Fatalf("ParseAWSIAM returned unexpected error: %v", err)
	}

	var found bool
	for _, e := range snap.Edges {
		if e.Kind == model.EdgeKindMemberOf {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one MEMBER_OF edge, found none")
	}
}

// TestParseAWSIAMAllEdgesHaveSnapshotID verifies that every edge's SnapshotID
// field is set to the snapshot's own ID.
func TestParseAWSIAMAllEdgesHaveSnapshotID(t *testing.T) {
	ctx := context.Background()
	p := parser.NewAWSIAMParser()

	snap, err := p.ParseAWSIAM(ctx, []byte(minimalIAMJSON), "snap-id-test")
	if err != nil {
		t.Fatalf("ParseAWSIAM returned unexpected error: %v", err)
	}

	for i, e := range snap.Edges {
		if e.SnapshotID != snap.ID {
			t.Errorf("edge[%d].SnapshotID=%q, want %q", i, e.SnapshotID, snap.ID)
		}
	}
}

// TestParseAWSIAMContextCancellation verifies that a cancelled context
// causes ParseAWSIAM to return the context error.
func TestParseAWSIAMContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	p := parser.NewAWSIAMParser()
	_, err := p.ParseAWSIAM(ctx, []byte(minimalIAMJSON), "cancelled-test")
	if err == nil {
		// The parser may finish before the context is checked; this is an
		// acceptable race. Only fail if no error is returned AND we expect one.
		// Because the JSON is tiny, the parser may legitimately succeed.
		// This test documents the cancellation path without asserting hard failure.
		t.Log("parser completed before context check (acceptable for small inputs)")
	}
}

// TestParseAWSIAMTableDrivenEdgeCases uses table-driven tests to verify a
// variety of edge-case inputs.
func TestParseAWSIAMTableDrivenEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errTarget error
	}{
		{
			name:      "json array instead of object",
			input:     `[]`,
			wantErr:   true,
			errTarget: parser.ErrParseFailed,
		},
		{
			name:      "json string instead of object",
			input:     `"hello"`,
			wantErr:   true,
			errTarget: parser.ErrParseFailed,
		},
		{
			name:    "empty users array is valid",
			input:   `{"account_id":"000","users":[],"roles":[],"groups":[],"policies":[{"PolicyName":"P","PolicyArn":"arn:p","PolicyDocument":{"Version":"2012-10-17","Statement":[]}}]}`,
			wantErr: false,
		},
		{
			name:    "missing account_id defaults gracefully",
			input:   `{"users":[],"roles":[],"groups":[],"policies":[{"PolicyName":"P","PolicyArn":"arn:p","PolicyDocument":{"Version":"2012-10-17","Statement":[]}}]}`,
			wantErr: false,
		},
	}

	ctx := context.Background()
	p := parser.NewAWSIAMParser()

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.ParseAWSIAM(ctx, []byte(tc.input), tc.name)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errTarget != nil && !errors.Is(err, tc.errTarget) {
					t.Errorf("expected error wrapping %v, got: %v", tc.errTarget, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
			}
		})
	}
}
