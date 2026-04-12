package iampolicy_test

import (
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/iampolicy"
	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// TestForm1_AdministratorAccessARN verifies that a policy whose ARN is the
// canonical AdministratorAccess ARN is admin-equivalent regardless of its
// permission statements.
func TestForm1_AdministratorAccessARN(t *testing.T) {
	pol := &model.Policy{
		ID:   "pol-admin-arn",
		ARN:  "arn:aws:iam::aws:policy/AdministratorAccess",
		Name: "AdministratorAccess",
	}
	if !iampolicy.IsAdminEquivalentPolicy(pol) {
		t.Error("expected AdministratorAccess ARN to be admin-equivalent")
	}
}

// TestForm2_IAMWildcardOnStar verifies that a policy granting iam:* on
// Resource "*" is admin-equivalent.
func TestForm2_IAMWildcardOnStar(t *testing.T) {
	pol := &model.Policy{
		ID:   "pol-iam-star",
		Name: "iam-wildcard-policy",
		Permissions: []*model.Permission{
			{
				ID:              "perm-1",
				PolicyID:        "pol-iam-star",
				Action:          "iam:*",
				Effect:          "Allow",
				ResourcePattern: "*",
			},
		},
	}
	if !iampolicy.IsAdminEquivalentPolicy(pol) {
		t.Error("expected iam:* on * to be admin-equivalent")
	}
}

// TestForm3_FullWildcardOnStar verifies that a policy granting Action "*"
// on Resource "*" is admin-equivalent.
func TestForm3_FullWildcardOnStar(t *testing.T) {
	pol := &model.Policy{
		ID:   "pol-full-star",
		Name: "full-wildcard-policy",
		Permissions: []*model.Permission{
			{
				ID:              "perm-1",
				PolicyID:        "pol-full-star",
				Action:          "*",
				Effect:          "Allow",
				ResourcePattern: "*",
			},
		},
	}
	if !iampolicy.IsAdminEquivalentPolicy(pol) {
		t.Error("expected * on * to be admin-equivalent")
	}
}

// TestForm3_StarColonStarOnStar verifies that a policy granting Action "*:*"
// on Resource "*" is admin-equivalent (the explicit notation for all services,
// all actions).
func TestForm3_StarColonStarOnStar(t *testing.T) {
	pol := &model.Policy{
		ID:   "pol-star-colon-star",
		Name: "star-colon-star-policy",
		Permissions: []*model.Permission{
			{
				ID:              "perm-1",
				PolicyID:        "pol-star-colon-star",
				Action:          "*:*",
				Effect:          "Allow",
				ResourcePattern: "*",
			},
		},
	}
	if !iampolicy.IsAdminEquivalentPolicy(pol) {
		t.Error("expected *:* on * to be admin-equivalent")
	}
}

// TestNegative_SpecificAction verifies that a policy granting only
// iam:CreatePolicyVersion is NOT admin-equivalent.
func TestNegative_SpecificAction(t *testing.T) {
	pol := &model.Policy{
		ID:   "pol-specific",
		Name: "specific-action-policy",
		Permissions: []*model.Permission{
			{
				ID:              "perm-1",
				PolicyID:        "pol-specific",
				Action:          "iam:CreatePolicyVersion",
				Effect:          "Allow",
				ResourcePattern: "*",
			},
		},
	}
	if iampolicy.IsAdminEquivalentPolicy(pol) {
		t.Error("expected iam:CreatePolicyVersion on * to NOT be admin-equivalent")
	}
}

// TestNegative_IAMWildcardOnSpecificResource verifies that iam:* scoped to a
// specific resource ARN (not "*") is NOT admin-equivalent.
func TestNegative_IAMWildcardOnSpecificResource(t *testing.T) {
	pol := &model.Policy{
		ID:   "pol-scoped-iam",
		Name: "scoped-iam-policy",
		Permissions: []*model.Permission{
			{
				ID:              "perm-1",
				PolicyID:        "pol-scoped-iam",
				Action:          "iam:*",
				Effect:          "Allow",
				ResourcePattern: "arn:aws:iam::123456789012:role/SpecificRole",
			},
		},
	}
	if iampolicy.IsAdminEquivalentPolicy(pol) {
		t.Error("expected iam:* on specific resource to NOT be admin-equivalent")
	}
}

// TestNegative_ReadOnlyAccess verifies that a managed policy with a
// non-AdministratorAccess ARN and no wildcard grants is NOT admin-equivalent.
func TestNegative_ReadOnlyAccess(t *testing.T) {
	pol := &model.Policy{
		ID:   "pol-readonly",
		ARN:  "arn:aws:iam::aws:policy/ReadOnlyAccess",
		Name: "ReadOnlyAccess",
		Permissions: []*model.Permission{
			{
				ID:              "perm-1",
				PolicyID:        "pol-readonly",
				Action:          "s3:GetObject",
				Effect:          "Allow",
				ResourcePattern: "*",
			},
		},
	}
	if iampolicy.IsAdminEquivalentPolicy(pol) {
		t.Error("expected ReadOnlyAccess to NOT be admin-equivalent")
	}
}

// TestNegative_DenyDoesNotCount verifies that a Deny statement granting iam:*
// on * does NOT make a policy admin-equivalent.
func TestNegative_DenyDoesNotCount(t *testing.T) {
	pol := &model.Policy{
		ID:   "pol-deny",
		Name: "deny-all-iam",
		Permissions: []*model.Permission{
			{
				ID:              "perm-1",
				PolicyID:        "pol-deny",
				Action:          "iam:*",
				Effect:          "Deny",
				ResourcePattern: "*",
			},
		},
	}
	if iampolicy.IsAdminEquivalentPolicy(pol) {
		t.Error("expected Deny iam:* on * to NOT be admin-equivalent")
	}
}
