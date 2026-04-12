package iampolicy

import (
	"strings"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// adminAccessPolicyARN is the canonical ARN of the AWS-managed
// AdministratorAccess policy.
const adminAccessPolicyARN = "arn:aws:iam::aws:policy/AdministratorAccess"

// IsAdminEquivalentPolicy reports whether pol satisfies the admin-equivalence
// criteria defined in findings_schema.md Section 1.1.
//
// A policy is admin-equivalent when ANY of the following is true:
//
//  1. Its ARN is arn:aws:iam::aws:policy/AdministratorAccess (the canonical
//     AWS-managed full-access policy).
//  2. Any of its Allow permissions grants Action "iam:*" on Resource "*".
//  3. Any of its Allow permissions grants Action "*" (equivalently "*:*") on
//     Resource "*".
//
// Parameters:
//   - pol: the policy to evaluate; must not be nil.
//
// Returns:
//   - true if the policy is admin-equivalent; false otherwise.
func IsAdminEquivalentPolicy(pol *model.Policy) bool {
	if pol.ARN == adminAccessPolicyARN {
		return true
	}
	for _, perm := range pol.Permissions {
		if perm == nil {
			continue
		}
		if !strings.EqualFold(perm.Effect, "Allow") {
			continue
		}
		if perm.ResourcePattern != "*" && perm.ResourcePattern != "" {
			continue
		}
		lower := strings.ToLower(perm.Action)
		if lower == "*" || lower == "*:*" || lower == "iam:*" {
			return true
		}
	}
	return false
}
