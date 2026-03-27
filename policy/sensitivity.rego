package accessgraph

import rego.v1

# Flags IAM roles with AdministratorAccess or equivalent admin-level policies
# attached. These are the highest-value targets in the blast-radius graph.
violations contains result if {
	some policy in input.policies
	_is_admin_policy(policy)
	some edge in input.edges
	edge.to == policy.id
	edge.kind in {"ATTACHED_POLICY", "INLINE_POLICY"}
	some principal in input.principals
	principal.id == edge.from
	result := {
		"rule_id": "IAM.AdminPolicyAttached",
		"severity": "CRITICAL",
		"entity_ref": principal.arn,
		"reason": sprintf(
			"Principal '%v' has an administrator-equivalent policy attached ('%v'). Any compromised path to this principal yields full environment control.",
			[principal.arn, policy.name],
		),
		"remediation": "Remove AdministratorAccess and replace with a least-privilege policy scoped to the specific actions required. Audit CloudTrail for usage patterns to determine the minimum required permission set.",
	}
}

# Flags resources identified as sensitive by their ARN or kind, surfacing them
# as findings so analysts understand the high-value targets in the environment.
violations contains result if {
	some resource in input.resources
	resource.is_sensitive == true
	result := {
		"rule_id": "IAM.SensitiveResourceExposed",
		"severity": "HIGH",
		"entity_ref": resource.arn,
		"reason": sprintf(
			"Resource '%v' (kind: %v) is classified as a high-value target. Review all principals with any reachable path to this resource.",
			[resource.arn, resource.kind],
		),
		"remediation": "Audit the blast-radius report for all principals that can reach this resource. Restrict access to the minimum required set and enable CloudTrail logging for all API calls against it.",
	}
}

# Flags IAM roles without permission boundaries. A role lacking a permission
# boundary can escalate to any permission it is directly granted, with no
# cap enforced by the account administrator.
violations contains result if {
	some principal in input.principals
	principal.kind == "IAMRole"
	not _has_permission_boundary(principal, input.edges)
	_is_high_privilege_role(principal, input.policies, input.edges)
	result := {
		"rule_id": "IAM.MissingPermissionBoundary",
		"severity": "MEDIUM",
		"entity_ref": principal.arn,
		"reason": sprintf(
			"Role '%v' holds high-privilege permissions but has no permission boundary set. Without a boundary, the role's effective permissions are limited only by its attached policies.",
			[principal.arn],
		),
		"remediation": "Attach a permission boundary policy that caps the maximum permissions this role can exercise, even if its attached policies are later escalated.",
	}
}

# _is_admin_policy reports whether a policy is an admin-equivalent managed policy.
_is_admin_policy(policy) if {
	contains(policy.arn, "AdministratorAccess")
}

_is_admin_policy(policy) if {
	policy.name == "AdministratorAccess"
}

_is_admin_policy(policy) if {
	some perm in policy.permissions
	perm.action == "*"
	perm.resource == "*"
	perm.effect == "Allow"
}

# _has_permission_boundary reports whether a principal has a permission boundary edge.
# This uses the presence of a PERMISSION_BOUNDARY edge kind as a proxy.
_has_permission_boundary(principal, edges) if {
	some edge in edges
	edge.from == principal.id
	edge.kind == "PERMISSION_BOUNDARY"
}

# _is_high_privilege_role reports whether a principal holds at least one
# permission that grants wildcard actions across all resources.
_is_high_privilege_role(principal, policies, edges) if {
	some edge in edges
	edge.from == principal.id
	edge.kind in {"ATTACHED_POLICY", "INLINE_POLICY"}
	some policy in policies
	policy.id == edge.to
	some perm in policy.permissions
	perm.effect == "Allow"
	_action_is_wildcard(perm.action)
}
