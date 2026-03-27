package accessgraph

import rego.v1

# Detects synthesized CAN_PASS_ROLE edges, which represent iam:PassRole
# privilege escalation paths identified during graph construction.
violations contains result if {
	some edge in input.edges
	edge.kind == "CAN_PASS_ROLE"
	some principal in input.principals
	principal.id == edge.from
	result := {
		"rule_id": "IAM.PassRoleEscalation",
		"severity": "HIGH",
		"entity_ref": principal.arn,
		"reason": sprintf(
			"Principal '%v' holds iam:PassRole, enabling it to grant elevated permissions to EC2 instances, Lambda functions, or other services by passing a privileged role.",
			[principal.arn],
		),
		"remediation": "Restrict iam:PassRole to specific role ARNs using a resource condition. Audit which roles can be passed and ensure none grants more privileges than the caller already holds.",
	}
}

# Detects synthesized CAN_CREATE_KEY edges, which represent iam:CreateAccessKey
# privilege escalation paths — the ability to mint new long-lived credentials
# for any IAM user, including ones with higher privileges.
violations contains result if {
	some edge in input.edges
	edge.kind == "CAN_CREATE_KEY"
	some principal in input.principals
	principal.id == edge.from
	result := {
		"rule_id": "IAM.CreateAccessKeyEscalation",
		"severity": "HIGH",
		"entity_ref": principal.arn,
		"reason": sprintf(
			"Principal '%v' holds iam:CreateAccessKey, enabling it to mint persistent credentials for other IAM users.",
			[principal.arn],
		),
		"remediation": "Restrict iam:CreateAccessKey to the caller's own user ARN using a condition on aws:username, or remove the permission entirely and use temporary role credentials instead.",
	}
}

# Detects principals that hold both iam:CreateRole and iam:AttachRolePolicy,
# which together allow creating a new privileged role and attaching an
# admin-equivalent managed policy to it.
violations contains result if {
	some policy in input.policies
	some perm_create in policy.permissions
	perm_create.effect == "Allow"
	_matches_action(perm_create.action, "iam:CreateRole")
	some perm_attach in policy.permissions
	perm_attach.effect == "Allow"
	_matches_action(perm_attach.action, "iam:AttachRolePolicy")
	some principal in input.principals
	_principal_owns_policy(principal.id, policy.id, input.edges)
	result := {
		"rule_id": "IAM.CreateAndAttachRole",
		"severity": "CRITICAL",
		"entity_ref": principal.arn,
		"reason": sprintf(
			"Principal '%v' holds both iam:CreateRole and iam:AttachRolePolicy. Combined, these permissions allow creating a new role and attaching AdministratorAccess to it.",
			[principal.arn],
		),
		"remediation": "Separate role creation from policy attachment. Require MFA or approval workflows for privileged role creation. Add permission boundaries to all newly created roles.",
	}
}

# _matches_action reports whether an action matches a target, accounting for
# service-level wildcards (e.g., "iam:*" matches "iam:CreateRole").
_matches_action(action, target) if {
	action == target
}

_matches_action(action, target) if {
	action == "*"
	_ = target
}

_matches_action(action, target) if {
	endswith(action, ":*")
	prefix := substring(action, 0, indexof(action, ":"))
	target_prefix := substring(target, 0, indexof(target, ":"))
	prefix == target_prefix
}

# _principal_owns_policy reports whether a principal is connected to a policy
# via an ATTACHED_POLICY or INLINE_POLICY edge.
_principal_owns_policy(principal_id, policy_id, edges) if {
	some edge in edges
	edge.from == principal_id
	edge.to == policy_id
	edge.kind in {"ATTACHED_POLICY", "INLINE_POLICY"}
}
