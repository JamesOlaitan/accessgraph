package accessgraph

import rego.v1

# Detects cross-account trust relationships that allow external principals
# to assume roles in this environment. Every such edge is surfaced as a finding
# because cross-account assumptions are common privilege escalation entry points.
violations contains result if {
	some edge in input.edges
	edge.kind == "TRUSTS_CROSS_ACCOUNT"
	some principal in input.principals
	principal.id == edge.from
	result := {
		"rule_id": "IAM.CrossAccountTrust",
		"severity": "HIGH",
		"entity_ref": principal.arn,
		"reason": sprintf(
			"Principal '%v' is reachable from a cross-account trust relationship (edge to '%v').",
			[principal.arn, edge.to],
		),
		"remediation": "Verify that the cross-account trust is intentional and that the trusted external principal operates under least-privilege. Add an explicit ExternalId condition to the trust policy to prevent confused deputy attacks.",
	}
}

# Detects IAM roles with overly broad trust policies that allow any AWS principal
# to assume them (Principal: "*" in the trust policy).
violations contains result if {
	some edge in input.edges
	edge.kind == "ASSUMES_ROLE"
	some principal in input.principals
	principal.id == edge.from
	principal.arn == "*"
	some role in input.principals
	role.id == edge.to
	role.kind == "IAMRole"
	result := {
		"rule_id": "IAM.OpenTrustPolicy",
		"severity": "CRITICAL",
		"entity_ref": role.arn,
		"reason": sprintf(
			"Role '%v' has an open trust policy that allows any AWS principal to assume it.",
			[role.arn],
		),
		"remediation": "Restrict the trust policy Principal to the specific AWS accounts, services, or users that require access to this role. Never use Principal: '*' in a role trust policy.",
	}
}
