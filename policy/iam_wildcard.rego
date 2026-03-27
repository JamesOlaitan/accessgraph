# Package accessgraph contains all AccessGraph OPA policy rules.
# All rules in this directory contribute to the data.accessgraph.violations set.
# Each violation object must contain: rule_id, severity, entity_ref, reason, remediation.
package accessgraph

import rego.v1

# violations is the unified set of all policy findings across all rules.
# The analyze command queries data.accessgraph.violations to collect all findings.
violations contains result if {
	some policy in input.policies
	some perm in policy.permissions
	perm.effect == "Allow"
	_action_is_wildcard(perm.action)
	result := {
		"rule_id": "IAM.WildcardAction",
		"severity": _wildcard_severity(perm.action, perm.resource),
		"entity_ref": policy.arn,
		"reason": sprintf(
			"Policy '%v' grants wildcard action '%v' on resource '%v'.",
			[policy.name, perm.action, perm.resource],
		),
		"remediation": "Replace the wildcard action with the specific IAM actions required by the workload. Use the IAM Access Analyzer policy generation feature to identify the minimum required action set.",
	}
}

# _action_is_wildcard reports whether an IAM action string is a wildcard.
# Matches "iam:*", "s3:*", "*", and similar service-level or full wildcards.
_action_is_wildcard(action) if {
	endswith(action, ":*")
}

_action_is_wildcard(action) if {
	action == "*"
}

# _wildcard_severity computes severity based on whether both action and resource are wildcards.
# A wildcard action on a wildcard resource is CRITICAL; on a specific resource it is MEDIUM.
_wildcard_severity(action, resource) := "CRITICAL" if {
	_action_is_wildcard(action)
	_resource_is_wildcard(resource)
}

_wildcard_severity(action, resource) := "HIGH" if {
	action == "*"
	not _resource_is_wildcard(resource)
}

_wildcard_severity(action, _resource) := "MEDIUM" if {
	endswith(action, ":*")
	action != "*"
}

# _resource_is_wildcard reports whether a resource pattern is a bare wildcard.
_resource_is_wildcard(resource) if {
	resource == "*"
}
