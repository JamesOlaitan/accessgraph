package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// escalationActions lists the IAM action patterns that imply a privilege
// escalation primitive. Each entry is paired with the EdgeKind that should be
// synthesised when the action is matched.
var escalationActions = []struct {
	pattern string
	kind    model.EdgeKind
}{
	// Role-centric escalation primitives: allow handing a role to a service,
	// effectively granting the attacker that role's full permissions.
	{pattern: "iam:PassRole", kind: model.EdgeKindCanPassRole},

	// Direct policy manipulation: allows attaching arbitrary managed policies.
	{pattern: "iam:AttachUserPolicy", kind: model.EdgeKindCanPassRole},
	{pattern: "iam:AttachGroupPolicy", kind: model.EdgeKindCanPassRole},
	{pattern: "iam:AttachRolePolicy", kind: model.EdgeKindCanPassRole},
	{pattern: "iam:PutUserPolicy", kind: model.EdgeKindCanPassRole},
	{pattern: "iam:PutGroupPolicy", kind: model.EdgeKindCanPassRole},
	{pattern: "iam:PutRolePolicy", kind: model.EdgeKindCanPassRole},
	{pattern: "iam:CreatePolicyVersion", kind: model.EdgeKindCanPassRole},
	{pattern: "iam:SetDefaultPolicyVersion", kind: model.EdgeKindCanPassRole},

	// Credential and login manipulation: create or reset credentials for any
	// IAM user, giving the attacker persistent access as that user.
	{pattern: "iam:CreateAccessKey", kind: model.EdgeKindCanCreateKey},
	{pattern: "iam:CreateLoginProfile", kind: model.EdgeKindCanCreateKey},
	{pattern: "iam:UpdateLoginProfile", kind: model.EdgeKindCanCreateKey},

	// Role assumption chain: allows a principal to assume a role directly.
	{pattern: "sts:AssumeRole", kind: model.EdgeKindAssumesRole},
}

// escalationTriple is the deduplication key for synthesised edges.
// Using a struct as a map key is safe because all fields are comparable.
type escalationTriple struct {
	from string
	to   string
	kind model.EdgeKind
}

// SynthesizeEscalationEdges analyses the permission graph and injects synthetic
// edges for IAM privilege-escalation primitives that are not encoded as explicit
// edges in the raw snapshot data.
//
// The function is designed to be called exactly once, immediately after
// NewEngine returns. Calling it multiple times is safe: the deduplication set
// ensures no edge is added twice for the same (from, to, kind) triple regardless
// of how many times the function is invoked.
//
// Detection logic:
//
//  1. For every Principal in the snapshot, walk outbound edges to find attached
//     or inline Policies. Then walk each Policy's outbound ALLOWS_ACTION edges to
//     collect Permission nodes (the ToNodeID of an ALLOWS_ACTION edge is the
//     permission's Policy ID — but the actual permission data lives in
//     Policy.Permissions). To avoid reimplementing policy-graph traversal, the
//     function inspects Policy.Permissions directly from the snapshot.
//
//  2. For each permission with Effect == "Allow" and an action matching one of
//     the escalation patterns, determine the target principals:
//     - For iam:PassRole / role-centric actions: target is every principal of
//     kind IAMRole in the snapshot.
//     - For iam:CreateAccessKey / login-profile actions: target is every principal
//     of kind IAMUser in the snapshot.
//     - When the permission's ResourcePattern is a specific ARN (not "*" or
//     a wildcard suffix), only the principal whose ARN matches is targeted.
//
//  3. Synthesise one EdgeKindCanPassRole or EdgeKindCanCreateKey edge per unique
//     (sourcePrincipal, targetPrincipal, kind) triple, add it to the engine, and
//     append it to snapshot.Edges so that OPA evaluation and graphviz rendering
//     see the complete edge set.
//
// Parameters:
//   - engine: a *Engine returned by NewEngine; must not be nil.
//   - snapshot: the source snapshot; must not be nil.
//
// Returns:
//   - nil on success.
//   - ErrInvalidInput if engine or snapshot is nil.
func SynthesizeEscalationEdges(engine *Engine, snapshot *model.Snapshot) error {
	if engine == nil || snapshot == nil {
		return fmt.Errorf("SynthesizeEscalationEdges: %w", ErrInvalidInput)
	}
	eng := engine

	// Build quick-lookup maps keyed by ARN for role and user principals.
	rolesByARN := make(map[string]*model.Principal)
	usersByARN := make(map[string]*model.Principal)
	for _, p := range snapshot.Principals {
		if p == nil {
			continue
		}
		switch p.Kind {
		case model.PrincipalKindIAMRole:
			rolesByARN[p.ARN] = p
		case model.PrincipalKindIAMUser:
			usersByARN[p.ARN] = p
		}
	}

	// allRoles and allUsers are slices for "wildcard resource" iteration.
	allRoles := make([]*model.Principal, 0, len(rolesByARN))
	for _, r := range rolesByARN {
		allRoles = append(allRoles, r)
	}
	allUsers := make([]*model.Principal, 0, len(usersByARN))
	for _, u := range usersByARN {
		allUsers = append(allUsers, u)
	}

	// Build a map from policy ID to its owning principal IDs. A policy may be
	// owned by multiple principals (e.g., a managed policy attached to several
	// roles), so the value is a slice.
	policyOwners := buildPolicyOwners(eng)

	// dedup tracks (from, to, kind) triples that have already been synthesised,
	// including those from previous invocations (idempotency guarantee).
	dedup := collectExistingEscalationTriples(eng)

	// Examine every policy in the snapshot.
	for _, policy := range snapshot.Policies {
		if policy == nil {
			continue
		}
		owners := policyOwners[policy.ID]
		if len(owners) == 0 {
			// Policy is not reachable from any principal in the current graph;
			// skip it to avoid creating orphaned synthetic edges.
			continue
		}

		for _, perm := range policy.Permissions {
			if perm == nil {
				continue
			}
			// Only Allow effects grant capabilities; Deny effects cannot escalate.
			if !strings.EqualFold(perm.Effect, "Allow") {
				continue
			}

			for _, ea := range escalationActions {
				if !actionMatches(perm.Action, ea.pattern) {
					continue
				}

				// Determine the set of target principals for this permission.
				targets := resolveTargets(perm.ResourcePattern, ea.kind, allRoles, allUsers, rolesByARN, usersByARN)

				for _, ownerID := range owners {
					for _, target := range targets {
						// Skip self-edges (a principal cannot escalate to itself
						// via these primitives in a meaningful threat-model sense).
						if ownerID == target.ID {
							continue
						}

						triple := escalationTriple{from: ownerID, to: target.ID, kind: ea.kind}
						if dedup[triple] {
							continue
						}
						dedup[triple] = true

						edge := synthesizeEdge(snapshot.ID, ownerID, target.ID, ea.kind)
						eng.addEdge(edge)
						snapshot.Edges = append(snapshot.Edges, edge)
					}
				}
			}
		}
	}

	return nil
}

// IsEscalationEdge reports whether the given edge represents a known privilege
// escalation primitive.
//
// An edge qualifies as an escalation primitive if any of the following is true:
//   - Its Kind is EdgeKindCanPassRole.
//   - Its Kind is EdgeKindCanCreateKey.
//   - Its Metadata map contains the key "escalation_primitive" with value "true".
//
// Parameters:
//   - e: the edge to inspect; passing nil returns false.
//
// Returns:
//   - true if the edge is an escalation primitive; false otherwise.
func IsEscalationEdge(e *model.Edge) bool {
	if e == nil {
		return false
	}
	if e.Kind == model.EdgeKindCanPassRole || e.Kind == model.EdgeKindCanCreateKey {
		return true
	}
	return e.Metadata["escalation_primitive"] == "true"
}

// actionMatches reports whether the IAM action pattern matches the given action.
//
// Matching rules (case-insensitive):
//   - The pattern "iam:*" matches any action whose service prefix is "iam:".
//   - Any other pattern must be an exact case-insensitive match.
//
// Parameters:
//   - action: the concrete IAM action to test (e.g., "iam:PassRole").
//   - pattern: the pattern from the policy permission (e.g., "iam:*", "iam:PassRole").
//
// Returns:
//   - true if pattern covers action; false otherwise.
func actionMatches(action, pattern string) bool {
	lower := strings.ToLower(action)
	patternLower := strings.ToLower(pattern)

	// Handle service-level wildcards: "iam:*" matches any "iam:..." action,
	// "sts:*" matches any "sts:..." action.
	if strings.HasSuffix(patternLower, ":*") {
		prefix := strings.TrimSuffix(patternLower, "*")
		return strings.HasPrefix(lower, prefix)
	}
	return lower == patternLower
}

// buildPolicyOwners scans the engine's outbound edge index to build a map
// from policy node ID to the slice of principal node IDs that own (are attached
// to or have inline) that policy.
//
// Parameters:
//   - engine: the engine whose edge index to scan.
//
// Returns:
//   - map[policyID][]ownerPrincipalID
func buildPolicyOwners(engine *Engine) map[string][]string {
	owners := make(map[string][]string)
	for fromID, edgeList := range engine.outbound {
		for _, edge := range edgeList {
			if edge.Kind == model.EdgeKindAttachedPolicy || edge.Kind == model.EdgeKindInlinePolicy {
				owners[edge.ToNodeID] = append(owners[edge.ToNodeID], fromID)
			}
		}
	}
	return owners
}

// collectExistingEscalationTriples builds the initial deduplication set from
// edges already present in the engine that are escalation primitives.
//
// Parameters:
//   - engine: the engine whose edge index to scan.
//
// Returns:
//   - map[escalationTriple]bool with an entry for every pre-existing escalation edge.
func collectExistingEscalationTriples(engine *Engine) map[escalationTriple]bool {
	dedup := make(map[escalationTriple]bool)
	for _, edge := range engine.edges {
		if IsEscalationEdge(edge) {
			dedup[escalationTriple{from: edge.FromNodeID, to: edge.ToNodeID, kind: edge.Kind}] = true
		}
	}
	return dedup
}

// resolveTargets determines which target principals are reachable through a
// given escalation action and resource pattern.
//
// Resolution rules:
//   - If the resource pattern is "*", all principals of the relevant kind are returned.
//   - If the resource pattern ends with "*", it is treated as a wildcard prefix match
//     against principal ARNs.
//   - Otherwise the pattern is matched as an exact ARN against the relevant kind lookup map.
//
// For CanPassRole the relevant kind is IAMRole; for all other escalation kinds
// the relevant kind is IAMUser.
//
// Parameters:
//   - resourcePattern: the ResourcePattern field from a Permission.
//   - kind: the EdgeKind being synthesised (determines which principal kind to target).
//   - allRoles: all IAMRole principals in the snapshot.
//   - allUsers: all IAMUser principals in the snapshot.
//   - rolesByARN: map of ARN -> *Principal for IAMRole.
//   - usersByARN: map of ARN -> *Principal for IAMUser.
//
// Returns:
//   - []*model.Principal; may be empty.
func resolveTargets(
	resourcePattern string,
	kind model.EdgeKind,
	allRoles, allUsers []*model.Principal,
	rolesByARN, usersByARN map[string]*model.Principal,
) []*model.Principal {
	// Select the candidate pool and ARN lookup map based on edge kind.
	// For PassRole and AssumeRole the target is an IAMRole.
	// For credential/login manipulation the target is an IAMUser.
	var pool []*model.Principal
	var byARN map[string]*model.Principal
	if kind == model.EdgeKindCanPassRole || kind == model.EdgeKindAssumesRole {
		pool = allRoles
		byARN = rolesByARN
	} else {
		pool = allUsers
		byARN = usersByARN
	}

	// Full wildcard: target all principals in the pool.
	if resourcePattern == "*" || resourcePattern == "" {
		result := make([]*model.Principal, len(pool))
		copy(result, pool)
		return result
	}

	// Suffix wildcard (e.g., "arn:aws:iam::123456789012:role/*").
	if strings.HasSuffix(resourcePattern, "*") {
		prefix := strings.TrimSuffix(resourcePattern, "*")
		var result []*model.Principal
		for _, p := range pool {
			if strings.HasPrefix(p.ARN, prefix) {
				result = append(result, p)
			}
		}
		return result
	}

	// Exact ARN match.
	if p, ok := byARN[resourcePattern]; ok {
		return []*model.Principal{p}
	}

	return nil
}

// synthesizeEdge creates a new synthetic Edge with escalation metadata.
//
// The edge ID is a deterministic content hash of (snapshotID, fromID, toID, kind),
// ensuring that re-running synthesis against the same snapshot produces identical
// edge IDs across process restarts. This property is required for reproducible
// benchmark results.
//
// Parameters:
//   - snapshotID: the snapshot ID to stamp on the edge.
//   - fromID: the source node ID.
//   - toID: the destination node ID.
//   - kind: the escalation edge kind.
//
// Returns:
//   - *model.Edge ready to be inserted into the engine.
func synthesizeEdge(snapshotID, fromID, toID string, kind model.EdgeKind) *model.Edge {
	key, _ := json.Marshal([]any{snapshotID, fromID, toID, string(kind)})
	h := sha256.Sum256(key)
	id := "synth-" + hex.EncodeToString(h[:16]) // 32 hex chars
	return &model.Edge{
		ID:         id,
		SnapshotID: snapshotID,
		FromNodeID: fromID,
		ToNodeID:   toID,
		Kind:       kind,
		Weight:     1,
		Metadata: map[string]string{
			"escalation_primitive": "true",
		},
	}
}
