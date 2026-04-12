package graph_test

import (
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/graph"
	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// buildEscalationSnap builds a minimal snapshot where a user has the given
// IAM action as an Allow permission, targeting the given resource ARN.
// The snapshot always contains the user and, when targetKind is "IAMRole",
// also contains a role principal so that SynthesizeEscalationEdges has
// something to wire to.
func buildEscalationSnap(
	userID, userARN string,
	roleID, roleARN string,
	policyID, action, resourcePattern string,
) *model.Snapshot {
	snap := &model.Snapshot{
		ID:    "esc-snap",
		Label: "escalation-test",
	}

	user := &model.Principal{
		ID:         userID,
		SnapshotID: snap.ID,
		Kind:       model.PrincipalKindIAMUser,
		ARN:        userARN,
		Name:       "test-user",
		AccountID:  "123456789012",
	}
	snap.Principals = append(snap.Principals, user)

	if roleID != "" {
		role := &model.Principal{
			ID:         roleID,
			SnapshotID: snap.ID,
			Kind:       model.PrincipalKindIAMRole,
			ARN:        roleARN,
			Name:       "test-role",
			AccountID:  "123456789012",
		}
		snap.Principals = append(snap.Principals, role)
	}

	perm := &model.Permission{
		ID:              policyID + "::perm",
		PolicyID:        policyID,
		Action:          action,
		Effect:          "Allow",
		ResourcePattern: resourcePattern,
	}

	policy := &model.Policy{
		ID:          policyID,
		SnapshotID:  snap.ID,
		Name:        "EscPolicy",
		IsInline:    true,
		Permissions: []*model.Permission{perm},
	}
	snap.Policies = append(snap.Policies, policy)

	// INLINE_POLICY edge so SynthesizeEscalationEdges can discover policy owners.
	edge := &model.Edge{
		ID:         "esc-edge-inline",
		SnapshotID: snap.ID,
		FromNodeID: userID,
		ToNodeID:   policyID,
		Kind:       model.EdgeKindInlinePolicy,
		Weight:     1,
	}
	snap.Edges = append(snap.Edges, edge)

	return snap
}

// TestSynthesizeEscalationEdgesPassRole verifies that a user with
// iam:PassRole targeting a specific role ARN gets a CAN_PASS_ROLE edge.
func TestSynthesizeEscalationEdgesPassRole(t *testing.T) {
	const (
		userID      = "user-pr"
		userARN     = "arn:aws:iam::123456789012:user/user-pr"
		roleID      = "role-pr"
		roleARN     = "arn:aws:iam::123456789012:role/TargetRole"
		policyID    = "policy-pr"
		action      = "iam:PassRole"
		resourcePat = "arn:aws:iam::123456789012:role/TargetRole"
	)

	snap := buildEscalationSnap(userID, userARN, roleID, roleARN, policyID, action, resourcePat)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	edgesBefore := eng.EdgeCount()

	if err := graph.SynthesizeEscalationEdges(eng, snap); err != nil {
		t.Fatalf("SynthesizeEscalationEdges: %v", err)
	}

	edgesAfter := eng.EdgeCount()
	if edgesAfter <= edgesBefore {
		t.Errorf("expected new edges after synthesis; before=%d after=%d", edgesBefore, edgesAfter)
	}

	// Verify that a CAN_PASS_ROLE edge from userID to roleID now exists by
	// checking reachability in 1 hop via ShortestPath.
	path, err := eng.ShortestPath(t.Context(), userID, roleID, 1)
	if err != nil {
		t.Fatalf("ShortestPath user→role after synthesis: %v (CAN_PASS_ROLE edge not synthesized)", err)
	}
	if path.HopCount != 1 {
		t.Errorf("expected 1-hop path from user to role, got %d", path.HopCount)
	}
}

// TestSynthesizeEscalationEdgesCreateKey verifies that iam:CreateAccessKey
// targeting "*" produces CAN_CREATE_KEY edges to all IAM users in the snapshot.
func TestSynthesizeEscalationEdgesCreateKey(t *testing.T) {
	const (
		roleID      = "role-ck"
		roleARN     = "arn:aws:iam::123456789012:role/KeyCreator"
		targetID    = "user-ck-target"
		targetARN   = "arn:aws:iam::123456789012:user/target"
		policyID    = "policy-ck"
		action      = "iam:CreateAccessKey"
		resourcePat = "*"
	)

	snap := &model.Snapshot{
		ID:    "ck-snap",
		Label: "create-key-test",
	}

	// Source role that has the CreateAccessKey permission.
	sourceRole := &model.Principal{
		ID: roleID, SnapshotID: snap.ID,
		Kind: model.PrincipalKindIAMRole,
		ARN:  roleARN, AccountID: "123456789012",
	}
	snap.Principals = append(snap.Principals, sourceRole)

	// Target user that can have a key created for it.
	targetUser := &model.Principal{
		ID: targetID, SnapshotID: snap.ID,
		Kind: model.PrincipalKindIAMUser,
		ARN:  targetARN, AccountID: "123456789012",
	}
	snap.Principals = append(snap.Principals, targetUser)

	perm := &model.Permission{
		ID: policyID + "::perm", PolicyID: policyID,
		Action: action, Effect: "Allow", ResourcePattern: resourcePat,
	}
	pol := &model.Policy{
		ID: policyID, SnapshotID: snap.ID, Name: "CKPolicy",
		IsInline:    true,
		Permissions: []*model.Permission{perm},
	}
	snap.Policies = append(snap.Policies, pol)

	// INLINE_POLICY edge so the role is discovered as the policy owner.
	snap.Edges = append(snap.Edges, &model.Edge{
		ID: "ck-inline", SnapshotID: snap.ID,
		FromNodeID: roleID, ToNodeID: policyID,
		Kind: model.EdgeKindInlinePolicy, Weight: 1,
	})

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if err := graph.SynthesizeEscalationEdges(eng, snap); err != nil {
		t.Fatalf("SynthesizeEscalationEdges: %v", err)
	}

	// Confirm CAN_CREATE_KEY reachability: role → targetUser in 1 hop.
	path, err := eng.ShortestPath(t.Context(), roleID, targetID, 1)
	if err != nil {
		t.Fatalf("ShortestPath role→targetUser: %v (CAN_CREATE_KEY edge not synthesized)", err)
	}
	if path.HopCount != 1 {
		t.Errorf("expected HopCount=1, got %d", path.HopCount)
	}
}

// TestSynthesizeEscalationEdgesAddUserToGroup verifies that a user with
// iam:AddUserToGroup targeting "*" gets a CAN_PASS_ROLE edge to all roles.
func TestSynthesizeEscalationEdgesAddUserToGroup(t *testing.T) {
	const (
		userID      = "user-aug"
		userARN     = "arn:aws:iam::123456789012:user/user-aug"
		roleID      = "role-aug"
		roleARN     = "arn:aws:iam::123456789012:role/TargetRole"
		policyID    = "policy-aug"
		action      = "iam:AddUserToGroup"
		resourcePat = "*"
	)

	snap := buildEscalationSnap(userID, userARN, roleID, roleARN, policyID, action, resourcePat)
	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	edgesBefore := eng.EdgeCount()

	if err := graph.SynthesizeEscalationEdges(eng, snap); err != nil {
		t.Fatalf("SynthesizeEscalationEdges: %v", err)
	}

	edgesAfter := eng.EdgeCount()
	if edgesAfter <= edgesBefore {
		t.Errorf("expected new edges after synthesis; before=%d after=%d", edgesBefore, edgesAfter)
	}

	path, err := eng.ShortestPath(t.Context(), userID, roleID, 1)
	if err != nil {
		t.Fatalf("ShortestPath user→role after synthesis: %v (CAN_PASS_ROLE edge not synthesized for iam:AddUserToGroup)", err)
	}
	if path.HopCount != 1 {
		t.Errorf("expected 1-hop path from user to role, got %d", path.HopCount)
	}
}

// TestSynthesizeEscalationEdgesIdempotent verifies that calling
// SynthesizeEscalationEdges twice does not add duplicate edges.
func TestSynthesizeEscalationEdgesIdempotent(t *testing.T) {
	snap := buildEscalationSnap(
		"user-idem", "arn:aws:iam::111:user/u",
		"role-idem", "arn:aws:iam::111:role/r",
		"pol-idem", "iam:PassRole", "*",
	)

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if err := graph.SynthesizeEscalationEdges(eng, snap); err != nil {
		t.Fatalf("first SynthesizeEscalationEdges: %v", err)
	}
	edgesAfterFirst := eng.EdgeCount()

	if err := graph.SynthesizeEscalationEdges(eng, snap); err != nil {
		t.Fatalf("second SynthesizeEscalationEdges: %v", err)
	}
	edgesAfterSecond := eng.EdgeCount()

	if edgesAfterSecond != edgesAfterFirst {
		t.Errorf("idempotency violated: first=%d second=%d edges", edgesAfterFirst, edgesAfterSecond)
	}
}

// TestSynthesizeEscalationEdgesMultipleActions verifies that a principal with
// multiple escalation-relevant permissions (iam:PassRole and iam:CreateAccessKey)
// causes multiple distinct escalation edge types to be synthesized.
//
// Note: the actionMatches function in the engine matches a policy permission's
// Action against concrete escalation patterns (e.g. "iam:PassRole"). A policy
// Action of "iam:*" does NOT trigger synthesis because the matching logic only
// treats "iam:*" as a wildcard when it appears as the escalation-table pattern,
// not as the policy action. Tests that rely on wildcard synthesis therefore use
// the concrete action strings.
func TestSynthesizeEscalationEdgesMultipleActions(t *testing.T) {
	// The snapshot has both a target role (for PassRole) and a target user
	// (for CreateAccessKey).
	snap := &model.Snapshot{ID: "multi-snap", Label: "multi-action"}

	sourceRole := &model.Principal{
		ID: "multi-src", SnapshotID: "multi-snap",
		Kind:      model.PrincipalKindIAMRole,
		ARN:       "arn:aws:iam::123:role/MultiSrc",
		AccountID: "123",
	}
	targetRole := &model.Principal{
		ID: "multi-tgt-role", SnapshotID: "multi-snap",
		Kind:      model.PrincipalKindIAMRole,
		ARN:       "arn:aws:iam::123:role/MultiTgt",
		AccountID: "123",
	}
	targetUser := &model.Principal{
		ID: "multi-tgt-user", SnapshotID: "multi-snap",
		Kind:      model.PrincipalKindIAMUser,
		ARN:       "arn:aws:iam::123:user/MultiTgt",
		AccountID: "123",
	}
	snap.Principals = append(snap.Principals, sourceRole, targetRole, targetUser)

	// Two permissions: one PassRole, one CreateAccessKey.
	permPR := &model.Permission{
		ID: "multi-perm-pr", PolicyID: "multi-pol",
		Action: "iam:PassRole", Effect: "Allow", ResourcePattern: "*",
	}
	permCK := &model.Permission{
		ID: "multi-perm-ck", PolicyID: "multi-pol",
		Action: "iam:CreateAccessKey", Effect: "Allow", ResourcePattern: "*",
	}
	pol := &model.Policy{
		ID: "multi-pol", SnapshotID: "multi-snap", Name: "MultiPol",
		IsInline:    true,
		Permissions: []*model.Permission{permPR, permCK},
	}
	snap.Policies = append(snap.Policies, pol)

	snap.Edges = append(snap.Edges, &model.Edge{
		ID: "multi-inline", SnapshotID: "multi-snap",
		FromNodeID: "multi-src", ToNodeID: "multi-pol",
		Kind: model.EdgeKindInlinePolicy, Weight: 1,
	})

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	edgesBefore := eng.EdgeCount()

	if err := graph.SynthesizeEscalationEdges(eng, snap); err != nil {
		t.Fatalf("SynthesizeEscalationEdges: %v", err)
	}

	edgesAfter := eng.EdgeCount()
	// Expect at least 2 new edges: CAN_PASS_ROLE to tgt-role AND
	// CAN_CREATE_KEY to tgt-user.
	if edgesAfter < edgesBefore+2 {
		t.Errorf("expected at least 2 new escalation edges; before=%d after=%d",
			edgesBefore, edgesAfter)
	}
}

// TestSynthesizeEscalationEdgesNilInputs verifies that passing nil engine or
// nil snapshot returns ErrInvalidInput.
func TestSynthesizeEscalationEdgesNilInputs(t *testing.T) {
	validSnap := &model.Snapshot{ID: "s"}
	eng, _ := graph.NewEngine(validSnap)

	if err := graph.SynthesizeEscalationEdges(nil, validSnap); err == nil {
		t.Error("expected error for nil engine, got nil")
	}
	if err := graph.SynthesizeEscalationEdges(eng, nil); err == nil {
		t.Error("expected error for nil snapshot, got nil")
	}
}

// TestIsEscalationEdge is a table-driven test covering all branches of
// IsEscalationEdge.
func TestIsEscalationEdge(t *testing.T) {
	tests := []struct {
		name string
		edge *model.Edge
		want bool
	}{
		{
			name: "CAN_PASS_ROLE edge is escalation",
			edge: &model.Edge{ID: "e1", Kind: model.EdgeKindCanPassRole},
			want: true,
		},
		{
			name: "CAN_CREATE_KEY edge is escalation",
			edge: &model.Edge{ID: "e2", Kind: model.EdgeKindCanCreateKey},
			want: true,
		},
		{
			name: "ASSUMES_ROLE edge is not escalation",
			edge: &model.Edge{ID: "e3", Kind: model.EdgeKindAssumesRole},
			want: false,
		},
		{
			name: "ATTACHED_POLICY edge is not escalation",
			edge: &model.Edge{ID: "e4", Kind: model.EdgeKindAttachedPolicy},
			want: false,
		},
		{
			name: "edge with escalation_primitive metadata is escalation",
			edge: &model.Edge{
				ID:       "e5",
				Kind:     model.EdgeKindAssumesRole,
				Metadata: map[string]string{"escalation_primitive": "true"},
			},
			want: true,
		},
		{
			name: "edge with escalation_primitive=false is not escalation",
			edge: &model.Edge{
				ID:       "e6",
				Kind:     model.EdgeKindAssumesRole,
				Metadata: map[string]string{"escalation_primitive": "false"},
			},
			want: false,
		},
		{
			name: "nil edge returns false",
			edge: nil,
			want: false,
		},
		{
			name: "ALLOWS_ACTION edge is not escalation",
			edge: &model.Edge{ID: "e7", Kind: model.EdgeKindAllowsAction},
			want: false,
		},
		{
			name: "INLINE_POLICY edge is not escalation",
			edge: &model.Edge{ID: "e8", Kind: model.EdgeKindInlinePolicy},
			want: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := graph.IsEscalationEdge(tc.edge)
			if got != tc.want {
				t.Errorf("IsEscalationEdge(%v) = %v, want %v", tc.edge, got, tc.want)
			}
		})
	}
}

// TestSynthesizeEscalationEdgesDenyIgnored verifies that a Deny permission
// with an escalation action does not produce escalation edges.
func TestSynthesizeEscalationEdgesDenyIgnored(t *testing.T) {
	snap := &model.Snapshot{ID: "deny-snap", Label: "deny-test"}

	user := &model.Principal{
		ID: "deny-user", SnapshotID: "deny-snap",
		Kind: model.PrincipalKindIAMUser,
		ARN:  "arn:aws:iam::456:user/u", AccountID: "456",
	}
	role := &model.Principal{
		ID: "deny-role", SnapshotID: "deny-snap",
		Kind: model.PrincipalKindIAMRole,
		ARN:  "arn:aws:iam::456:role/r", AccountID: "456",
	}
	snap.Principals = append(snap.Principals, user, role)

	perm := &model.Permission{
		ID: "deny-perm", PolicyID: "deny-pol",
		// Deny effect must never synthesize escalation edges.
		Action: "iam:PassRole", Effect: "Deny", ResourcePattern: "*",
	}
	pol := &model.Policy{
		ID: "deny-pol", SnapshotID: "deny-snap", Name: "DenyPol",
		IsInline:    true,
		Permissions: []*model.Permission{perm},
	}
	snap.Policies = append(snap.Policies, pol)

	snap.Edges = append(snap.Edges, &model.Edge{
		ID: "deny-inline", SnapshotID: "deny-snap",
		FromNodeID: "deny-user", ToNodeID: "deny-pol",
		Kind: model.EdgeKindInlinePolicy, Weight: 1,
	})

	eng, err := graph.NewEngine(snap)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	edgesBefore := eng.EdgeCount()

	if err := graph.SynthesizeEscalationEdges(eng, snap); err != nil {
		t.Fatalf("SynthesizeEscalationEdges: %v", err)
	}

	if eng.EdgeCount() != edgesBefore {
		t.Errorf("Deny permission should not produce escalation edges; before=%d after=%d",
			edgesBefore, eng.EdgeCount())
	}
}
