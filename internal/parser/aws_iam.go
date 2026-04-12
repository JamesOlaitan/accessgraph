package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/JamesOlaitan/accessgraph/internal/iampolicy"
	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// Raw JSON structures

// iamExport is the top-level JSON object produced by an AWS IAM environment
// export. Only the fields consumed by the parser are decoded; additional fields
// in the source document are silently ignored.
type iamExport struct {
	AccountID string      `json:"account_id"`
	Users     []iamUser   `json:"users"`
	Roles     []iamRole   `json:"roles"`
	Groups    []iamGroup  `json:"groups"`
	Policies  []iamPolicy `json:"policies"`
}

// iamUser represents a single IAM user record.
type iamUser struct {
	UserName                string           `json:"UserName"`
	UserID                  string           `json:"UserId"`
	ARN                     string           `json:"Arn"`
	AttachedManagedPolicies []attachedPolicy `json:"AttachedManagedPolicies"`
	UserPolicies            []inlinePolicy   `json:"UserPolicies"`
	GroupList               []string         `json:"GroupList"`
}

// iamRole represents a single IAM role record.
type iamRole struct {
	RoleName                 string           `json:"RoleName"`
	RoleID                   string           `json:"RoleId"`
	ARN                      string           `json:"Arn"`
	AssumeRolePolicyDocument *policyDocument  `json:"AssumeRolePolicyDocument"`
	AttachedManagedPolicies  []attachedPolicy `json:"AttachedManagedPolicies"`
	RolePolicyList           []inlinePolicy   `json:"RolePolicyList"`
}

// iamGroup represents a single IAM group record.
type iamGroup struct {
	GroupName               string           `json:"GroupName"`
	GroupID                 string           `json:"GroupId"`
	ARN                     string           `json:"Arn"`
	AttachedManagedPolicies []attachedPolicy `json:"AttachedManagedPolicies"`
	GroupPolicyList         []inlinePolicy   `json:"GroupPolicyList"`
}

// iamPolicy represents a standalone managed policy record.
type iamPolicy struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyARN      string          `json:"PolicyArn"`
	PolicyDocument *policyDocument `json:"PolicyDocument"`
}

// attachedPolicy is a reference to an AWS managed policy attached to a principal.
type attachedPolicy struct {
	PolicyARN  string `json:"PolicyArn"`
	PolicyName string `json:"PolicyName"`
}

// inlinePolicy is an inline policy embedded directly in a principal definition.
type inlinePolicy struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyDocument *policyDocument `json:"PolicyDocument"`
}

// policyDocument is the JSON structure of an IAM policy or trust-policy document.
type policyDocument struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

// statement is a single IAM policy statement.
type statement struct {
	Effect    string          `json:"Effect"`
	Action    json.RawMessage `json:"Action"`
	Resource  json.RawMessage `json:"Resource"`
	Principal *principal      `json:"Principal"`
}

// principal captures the Principal field of an AssumeRolePolicyDocument
// statement. AWS allows Principal to be either a plain string ARN or a
// map of { "Service": "...", "AWS": "...", "Federated": "..." }.
type principal struct {
	// raw holds the undecoded JSON so we can handle both forms.
	raw json.RawMessage
}

// UnmarshalJSON implements json.Unmarshaler for principal.
func (p *principal) UnmarshalJSON(b []byte) error {
	p.raw = make(json.RawMessage, len(b))
	copy(p.raw, b)
	return nil
}

// arns extracts all ARN strings from a Principal field value.
// AWS allows:
//
//	"Principal": "arn:aws:..."
//	"Principal": { "Service": "ec2.amazonaws.com" }
//	"Principal": { "AWS": ["arn:aws:...", ...] }
//	"Principal": "*"
func (p *principal) arns() []string {
	if p == nil || len(p.raw) == 0 {
		return nil
	}
	// Try plain string first.
	var s string
	if err := json.Unmarshal(p.raw, &s); err == nil {
		if s != "" {
			return []string{s}
		}
		return nil
	}
	// Try map form.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(p.raw, &m); err != nil {
		return nil
	}
	var out []string
	for _, v := range m {
		out = append(out, normalizeStringOrSlice(v)...)
	}
	return out
}

// AWSIAMParser parses AWS IAM environment JSON exports into model.Snapshot
// values. It is the canonical implementation of the Parser interface for AWS.
//
// Construct instances via NewAWSIAMParser; the zero value is not ready for use.
type AWSIAMParser struct{}

// NewAWSIAMParser constructs a ready-to-use AWSIAMParser.
//
// Returns:
//   - *AWSIAMParser ready for ParseAWSIAM calls.
func NewAWSIAMParser() *AWSIAMParser {
	return &AWSIAMParser{}
}

// ParseTerraformPlan is not yet implemented; it returns ErrNotImplemented.
//
// Parameters:
//   - ctx: unused.
//   - data: unused.
//   - label: unused.
//
// Errors:
//   - Always returns ErrNotImplemented.
func (p *AWSIAMParser) ParseTerraformPlan(_ context.Context, _ []byte, _ string) (*model.Snapshot, error) {
	return nil, fmt.Errorf("AWSIAMParser.ParseTerraformPlan: %w", ErrNotImplemented)
}

// ParseAWSIAM implements Parser.ParseAWSIAM.
//
// It processes the four top-level arrays (users, roles, groups, policies) in a
// single pass, building principal, policy, permission, resource, and edge
// collections. All entity IDs are generated deterministically so that
// re-ingesting the same source document produces identical IDs.
//
// Parameters:
//   - ctx:   context for cancellation; checked before each major processing phase.
//   - data:  raw JSON bytes of the IAM environment export.
//   - label: human-readable label stored in Snapshot.Label.
//
// Returns:
//   - *model.Snapshot with all entities and edges populated.
//   - ErrInvalidInput if data is nil or empty.
//   - ErrParseFailed  if the JSON is malformed or a required field is absent.
func (p *AWSIAMParser) ParseAWSIAM(ctx context.Context, data []byte, label string) (*model.Snapshot, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("ParseAWSIAM: %w: data is nil or empty", ErrInvalidInput)
	}

	var export iamExport
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, fmt.Errorf("ParseAWSIAM: %w: %v", ErrParseFailed, err)
	}

	// Require at least one of the four main arrays to be present as a
	// sentinel that this is a recognisable IAM export structure.
	if export.Users == nil && export.Roles == nil &&
		export.Groups == nil && export.Policies == nil {
		return nil, fmt.Errorf("ParseAWSIAM: %w: missing required fields (users/roles/groups/policies)", ErrParseFailed)
	}

	accountID := export.AccountID
	if accountID == "" {
		accountID = "unknown"
	}

	snap := &model.Snapshot{
		ID:        fmt.Sprintf("snap-%s-%d", accountID, time.Now().UnixNano()),
		Label:     label,
		Provider:  "aws",
		CreatedAt: time.Now().UTC(),
	}

	// b is the shared builder for this snapshot.
	b := &snapshotBuilder{
		snap:            snap,
		accountID:       accountID,
		principalsByARN: make(map[string]*model.Principal),
		policiesByARN:   make(map[string]*model.Policy),
		policiesByID:    make(map[string]*model.Policy),
		resourcesByARN:  make(map[string]*model.Resource),
		edgeSet:         make(map[string]bool),
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.processUsers(export.Users)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.processRoles(export.Roles)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.processGroups(export.Groups)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.processManagedPolicies(export.Policies)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.createAdminEquivalentResources()

	// Second pass: wire edges that require all principals to be known.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.wireUserGroupEdges(export.Users)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.wireAssumeRoleEdges(export.Roles)

	// Assign snapshot IDs to all entities.
	snapID := snap.ID
	for _, pr := range snap.Principals {
		pr.SnapshotID = snapID
	}
	for _, pol := range snap.Policies {
		pol.SnapshotID = snapID
	}
	for _, r := range snap.Resources {
		r.SnapshotID = snapID
	}
	for _, e := range snap.Edges {
		e.SnapshotID = snapID
	}

	return snap, nil
}

// snapshotBuilder — stateful helper used only during a single ParseAWSIAM call

type snapshotBuilder struct {
	snap            *model.Snapshot
	accountID       string
	principalsByARN map[string]*model.Principal // ARN → Principal
	policiesByARN   map[string]*model.Policy    // ARN → Policy
	policiesByID    map[string]*model.Policy    // ID  → Policy
	resourcesByARN  map[string]*model.Resource  // ARN → Resource
	edgeSet         map[string]bool             // deduplicate edges by ID
}

// ID generators

// principalID returns the deterministic ID for an IAM principal.
func (b *snapshotBuilder) principalID(kind, name string) string {
	return b.accountID + "::" + kind + "::" + name
}

// policyID returns the deterministic ID for an IAM policy (managed or inline).
func (b *snapshotBuilder) policyID(name string) string {
	return b.accountID + "::Policy::" + name
}

// permissionID returns the deterministic ID for a permission triple.
func (b *snapshotBuilder) permissionID(policyID, action, effect string) string {
	return policyID + "::Perm::" + effect + "::" + action
}

// resourceID returns the deterministic ID for a resource ARN.
func (b *snapshotBuilder) resourceID(arn string) string {
	return b.accountID + "::Resource::" + arn
}

// edgeID returns the deterministic ID for a directed labelled edge.
func (b *snapshotBuilder) edgeID(from, to string, kind model.EdgeKind) string {
	return string(kind) + "::" + from + "::" + to
}

// Entity registration helpers

// addPrincipal adds a principal to the snapshot if not already present.
func (b *snapshotBuilder) addPrincipal(pr *model.Principal) {
	if _, ok := b.principalsByARN[pr.ARN]; ok {
		return
	}
	b.principalsByARN[pr.ARN] = pr
	b.snap.Principals = append(b.snap.Principals, pr)
}

// addPolicy adds a policy to the snapshot if not already present (keyed by ID).
func (b *snapshotBuilder) addPolicy(pol *model.Policy) {
	if _, ok := b.policiesByID[pol.ID]; ok {
		return
	}
	b.policiesByID[pol.ID] = pol
	if pol.ARN != "" {
		b.policiesByARN[pol.ARN] = pol
	}
	b.snap.Policies = append(b.snap.Policies, pol)
}

// addResource adds a resource to the snapshot if not already present.
func (b *snapshotBuilder) addResource(r *model.Resource) {
	if _, ok := b.resourcesByARN[r.ARN]; ok {
		return
	}
	b.resourcesByARN[r.ARN] = r
	b.snap.Resources = append(b.snap.Resources, r)
}

// addEdge adds an edge to the snapshot if a logically identical edge (same from,
// to, and kind) has not already been added.
func (b *snapshotBuilder) addEdge(from, to string, kind model.EdgeKind) {
	id := b.edgeID(from, to, kind)
	if b.edgeSet[id] {
		return
	}
	b.edgeSet[id] = true
	b.snap.Edges = append(b.snap.Edges, &model.Edge{
		ID:         id,
		FromNodeID: from,
		ToNodeID:   to,
		Kind:       kind,
		Weight:     1,
	})
}

// Policy document processing

// buildPolicyFromDocument parses a policyDocument and creates a model.Policy
// along with all model.Permission entries and model.Resource nodes that result
// from its statements. The policy is registered in the builder but is NOT
// added to the snapshot here; the caller does that after setting ARN/Name.
func (b *snapshotBuilder) buildPolicyFromDocument(
	policyID, policyName, policyARN string,
	isInline bool,
	doc *policyDocument,
	rawJSON string,
) *model.Policy {
	pol := &model.Policy{
		ID:       policyID,
		ARN:      policyARN,
		Name:     policyName,
		IsInline: isInline,
		JSONRaw:  rawJSON,
	}

	if doc == nil {
		return pol
	}

	for _, stmt := range doc.Statement {
		effect := stmt.Effect
		if effect == "" {
			effect = "Allow"
		}
		actions := normalizeStringOrSlice(stmt.Action)
		resources := normalizeStringOrSlice(stmt.Resource)

		for _, action := range actions {
			// Create one Permission record per resource ARN so that each
			// (action, resource) pair is represented individually in the graph.
			if len(resources) == 0 {
				permID := b.permissionID(policyID, action, effect)
				perm := &model.Permission{
					ID:       permID,
					PolicyID: policyID,
					Action:   action,
					Effect:   effect,
				}
				pol.Permissions = append(pol.Permissions, perm)
				b.addEdge(policyID, permID, model.EdgeKindAllowsAction)
				continue
			}

			for _, resourceARN := range resources {
				permID := b.permissionID(policyID, action+":"+resourceARN, effect)
				perm := &model.Permission{
					ID:              permID,
					PolicyID:        policyID,
					Action:          action,
					Effect:          effect,
					ResourcePattern: resourceARN,
				}
				pol.Permissions = append(pol.Permissions, perm)

				// ALLOWS_ACTION edge: policy → permission node.
				b.addEdge(policyID, permID, model.EdgeKindAllowsAction)

				// APPLIES_TO edge: permission → resource (skip wildcard "*").
				if resourceARN == "*" {
					continue
				}
				resID := b.resourceID(resourceARN)
				b.ensureResource(resourceARN, resID)
				b.addEdge(permID, resID, model.EdgeKindAppliesTo)
			}
		}
	}

	return pol
}

// ensureResource creates the resource for the given ARN if it does not already exist.
func (b *snapshotBuilder) ensureResource(arn, id string) {
	if _, ok := b.resourcesByARN[arn]; ok {
		return
	}
	r := &model.Resource{
		ID:   id,
		ARN:  arn,
		Kind: resourceKindFromARN(arn),
	}
	b.addResource(r)
}

// createAdminEquivalentResources creates a Resource node for each policy that
// satisfies the admin-equivalence criteria and has a non-empty ARN.
func (b *snapshotBuilder) createAdminEquivalentResources() {
	for _, pol := range b.snap.Policies {
		if pol.ARN == "" {
			continue
		}
		if !iampolicy.IsAdminEquivalentPolicy(pol) {
			continue
		}
		resID := b.resourceID(pol.ARN)
		b.ensureResource(pol.ARN, resID)
	}
}

// ensurePrincipalStub returns an existing principal or creates a stub principal
// for a trust-policy ARN that was not found in the snapshot.
func (b *snapshotBuilder) ensurePrincipalStub(arn string) *model.Principal {
	if pr, ok := b.principalsByARN[arn]; ok {
		return pr
	}
	kind := principalKindFromARN(arn)
	name := nameFromARN(arn)
	// Derive account from the ARN if possible (field 4 of colon-split ARN).
	acct := b.accountID
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 && parts[4] != "" {
		acct = parts[4]
	}
	id := acct + "::" + string(kind) + "::" + name
	pr := &model.Principal{
		ID:        id,
		Kind:      kind,
		ARN:       arn,
		Name:      name,
		AccountID: acct,
	}
	b.addPrincipal(pr)
	return pr
}

// Per-entity-type processing

// processUsers registers Principal nodes and associated Policy/Permission/Edge
// entities for all IAM users in the export.
func (b *snapshotBuilder) processUsers(users []iamUser) {
	for _, u := range users {
		prID := b.principalID("IAMUser", u.UserName)
		pr := &model.Principal{
			ID:        prID,
			Kind:      model.PrincipalKindIAMUser,
			ARN:       u.ARN,
			Name:      u.UserName,
			AccountID: b.accountID,
			RawProps:  map[string]string{"UserId": u.UserID},
		}
		b.addPrincipal(pr)

		// Attached managed policies.
		for _, ap := range u.AttachedManagedPolicies {
			polID := b.policyID(ap.PolicyName)
			pol := b.ensureManagedPolicyStub(polID, ap.PolicyName, ap.PolicyARN)
			b.addEdge(prID, pol.ID, model.EdgeKindAttachedPolicy)
		}

		// Inline policies.
		for _, ip := range u.UserPolicies {
			polID := b.policyID(u.UserName + "::" + ip.PolicyName)
			var rawJSON string
			if ip.PolicyDocument != nil {
				if raw, err := json.Marshal(ip.PolicyDocument); err == nil {
					rawJSON = string(raw)
				}
			}
			pol := b.buildPolicyFromDocument(polID, ip.PolicyName, "", true, ip.PolicyDocument, rawJSON)
			b.addPolicy(pol)
			b.addEdge(prID, polID, model.EdgeKindInlinePolicy)
		}
	}
}

// processRoles registers Principal nodes and associated Policy/Permission/Edge
// entities for all IAM roles in the export.
func (b *snapshotBuilder) processRoles(roles []iamRole) {
	for _, r := range roles {
		prID := b.principalID("IAMRole", r.RoleName)
		pr := &model.Principal{
			ID:        prID,
			Kind:      model.PrincipalKindIAMRole,
			ARN:       r.ARN,
			Name:      r.RoleName,
			AccountID: b.accountID,
			RawProps:  map[string]string{"RoleId": r.RoleID},
		}
		b.addPrincipal(pr)

		// Attached managed policies.
		for _, ap := range r.AttachedManagedPolicies {
			polID := b.policyID(ap.PolicyName)
			pol := b.ensureManagedPolicyStub(polID, ap.PolicyName, ap.PolicyARN)
			b.addEdge(prID, pol.ID, model.EdgeKindAttachedPolicy)
		}

		// Inline policies.
		for _, ip := range r.RolePolicyList {
			polID := b.policyID(r.RoleName + "::" + ip.PolicyName)
			var rawJSON string
			if ip.PolicyDocument != nil {
				if raw, err := json.Marshal(ip.PolicyDocument); err == nil {
					rawJSON = string(raw)
				}
			}
			pol := b.buildPolicyFromDocument(polID, ip.PolicyName, "", true, ip.PolicyDocument, rawJSON)
			b.addPolicy(pol)
			b.addEdge(prID, polID, model.EdgeKindInlinePolicy)
		}
	}
}

// processGroups registers Principal nodes and associated Policy/Permission/Edge
// entities for all IAM groups in the export.
func (b *snapshotBuilder) processGroups(groups []iamGroup) {
	for _, g := range groups {
		prID := b.principalID("IAMGroup", g.GroupName)
		pr := &model.Principal{
			ID:        prID,
			Kind:      model.PrincipalKindIAMGroup,
			ARN:       g.ARN,
			Name:      g.GroupName,
			AccountID: b.accountID,
			RawProps:  map[string]string{"GroupId": g.GroupID},
		}
		b.addPrincipal(pr)

		// Attached managed policies.
		for _, ap := range g.AttachedManagedPolicies {
			polID := b.policyID(ap.PolicyName)
			pol := b.ensureManagedPolicyStub(polID, ap.PolicyName, ap.PolicyARN)
			b.addEdge(prID, pol.ID, model.EdgeKindAttachedPolicy)
		}

		// Inline policies.
		for _, ip := range g.GroupPolicyList {
			polID := b.policyID(g.GroupName + "::" + ip.PolicyName)
			var rawJSON string
			if ip.PolicyDocument != nil {
				if raw, err := json.Marshal(ip.PolicyDocument); err == nil {
					rawJSON = string(raw)
				}
			}
			pol := b.buildPolicyFromDocument(polID, ip.PolicyName, "", true, ip.PolicyDocument, rawJSON)
			b.addPolicy(pol)
			b.addEdge(prID, polID, model.EdgeKindInlinePolicy)
		}
	}
}

// processManagedPolicies fully populates any managed Policy nodes whose
// PolicyDocument was provided in the top-level "policies" array. Stubs created
// earlier by ensureManagedPolicyStub are upgraded in-place.
func (b *snapshotBuilder) processManagedPolicies(policies []iamPolicy) {
	for _, mp := range policies {
		polID := b.policyID(mp.PolicyName)

		var rawJSON string
		if mp.PolicyDocument != nil {
			if raw, err := json.Marshal(mp.PolicyDocument); err == nil {
				rawJSON = string(raw)
			}
		}

		if existing, ok := b.policiesByID[polID]; ok {
			// Upgrade the stub: fill in the document and permissions.
			existing.ARN = mp.PolicyARN
			existing.JSONRaw = rawJSON
			if mp.PolicyDocument != nil {
				b.attachPermissions(existing, mp.PolicyDocument)
			}
			if mp.PolicyARN != "" {
				b.policiesByARN[mp.PolicyARN] = existing
			}
			continue
		}

		// Not yet created: build the full policy now.
		pol := b.buildPolicyFromDocument(polID, mp.PolicyName, mp.PolicyARN, false, mp.PolicyDocument, rawJSON)
		b.addPolicy(pol)
	}
}

// attachPermissions parses a policyDocument and appends new Permission entries
// (and associated edges/resources) to an existing Policy. Used when upgrading
// a stub created before the managed policies array was processed.
func (b *snapshotBuilder) attachPermissions(pol *model.Policy, doc *policyDocument) {
	if doc == nil {
		return
	}
	for _, stmt := range doc.Statement {
		effect := stmt.Effect
		if effect == "" {
			effect = "Allow"
		}
		actions := normalizeStringOrSlice(stmt.Action)
		resources := normalizeStringOrSlice(stmt.Resource)

		for _, action := range actions {
			if len(resources) == 0 {
				permID := b.permissionID(pol.ID, action, effect)
				if !b.permissionExists(pol, permID) {
					perm := &model.Permission{
						ID:       permID,
						PolicyID: pol.ID,
						Action:   action,
						Effect:   effect,
					}
					pol.Permissions = append(pol.Permissions, perm)
					b.addEdge(pol.ID, permID, model.EdgeKindAllowsAction)
				}
				continue
			}

			for _, resourceARN := range resources {
				permID := b.permissionID(pol.ID, action+":"+resourceARN, effect)
				if b.permissionExists(pol, permID) {
					continue
				}
				perm := &model.Permission{
					ID:              permID,
					PolicyID:        pol.ID,
					Action:          action,
					Effect:          effect,
					ResourcePattern: resourceARN,
				}
				pol.Permissions = append(pol.Permissions, perm)
				b.addEdge(pol.ID, permID, model.EdgeKindAllowsAction)
				if resourceARN != "*" {
					resID := b.resourceID(resourceARN)
					b.ensureResource(resourceARN, resID)
					b.addEdge(permID, resID, model.EdgeKindAppliesTo)
				}
			}
		}
	}
}

// permissionExists reports whether a Permission with the given ID is already
// present in pol.Permissions.
func (b *snapshotBuilder) permissionExists(pol *model.Policy, permID string) bool {
	for _, existing := range pol.Permissions {
		if existing.ID == permID {
			return true
		}
	}
	return false
}

// ensureManagedPolicyStub returns an existing policy or creates a minimal stub
// for a managed policy that has not yet been fully processed from the "policies"
// top-level array.
func (b *snapshotBuilder) ensureManagedPolicyStub(polID, name, arn string) *model.Policy {
	if pol, ok := b.policiesByID[polID]; ok {
		return pol
	}
	pol := &model.Policy{
		ID:       polID,
		ARN:      arn,
		Name:     name,
		IsInline: false,
	}
	b.addPolicy(pol)
	return pol
}

// Second-pass edge wiring

// wireUserGroupEdges creates MEMBER_OF edges from each IAM user to each group
// it belongs to, using the GroupList field. If a group named in GroupList was
// not present in the top-level "groups" array, a stub Principal node is created
// so that the edge has a valid target.
func (b *snapshotBuilder) wireUserGroupEdges(users []iamUser) {
	for _, u := range users {
		userID := b.principalID("IAMUser", u.UserName)
		for _, groupName := range u.GroupList {
			groupID := b.principalID("IAMGroup", groupName)
			groupARN := b.arnForGroup(groupName)
			// Create a stub group principal if it was not yet registered.
			if _, ok := b.principalsByARN[groupARN]; !ok {
				stub := &model.Principal{
					ID:        groupID,
					Kind:      model.PrincipalKindIAMGroup,
					ARN:       groupARN,
					Name:      groupName,
					AccountID: b.accountID,
				}
				b.addPrincipal(stub)
			}
			b.addEdge(userID, groupID, model.EdgeKindMemberOf)
		}
	}
}

// arnForGroup constructs a best-effort ARN for a group given only its name.
func (b *snapshotBuilder) arnForGroup(groupName string) string {
	return fmt.Sprintf("arn:aws:iam::%s:group/%s", b.accountID, groupName)
}

// wireAssumeRoleEdges creates ASSUMES_ROLE edges from each principal named in
// a role's AssumeRolePolicyDocument trust policy to that role.
func (b *snapshotBuilder) wireAssumeRoleEdges(roles []iamRole) {
	for _, r := range roles {
		roleID := b.principalID("IAMRole", r.RoleName)
		if r.AssumeRolePolicyDocument == nil {
			continue
		}
		for _, stmt := range r.AssumeRolePolicyDocument.Statement {
			if stmt.Principal == nil {
				continue
			}
			for _, arn := range stmt.Principal.arns() {
				if arn == "*" || arn == "" {
					continue
				}
				srcPR := b.ensurePrincipalStub(arn)
				b.addEdge(srcPR.ID, roleID, model.EdgeKindAssumesRole)
			}
		}
	}
}

// Utility helpers

// normalizeStringOrSlice decodes a json.RawMessage that may be either a JSON
// string or a JSON array of strings and returns the canonical []string form.
// Unknown or null JSON values return nil.
func normalizeStringOrSlice(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	// Try single string.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}
	}
	// Try string slice.
	var ss []string
	if err := json.Unmarshal(raw, &ss); err == nil {
		return ss
	}
	return nil
}

// resourceKindFromARN derives a coarse resource kind string from an AWS ARN.
// Examples:
//
//	arn:aws:s3:::my-bucket       → "S3Bucket"
//	arn:aws:iam::123:role/Dev    → "IAMRole"
//	arn:aws:kms::123:key/abc     → "KMSKey"
//	arn:aws:secretsmanager::...  → "SecretsManagerSecret"
func resourceKindFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return "AWSResource"
	}
	service := parts[2]
	resourcePart := strings.Join(parts[5:], ":")
	switch service {
	case "s3":
		return "S3Bucket"
	case "iam":
		if strings.HasPrefix(resourcePart, "role/") {
			return "IAMRole"
		}
		if strings.HasPrefix(resourcePart, "user/") {
			return "IAMUser"
		}
		if strings.HasPrefix(resourcePart, "group/") {
			return "IAMGroup"
		}
		if strings.HasPrefix(resourcePart, "policy/") {
			return "IAMPolicy"
		}
		return "IAMResource"
	case "kms":
		if strings.HasPrefix(resourcePart, "key/") {
			return "KMSKey"
		}
		return "KMSResource"
	case "secretsmanager":
		return "SecretsManagerSecret"
	case "lambda":
		return "LambdaFunction"
	case "ec2":
		return "EC2Resource"
	case "rds":
		return "RDSInstance"
	default:
		return "AWSResource"
	}
}

// principalKindFromARN infers a PrincipalKind from a trust-policy ARN.
func principalKindFromARN(arn string) model.PrincipalKind {
	switch {
	case strings.Contains(arn, ":role/"):
		return model.PrincipalKindIAMRole
	case strings.Contains(arn, ":user/"):
		return model.PrincipalKindIAMUser
	case strings.Contains(arn, ":group/"):
		return model.PrincipalKindIAMGroup
	default:
		// Service principals (e.g., "ec2.amazonaws.com") are represented as
		// stub IAMRole principals for graph purposes.
		return model.PrincipalKindIAMRole
	}
}

// nameFromARN extracts the short name from the resource portion of an ARN.
// For "arn:aws:iam::123456789012:role/DevRole" it returns "DevRole".
// For a plain service principal like "ec2.amazonaws.com" it returns the string
// unchanged.
func nameFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return arn
	}
	resourcePart := strings.Join(parts[5:], ":")
	if slashIdx := strings.LastIndex(resourcePart, "/"); slashIdx >= 0 {
		return resourcePart[slashIdx+1:]
	}
	return resourcePart
}
