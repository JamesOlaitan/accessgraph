package policy

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// OPAEvaluator is the concrete implementation of FindingEvaluator backed by
// the embedded OPA Go library.
//
// Construct instances via NewOPAEvaluator. The zero value is not ready for use.
// All Evaluate calls after successful construction share the same pre-compiled
// PreparedEvalQuery, making repeated evaluations efficient.
type OPAEvaluator struct {
	// preparedQuery holds the compiled OPA query. It is set once in
	// NewOPAEvaluator and read-only thereafter, making Evaluate safe for
	// concurrent use.
	preparedQuery rego.PreparedEvalQuery
}

// NewOPAEvaluator constructs an OPAEvaluator by loading all .rego files from
// policyFS, compiling them against the query "data.accessgraph.violations",
// and returning a pre-compiled PreparedEvalQuery ready for repeated evaluation.
//
// The caller supplies an fs.FS rooted at the directory that contains the .rego
// files (e.g., os.DirFS("policy") or an embed.FS). All files ending in ".rego"
// found anywhere within the FS are loaded as Rego modules. Non-.rego files are
// silently skipped.
//
// Parameters:
//   - policyFS: an fs.FS containing the .rego policy files; must not be nil.
//
// Returns:
//   - *OPAEvaluator ready for Evaluate calls.
//   - ErrInvalidInput    if policyFS is nil.
//   - ErrOPAUnavailable if any .rego file cannot be read or OPA fails to
//     compile the modules.
func NewOPAEvaluator(policyFS fs.FS) (*OPAEvaluator, error) {
	if policyFS == nil {
		return nil, fmt.Errorf("NewOPAEvaluator: %w: policyFS must not be nil", ErrInvalidInput)
	}

	var regoOpts []func(*rego.Rego)
	regoOpts = append(regoOpts, rego.Query("data.accessgraph.violations"))

	err := fs.WalkDir(policyFS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".rego") {
			return nil
		}

		f, openErr := policyFS.Open(path)
		if openErr != nil {
			return fmt.Errorf("open %q: %w", path, openErr)
		}
		defer f.Close()

		content, readErr := io.ReadAll(f)
		if readErr != nil {
			return fmt.Errorf("read %q: %w", path, readErr)
		}

		regoOpts = append(regoOpts, rego.Module(path, string(content)))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("NewOPAEvaluator: %w: walking policy FS: %v", ErrOPAUnavailable, err)
	}

	pq, err := rego.New(regoOpts...).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("NewOPAEvaluator: %w: compiling OPA modules: %v", ErrOPAUnavailable, err)
	}

	return &OPAEvaluator{preparedQuery: pq}, nil
}

// Evaluate implements FindingEvaluator.Evaluate.
//
// It builds an OPA input document from snapshot, runs the pre-compiled query
// "data.accessgraph.violations", and converts each violation object into a
// model.Finding.
//
// Expected violation shape (each element of the result array):
//
//	{
//	  "rule_id":     string,
//	  "severity":    string,  // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
//	  "entity_ref":  string,
//	  "reason":      string,
//	  "remediation": string
//	}
//
// Finding IDs are generated as:
//
//	model.ComputeFindingID(snapshot.ID, ruleID, entityRef)
//
// Parameters:
//   - ctx:      context for cancellation; forwarded to the OPA evaluator.
//   - snapshot: the point-in-time IAM environment to evaluate; must not be nil.
//
// Returns:
//   - []*model.Finding, one entry per violation; may be empty but never nil.
//   - ErrInvalidInput    if snapshot is nil.
//   - ErrOPAUnavailable if OPA evaluation fails or the result set is malformed.
func (e *OPAEvaluator) Evaluate(ctx context.Context, snapshot *model.Snapshot) ([]*model.Finding, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("Evaluate: %w: snapshot must not be nil", ErrInvalidInput)
	}

	input := buildOPAInput(snapshot)

	rs, err := e.preparedQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("Evaluate: %w: %v", ErrOPAUnavailable, err)
	}

	// An empty result set means the query is undefined (no violations).
	if len(rs) == 0 {
		return []*model.Finding{}, nil
	}

	// The result set should have exactly one result whose first expression
	// holds the violations array.
	if len(rs[0].Expressions) == 0 {
		return []*model.Finding{}, nil
	}

	violationsVal := rs[0].Expressions[0].Value
	violations, ok := violationsVal.([]interface{})
	if !ok {
		// The query returned a non-array value; treat as evaluation failure.
		return nil, fmt.Errorf("Evaluate: %w: expected []interface{} from OPA, got %T", ErrOPAUnavailable, violationsVal)
	}

	findings := make([]*model.Finding, 0, len(violations))
	for _, v := range violations {
		obj, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		ruleID := stringField(obj, "rule_id")
		severity := stringField(obj, "severity")
		entityRef := stringField(obj, "entity_ref")
		reason := stringField(obj, "reason")
		remediation := stringField(obj, "remediation")

		findingID := model.ComputeFindingID(snapshot.ID, ruleID, entityRef)

		findings = append(findings, &model.Finding{
			ID:          findingID,
			SnapshotID:  snapshot.ID,
			RuleID:      ruleID,
			Severity:    model.Severity(severity),
			EntityRef:   entityRef,
			Reason:      reason,
			Remediation: remediation,
		})
	}

	return findings, nil
}

// buildOPAInput converts a model.Snapshot into the map[string]interface{}
// structure consumed by the OPA rules as their input document.
//
// The resulting structure mirrors the documented input schema so that Rego
// rules can reference input.principals, input.policies, input.resources, and
// input.edges without additional adaptation.
func buildOPAInput(snapshot *model.Snapshot) map[string]interface{} {
	principals := make([]map[string]interface{}, 0, len(snapshot.Principals))
	for _, p := range snapshot.Principals {
		if p == nil {
			continue
		}
		principals = append(principals, map[string]interface{}{
			"id":         p.ID,
			"arn":        p.ARN,
			"kind":       string(p.Kind),
			"account_id": p.AccountID,
		})
	}

	policies := make([]map[string]interface{}, 0, len(snapshot.Policies))
	for _, pol := range snapshot.Policies {
		if pol == nil {
			continue
		}
		perms := make([]map[string]interface{}, 0, len(pol.Permissions))
		for _, perm := range pol.Permissions {
			if perm == nil {
				continue
			}
			perms = append(perms, map[string]interface{}{
				"action":   perm.Action,
				"resource": perm.ResourcePattern,
				"effect":   perm.Effect,
			})
		}
		policies = append(policies, map[string]interface{}{
			"id":          pol.ID,
			"arn":         pol.ARN,
			"name":        pol.Name,
			"is_inline":   pol.IsInline,
			"permissions": perms,
		})
	}

	resources := make([]map[string]interface{}, 0, len(snapshot.Resources))
	for _, r := range snapshot.Resources {
		if r == nil {
			continue
		}
		resources = append(resources, map[string]interface{}{
			"id":           r.ID,
			"arn":          r.ARN,
			"kind":         r.Kind,
			"is_sensitive": r.IsSensitive,
		})
	}

	edges := make([]map[string]interface{}, 0, len(snapshot.Edges))
	for _, e := range snapshot.Edges {
		if e == nil {
			continue
		}
		edges = append(edges, map[string]interface{}{
			"from": e.FromNodeID,
			"to":   e.ToNodeID,
			"kind": string(e.Kind),
		})
	}

	return map[string]interface{}{
		"snapshot_id": snapshot.ID,
		"principals":  principals,
		"policies":    policies,
		"resources":   resources,
		"edges":       edges,
	}
}

// stringField extracts a string value from a map[string]interface{} by key.
// If the key is absent or the value is not a string, it returns an empty string.
func stringField(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
