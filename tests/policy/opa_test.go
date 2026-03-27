package policy_test

import (
	"context"
	"errors"
	"testing"
	"testing/fstest"

	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/policy"
)

// wildcardRegoContent is an inline copy of policy/iam_wildcard.rego.
// It fires for any Allow permission whose action ends with ":*" and reports
// MEDIUM severity (matching the real rule's logic for service-level wildcards
// on a non-wildcard resource).
const wildcardRegoContent = `package accessgraph
import rego.v1
violations contains result if {
    some policy in input.policies
    some perm in policy.permissions
    perm.effect == "Allow"
    endswith(perm.action, ":*")
    result := {"rule_id": "IAM.WildcardAction", "severity": "MEDIUM",
               "entity_ref": policy.arn, "reason": "wildcard action", "remediation": "fix it"}
}`

// noFireRegoContent is a rule that never fires (Deny permission only).
const noFireRegoContent = `package accessgraph
import rego.v1
violations contains result if {
    some policy in input.policies
    some perm in policy.permissions
    perm.effect == "Allow"
    perm.action == "THIS_ACTION_NEVER_EXISTS_IN_TESTS"
    result := {"rule_id": "Noop.Rule", "severity": "LOW",
               "entity_ref": policy.arn, "reason": "noop", "remediation": "none"}
}`

// invalidRegoContent is syntactically broken Rego.
const invalidRegoContent = `package accessgraph
import rego.v1
this is not valid rego {{{{`

func snapshotWithAllowPermission(action string) *model.Snapshot {
	perm := &model.Permission{
		ID:              "perm-1",
		PolicyID:        "pol-1",
		Action:          action,
		ResourcePattern: "arn:aws:s3:::my-bucket",
		Effect:          "Allow",
	}
	pol := &model.Policy{
		ID:          "pol-1",
		SnapshotID:  "snap-1",
		ARN:         "arn:aws:iam::123456789012:policy/TestPolicy",
		Name:        "TestPolicy",
		IsInline:    false,
		Permissions: []*model.Permission{perm},
	}
	return &model.Snapshot{
		ID:       "snap-1",
		Label:    "test",
		Provider: "aws",
		Policies: []*model.Policy{pol},
	}
}

// snapshotWithDenyPermission builds a snapshot whose single permission is a
// Deny, so no wildcard-action rule should fire.
func snapshotWithDenyPermission() *model.Snapshot {
	perm := &model.Permission{
		ID:              "perm-deny-1",
		PolicyID:        "pol-deny-1",
		Action:          "s3:*",
		ResourcePattern: "*",
		Effect:          "Deny",
	}
	pol := &model.Policy{
		ID:          "pol-deny-1",
		SnapshotID:  "snap-deny",
		ARN:         "arn:aws:iam::123456789012:policy/DenyAll",
		Name:        "DenyAll",
		Permissions: []*model.Permission{perm},
	}
	return &model.Snapshot{
		ID:       "snap-deny",
		Label:    "test-deny",
		Provider: "aws",
		Policies: []*model.Policy{pol},
	}
}

// TestOPAEvaluatorWildcardActionFinding verifies that a snapshot with a single
// Allow permission whose action is "s3:*" produces at least one finding with
// RuleID == "IAM.WildcardAction" and Severity == model.SeverityMedium.
//
// The inline Rego used here matches the real policy/iam_wildcard.rego logic
// for a service-level wildcard (e.g. "s3:*") on a specific resource, which is
// rated MEDIUM.
func TestOPAEvaluatorWildcardActionFinding(t *testing.T) {
	testFS := fstest.MapFS{
		"iam_wildcard.rego": &fstest.MapFile{Data: []byte(wildcardRegoContent)},
	}

	evaluator, err := policy.NewOPAEvaluator(testFS)
	if err != nil {
		t.Fatalf("NewOPAEvaluator returned unexpected error: %v", err)
	}

	snap := snapshotWithAllowPermission("s3:*")

	ctx := context.Background()
	findings, err := evaluator.Evaluate(ctx, snap)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got none")
	}

	var wildcardFinding *model.Finding
	for _, f := range findings {
		if f.RuleID == "IAM.WildcardAction" {
			wildcardFinding = f
			break
		}
	}
	if wildcardFinding == nil {
		t.Fatalf("expected a finding with RuleID=%q, none found in %+v", "IAM.WildcardAction", findings)
	}
	if wildcardFinding.Severity != model.SeverityMedium {
		t.Errorf("expected Severity=%q for s3:* on specific resource, got %q",
			model.SeverityMedium, wildcardFinding.Severity)
	}
}

// TestOPAEvaluatorNoViolations verifies that a snapshot whose only permission
// has Effect="Deny" produces no findings. The wildcard-action rule only fires
// for Effect=="Allow", so Deny permissions must be silently ignored.
func TestOPAEvaluatorNoViolations(t *testing.T) {
	testFS := fstest.MapFS{
		"iam_wildcard.rego": &fstest.MapFile{Data: []byte(wildcardRegoContent)},
	}

	evaluator, err := policy.NewOPAEvaluator(testFS)
	if err != nil {
		t.Fatalf("NewOPAEvaluator returned unexpected error: %v", err)
	}

	snap := snapshotWithDenyPermission()

	ctx := context.Background()
	findings, err := evaluator.Evaluate(ctx, snap)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for Deny-only snapshot, got %d: %+v", len(findings), findings)
	}
}

// TestOPAEvaluatorNilSnapshot verifies that passing a nil snapshot to Evaluate
// returns a non-nil error that wraps policy.ErrInvalidInput.
func TestOPAEvaluatorNilSnapshot(t *testing.T) {
	testFS := fstest.MapFS{
		"iam_wildcard.rego": &fstest.MapFile{Data: []byte(wildcardRegoContent)},
	}

	evaluator, err := policy.NewOPAEvaluator(testFS)
	if err != nil {
		t.Fatalf("NewOPAEvaluator returned unexpected error: %v", err)
	}

	ctx := context.Background()
	_, err = evaluator.Evaluate(ctx, nil)
	if err == nil {
		t.Fatal("expected an error when snapshot is nil, got nil")
	}
	if !errors.Is(err, policy.ErrInvalidInput) {
		t.Errorf("expected error wrapping ErrInvalidInput, got: %v", err)
	}
}

// TestOPAEvaluatorMultipleRules loads two rules into a single MapFS: the
// wildcard-action rule (which fires for "s3:*") and a noop rule (which never
// fires). It verifies that exactly one finding is returned, confirming that
// the noop rule does not produce spurious findings.
func TestOPAEvaluatorMultipleRules(t *testing.T) {
	testFS := fstest.MapFS{
		// The wildcard rule fires for "s3:*".
		"iam_wildcard.rego": &fstest.MapFile{Data: []byte(wildcardRegoContent)},
		// The noop rule never fires; its action string is not present in the snapshot.
		"noop.rego": &fstest.MapFile{Data: []byte(noFireRegoContent)},
	}

	evaluator, err := policy.NewOPAEvaluator(testFS)
	if err != nil {
		t.Fatalf("NewOPAEvaluator returned unexpected error: %v", err)
	}

	snap := snapshotWithAllowPermission("s3:*")

	ctx := context.Background()
	findings, err := evaluator.Evaluate(ctx, snap)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}

	// Only the wildcard rule should have fired; the noop rule must not add findings.
	if len(findings) != 1 {
		t.Errorf("expected exactly 1 finding with two rules (one fires, one does not), got %d: %+v",
			len(findings), findings)
	}
	if len(findings) > 0 && findings[0].RuleID != "IAM.WildcardAction" {
		t.Errorf("expected RuleID=%q, got %q", "IAM.WildcardAction", findings[0].RuleID)
	}
}

// TestOPAEvaluatorInvalidRego verifies that NewOPAEvaluator returns a non-nil
// error when the MapFS contains syntactically invalid Rego. OPA detects the
// syntax error at compile time during PrepareForEval, so the constructor must
// propagate that failure before returning an evaluator.
func TestOPAEvaluatorInvalidRego(t *testing.T) {
	invalidFS := fstest.MapFS{
		"broken.rego": &fstest.MapFile{Data: []byte(invalidRegoContent)},
	}

	_, err := policy.NewOPAEvaluator(invalidFS)
	if err == nil {
		t.Fatal("expected NewOPAEvaluator to return an error for invalid Rego, got nil")
	}
}

// TestOPAEvaluatorEmptyFS documents the behavior of NewOPAEvaluator when
// passed a MapFS that contains no .rego files at all.
//
// Observed behavior: NewOPAEvaluator succeeds (no error), and the resulting
// evaluator returns zero findings for any snapshot, because there are no rules
// to fire. OPA compiles the empty module set successfully and the
// "data.accessgraph.violations" query evaluates to an undefined (empty) result.
func TestOPAEvaluatorEmptyFS(t *testing.T) {
	emptyFS := fstest.MapFS{}

	evaluator, err := policy.NewOPAEvaluator(emptyFS)
	if err != nil {
		// An error here is also acceptable — if the implementation chooses to
		// reject an empty module set, the test documents that behavior instead.
		t.Logf("NewOPAEvaluator returned error for empty FS (acceptable): %v", err)
		return
	}

	// If construction succeeded, Evaluate must return zero findings.
	snap := snapshotWithAllowPermission("s3:*")
	ctx := context.Background()
	findings, evalErr := evaluator.Evaluate(ctx, snap)
	if evalErr != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", evalErr)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings from empty rule set, got %d", len(findings))
	}
}

// TestOPAEvaluatorDegradedMode verifies that ErrOPAUnavailable is returned
// when OPA evaluation fails due to compilation of invalid Rego modules.
//
// This is the "degraded mode" path: service/analysis.go catches ErrOPAUnavailable
// and continues with PolicyEvalSkipped=true rather than aborting the pipeline.
// Here we verify that NewOPAEvaluator propagates ErrOPAUnavailable so that
// callers can apply the degraded-mode logic.
func TestOPAEvaluatorDegradedMode(t *testing.T) {
	// Providing a broken Rego module triggers a compile-time error in
	// NewOPAEvaluator, which wraps and returns ErrOPAUnavailable.
	brokenFS := fstest.MapFS{
		"broken.rego": &fstest.MapFile{Data: []byte(invalidRegoContent)},
	}

	_, err := policy.NewOPAEvaluator(brokenFS)
	if err == nil {
		t.Fatal("expected ErrOPAUnavailable when Rego is invalid, got nil")
	}
	if !errors.Is(err, policy.ErrOPAUnavailable) {
		t.Errorf("expected error wrapping ErrOPAUnavailable, got: %v", err)
	}
}

// TestNewOPAEvaluatorNilFS verifies that passing a nil fs.FS to NewOPAEvaluator
// returns a non-nil error that wraps policy.ErrInvalidInput. The constructor
// must guard against nil before attempting to walk the filesystem.
func TestNewOPAEvaluatorNilFS(t *testing.T) {
	_, err := policy.NewOPAEvaluator(nil)
	if err == nil {
		t.Fatal("expected NewOPAEvaluator to return an error for nil FS, got nil")
	}
	if !errors.Is(err, policy.ErrInvalidInput) {
		t.Errorf("expected error wrapping ErrInvalidInput, got: %v", err)
	}
}
