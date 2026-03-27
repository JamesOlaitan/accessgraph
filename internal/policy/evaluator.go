// Package policy provides OPA-based policy evaluation for AccessGraph.
//
// The package embeds one or more Rego policy files and evaluates them against
// a model.Snapshot to produce a slice of model.Finding values that describe
// policy violations discovered in the environment.
//
// Dependency rule: this package imports only the standard library,
// github.com/JamesOlaitan/accessgraph/internal/model, and the OPA library
// (github.com/open-policy-agent/opa/v1/rego). This package must not import
// any other internal package.
package policy

import (
	"context"
	"errors"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// Sentinel errors returned by FindingEvaluator implementations.
var (
	// ErrInvalidInput is returned when a required argument fails a precondition
	// check (e.g., nil snapshot).
	ErrInvalidInput = errors.New("invalid input")

	// ErrOPAUnavailable is returned when the OPA engine is unavailable or
	// returns an unexpected error (e.g., compilation error, undefined query,
	// or an unexpected result shape).
	ErrOPAUnavailable = errors.New("OPA evaluation failed")
)

// FindingEvaluator runs OPA policy rules against a snapshot and converts the
// results into model.Finding values.
//
// Implementations compile the Rego modules once at construction time and reuse
// the compiled query across multiple Evaluate calls for efficiency.
type FindingEvaluator interface {
	// Evaluate runs all OPA rules against the snapshot and returns the full
	// set of violations as model.Finding values.
	//
	// The OPA query path is "data.accessgraph.violations". Each violation
	// object emitted by the rules must carry the keys "rule_id", "severity",
	// "entity_ref", "reason", and "remediation".
	//
	// Parameters:
	//   - ctx:      context for cancellation; forwarded to the OPA evaluator.
	//   - snapshot: the point-in-time IAM environment to evaluate; must not be nil.
	//
	// Returns:
	//   - []*model.Finding, one entry per violation; may be empty but never nil.
	//   - ErrInvalidInput    if snapshot is nil.
	//   - ErrOPAUnavailable  if OPA compilation or evaluation fails.
	Evaluate(ctx context.Context, snapshot *model.Snapshot) ([]*model.Finding, error)
}

// Compile-time assertion: *OPAEvaluator must satisfy FindingEvaluator.
var _ FindingEvaluator = (*OPAEvaluator)(nil)
