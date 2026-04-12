// Package iampolicy defines canonical predicates over IAM policy documents
// and principals. These predicates are referenced by findings_schema.md and
// ARCHITECTURE.md as "single canonical definitions" and are imported by the
// parser, graph, analyzer, and benchmark layers.
//
// Add a new predicate to this package when (a) the predicate operates on
// policy or principal content, (b) more than one internal package needs to
// call it, and (c) the predicate is referenced by name in findings_schema.md
// or ARCHITECTURE.md as a canonical definition.
//
// This package imports only internal/model. It must never import
// internal/parser, internal/graph, internal/analyzer, internal/benchmark,
// or internal/service, to keep the dependency graph acyclic and the
// predicates layer-independent.
package iampolicy
