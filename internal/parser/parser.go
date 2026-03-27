// Package parser provides interfaces and implementations for ingesting cloud
// IAM environment exports and converting them into the canonical model.Snapshot
// type used throughout AccessGraph.
//
// Dependency rule: this package imports only the standard library and
// github.com/JamesOlaitan/accessgraph/internal/model. This package must not
// import any other internal package.
package parser

import (
	"context"
	"errors"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// Sentinel errors returned by Parser implementations.
var (
	// ErrInvalidInput is returned when the caller supplies nil or empty data.
	ErrInvalidInput = errors.New("invalid input")

	// ErrParseFailed is returned when the JSON is malformed or a required
	// top-level field is absent from the input document.
	ErrParseFailed = errors.New("parse failed")

	// ErrNotImplemented is returned by stub methods that are defined in the
	// interface but not yet implemented in the current phase.
	ErrNotImplemented = errors.New("not implemented")
)

// Parser is the ingestion interface for cloud IAM environment exports.
//
// Each method on a Parser corresponds to exactly one source format. The
// returned Snapshot is ready to be persisted to the DataStore or passed
// directly to a Traverser; its SourcePath field is left empty and should
// be set by the caller if the path is known.
type Parser interface {
	// ParseAWSIAM parses an AWS IAM environment JSON export and returns a
	// Snapshot populated with all principals, policies, permissions, resources,
	// and edges derived from the input document.
	//
	// The data argument must be a JSON object with the following top-level
	// fields: "users", "roles", "groups", "policies". The optional field
	// "account_id" is used to scope generated IDs; it defaults to "unknown"
	// if absent.
	//
	// Parameters:
	//   - ctx:   context for cancellation; long-running JSON unmarshal steps
	//            check ctx.Err() where practical.
	//   - data:  raw JSON bytes of the IAM environment export; must be non-nil
	//            and non-empty.
	//   - label: human-readable snapshot label stored verbatim in Snapshot.Label.
	//
	// Returns:
	//   - *model.Snapshot with all entities populated and edges wired.
	//   - ErrInvalidInput if data is nil or has zero length.
	//   - ErrParseFailed  if the JSON is malformed or a required field is absent.
	ParseAWSIAM(ctx context.Context, data []byte, label string) (*model.Snapshot, error)

	// ParseTerraformPlan parses a Terraform plan JSON export into a Snapshot.
	//
	// Parameters:
	//   - ctx: context for cancellation; implementations must honour it.
	//   - data: raw Terraform plan JSON bytes.
	//   - label: human-readable label to assign to the resulting Snapshot.
	//
	// Returns:
	//   - A *model.Snapshot on success.
	//
	// Errors:
	//   - ErrInvalidInput if data is nil or empty.
	//   - ErrParseFailed if the data cannot be parsed as a Terraform plan.
	//   - ErrNotImplemented if the implementation has not yet been built.
	ParseTerraformPlan(ctx context.Context, data []byte, label string) (*model.Snapshot, error)
}

// Compile-time assertion: AWSIAMParser must satisfy the Parser interface.
var _ Parser = (*AWSIAMParser)(nil)
