package store

import (
	"context"
	"errors"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// Sentinel errors returned by DataStore implementations.
//
// Callers should compare errors using errors.Is rather than direct equality so
// that wrapped errors are handled correctly.
var (
	// ErrNotFound is returned when a requested entity does not exist in the store.
	ErrNotFound = errors.New("entity not found")

	// ErrInvalidInput is returned when a caller supplies an argument that cannot
	// be accepted (e.g., an empty primary-key string).
	ErrInvalidInput = errors.New("invalid input")
)

// BenchmarkResultReader is a narrow read interface consumed by the aggregator.
// DataStore embeds it so that aggregators accept a DataStore directly while
// remaining testable with a minimal stub.
type BenchmarkResultReader interface {
	// LoadBenchmarkResults retrieves all benchmark results for the given run ID.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//   - runID: the benchmark run to query; must be non-empty.
	//
	// Returns:
	//   - A slice of *model.BenchmarkResult; empty slice (not nil) when none exist.
	//
	// Errors:
	//   - ErrInvalidInput if runID is empty.
	LoadBenchmarkResults(ctx context.Context, runID string) ([]*model.BenchmarkResult, error)
}

// DataStore is the persistence interface for all AccessGraph domain entities.
//
// Implementations must be safe for concurrent use. Every method accepts a
// context.Context; implementations must propagate cancellation and deadline
// signals to their underlying storage operations.
//
// Errors:
//   - ErrNotFound is returned when a Load or List method finds no matching entity.
//   - ErrInvalidInput is returned when a required argument (e.g., a primary key) is empty.
//   - Any other returned error originates from the underlying storage layer.
type DataStore interface {
	// BenchmarkResultReader embeds the narrow benchmark-read interface so that
	// aggregators can accept a DataStore directly.
	BenchmarkResultReader

	// SaveSnapshot persists a Snapshot and all of its nested entities (Principals,
	// Policies with their Permissions, Resources, and Edges) atomically.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//   - s: the Snapshot to save; must have a non-empty ID.
	//
	// Errors:
	//   - ErrInvalidInput if s is nil or s.ID is empty.
	SaveSnapshot(ctx context.Context, s *model.Snapshot) error

	// LoadSnapshot retrieves a Snapshot by its unique ID, fully populating all
	// nested fields (Principals, Policies, Resources, Edges).
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//   - id: the snapshot ID to look up; must be non-empty.
	//
	// Returns:
	//   - A fully populated *model.Snapshot on success.
	//
	// Errors:
	//   - ErrNotFound if no snapshot with the given ID exists.
	//   - ErrInvalidInput if id is empty.
	LoadSnapshot(ctx context.Context, id string) (*model.Snapshot, error)

	// LoadSnapshotByLabel retrieves a Snapshot by its human-readable label.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//   - label: the snapshot label to look up; must be non-empty.
	//
	// Returns:
	//   - A fully populated *model.Snapshot on success.
	//
	// Errors:
	//   - ErrNotFound if no snapshot with the given label exists.
	//   - ErrInvalidInput if label is empty.
	LoadSnapshotByLabel(ctx context.Context, label string) (*model.Snapshot, error)

	// ListSnapshots returns all stored snapshots ordered by creation time descending.
	// Nested fields (Principals, Policies, Resources, Edges) are populated for each
	// returned snapshot.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//
	// Returns:
	//   - A slice of *model.Snapshot; empty slice (not nil) when none exist.
	ListSnapshots(ctx context.Context) ([]*model.Snapshot, error)

	// SaveFindings persists a batch of Finding records.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//   - findings: slice of findings to save; each must have a non-empty ID and SnapshotID.
	//
	// Errors:
	//   - ErrInvalidInput if findings is nil or any element has an empty ID.
	SaveFindings(ctx context.Context, findings []*model.Finding) error

	// LoadFindings retrieves all findings associated with the given snapshot ID.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//   - snapshotID: the snapshot to query; must be non-empty.
	//
	// Returns:
	//   - A slice of *model.Finding; empty slice (not nil) when none exist.
	//
	// Errors:
	//   - ErrInvalidInput if snapshotID is empty.
	LoadFindings(ctx context.Context, snapshotID string) ([]*model.Finding, error)

	// SaveAttackPaths persists a batch of AttackPath records.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//   - paths: slice of attack paths to save; each must have a non-empty ID and SnapshotID.
	//
	// Errors:
	//   - ErrInvalidInput if paths is nil or any element has an empty ID.
	SaveAttackPaths(ctx context.Context, paths []*model.AttackPath) error

	// LoadAttackPaths retrieves all attack paths associated with the given snapshot ID.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//   - snapshotID: the snapshot to query; must be non-empty.
	//
	// Returns:
	//   - A slice of *model.AttackPath; empty slice (not nil) when none exist.
	//   - Paths that reference missing principals or resources are silently skipped
	//     (a warning is logged via slog).
	//
	// Errors:
	//   - ErrInvalidInput if snapshotID is empty.
	LoadAttackPaths(ctx context.Context, snapshotID string) ([]*model.AttackPath, error)

	// SaveBenchmarkResult persists a single BenchmarkResult record.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//   - r: the result to save; must have a non-empty ID and ScenarioID.
	//
	// Errors:
	//   - ErrInvalidInput if r is nil or r.ID is empty.
	SaveBenchmarkResult(ctx context.Context, r *model.BenchmarkResult) error

	// SaveScenario persists a Scenario record.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//   - s: the scenario to save; must have a non-empty ID.
	//
	// Errors:
	//   - ErrInvalidInput if s is nil or s.ID is empty.
	SaveScenario(ctx context.Context, s *model.Scenario) error

	// LoadScenario retrieves a Scenario by its unique ID.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//   - id: the scenario ID to look up; must be non-empty.
	//
	// Returns:
	//   - A *model.Scenario on success.
	//
	// Errors:
	//   - ErrNotFound if no scenario with the given ID exists.
	//   - ErrInvalidInput if id is empty.
	LoadScenario(ctx context.Context, id string) (*model.Scenario, error)

	// ListScenarios returns all stored scenarios.
	//
	// Parameters:
	//   - ctx: context for cancellation/deadline propagation.
	//
	// Returns:
	//   - A slice of *model.Scenario; empty slice (not nil) when none exist.
	ListScenarios(ctx context.Context) ([]*model.Scenario, error)

	// SaveClassMetrics persists per-class recall for one (tool, class) pair.
	SaveClassMetrics(ctx context.Context, runID string, tool model.ToolName, class model.ChainLengthClass, m *model.ClassMetrics) error

	// LoadClassMetrics returns all class metrics for the given run ID.
	LoadClassMetrics(ctx context.Context, runID string) (map[model.ToolName]map[model.ChainLengthClass]*model.ClassMetrics, error)

	// SaveToolMetrics persists tool-level aggregated precision/recall/F1.
	SaveToolMetrics(ctx context.Context, runID string, tool model.ToolName, m *model.ToolMetrics) error

	// LoadToolMetrics returns all tool metrics for the given run ID.
	LoadToolMetrics(ctx context.Context, runID string) (map[model.ToolName]*model.ToolMetrics, error)

	// SaveFalsePositiveRate persists FPR computed from TN environments.
	SaveFalsePositiveRate(ctx context.Context, runID string, tool model.ToolName, fpr *model.FalsePositiveRate) error

	// LoadFalsePositiveRates returns all FPR entries for the given run ID.
	LoadFalsePositiveRates(ctx context.Context, runID string) (map[model.ToolName]*model.FalsePositiveRate, error)

	// Close releases all resources held by the store.
	//
	// After Close returns, the DataStore must not be used. Implementations must
	// make Close safe to call multiple times (subsequent calls are no-ops or
	// return nil).
	Close() error
}
