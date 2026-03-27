package store

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// Compile-time assertion that MemStore satisfies the DataStore interface.
var _ DataStore = (*MemStore)(nil)

// MemStore is a thread-safe in-memory implementation of DataStore intended for
// use in tests and local development where a persistent SQLite file is not
// required.
//
// MemStore stores all entities in plain Go maps protected by a sync.RWMutex.
// All methods behave identically to Store for the operations that tests exercise.
// Calling Close is a no-op; the store is garbage-collected normally.
type MemStore struct {
	mu                 sync.RWMutex
	snapshots          map[string]*model.Snapshot                                                   // keyed by Snapshot.ID
	findings           map[string][]*model.Finding                                                  // keyed by SnapshotID
	attackPaths        map[string][]*model.AttackPath                                               // keyed by SnapshotID
	benchmarkResults   map[string][]*model.BenchmarkResult                                          // keyed by RunID
	scenarios          map[string]*model.Scenario                                                   // keyed by Scenario.ID
	classMetrics       map[string]map[model.ToolName]map[model.ChainLengthClass]*model.ClassMetrics // keyed by runID
	toolMetrics        map[string]map[model.ToolName]*model.ToolMetrics                             // keyed by runID
	falsePositiveRates map[string]map[model.ToolName]*model.FalsePositiveRate                       // keyed by runID
}

// NewMemStore allocates and returns a new, empty MemStore.
//
// Returns:
//   - A ready-to-use *MemStore with all internal maps initialized.
func NewMemStore() *MemStore {
	return &MemStore{
		snapshots:          make(map[string]*model.Snapshot),
		findings:           make(map[string][]*model.Finding),
		attackPaths:        make(map[string][]*model.AttackPath),
		benchmarkResults:   make(map[string][]*model.BenchmarkResult),
		scenarios:          make(map[string]*model.Scenario),
		classMetrics:       make(map[string]map[model.ToolName]map[model.ChainLengthClass]*model.ClassMetrics),
		toolMetrics:        make(map[string]map[model.ToolName]*model.ToolMetrics),
		falsePositiveRates: make(map[string]map[model.ToolName]*model.FalsePositiveRate),
	}
}

// SaveSnapshot stores a deep copy of the given Snapshot so that later mutations
// by the caller do not affect stored state.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//   - s: the Snapshot to save; must be non-nil with a non-empty ID.
//
// Errors:
//   - ErrInvalidInput if s is nil or s.ID is empty.
func (m *MemStore) SaveSnapshot(_ context.Context, s *model.Snapshot) error {
	if s == nil || s.ID == "" {
		return fmt.Errorf("store.MemStore.SaveSnapshot: %w", ErrInvalidInput)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshots[s.ID] = cloneSnapshot(s)
	return nil
}

// LoadSnapshot returns the Snapshot with the given ID, or ErrNotFound.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//   - id: the snapshot ID to look up; must be non-empty.
//
// Returns:
//   - A copy of the stored *model.Snapshot on success.
//
// Errors:
//   - ErrInvalidInput if id is empty.
//   - ErrNotFound if no snapshot with the given ID exists.
func (m *MemStore) LoadSnapshot(_ context.Context, id string) (*model.Snapshot, error) {
	if id == "" {
		return nil, fmt.Errorf("store.MemStore.LoadSnapshot: %w", ErrInvalidInput)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.snapshots[id]
	if !ok {
		return nil, fmt.Errorf("store.MemStore.LoadSnapshot: %w", ErrNotFound)
	}
	return cloneSnapshot(s), nil
}

// LoadSnapshotByLabel returns the first Snapshot whose Label matches the given value.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//   - label: the snapshot label to look up; must be non-empty.
//
// Returns:
//   - A copy of the stored *model.Snapshot on success.
//
// Errors:
//   - ErrInvalidInput if label is empty.
//   - ErrNotFound if no snapshot with the given label exists.
func (m *MemStore) LoadSnapshotByLabel(_ context.Context, label string) (*model.Snapshot, error) {
	if label == "" {
		return nil, fmt.Errorf("store.MemStore.LoadSnapshotByLabel: %w", ErrInvalidInput)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.snapshots {
		if s.Label == label {
			return cloneSnapshot(s), nil
		}
	}
	return nil, fmt.Errorf("store.MemStore.LoadSnapshotByLabel: %w", ErrNotFound)
}

// ListSnapshots returns all stored snapshots sorted by CreatedAt descending.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//
// Returns:
//   - A slice of copies of all stored *model.Snapshot; empty slice (not nil) when none exist.
func (m *MemStore) ListSnapshots(_ context.Context) ([]*model.Snapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*model.Snapshot, 0, len(m.snapshots))
	for _, s := range m.snapshots {
		result = append(result, cloneSnapshot(s))
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

// SaveFindings appends a batch of Finding records to the in-memory store,
// replacing any existing finding that has the same ID.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//   - findings: the batch to save; must be non-nil; each element must have a non-empty ID.
//
// Errors:
//   - ErrInvalidInput if findings is nil or any element has an empty ID.
func (m *MemStore) SaveFindings(_ context.Context, findings []*model.Finding) error {
	if findings == nil {
		return fmt.Errorf("store.MemStore.SaveFindings: %w", ErrInvalidInput)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, f := range findings {
		if f == nil || f.ID == "" {
			return fmt.Errorf("store.MemStore.SaveFindings: %w", ErrInvalidInput)
		}
		// Replace any existing finding with the same ID within this snapshot's slice.
		snapshotFindings := m.findings[f.SnapshotID]
		replaced := false
		for i, existing := range snapshotFindings {
			if existing.ID == f.ID {
				snapshotFindings[i] = cloneFinding(f)
				replaced = true
				break
			}
		}
		if !replaced {
			m.findings[f.SnapshotID] = append(snapshotFindings, cloneFinding(f))
		}
	}
	return nil
}

// LoadFindings returns all findings associated with the given snapshot ID.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//   - snapshotID: the snapshot to query; must be non-empty.
//
// Returns:
//   - A slice of *model.Finding; empty slice (not nil) when none exist.
//
// Errors:
//   - ErrInvalidInput if snapshotID is empty.
func (m *MemStore) LoadFindings(_ context.Context, snapshotID string) ([]*model.Finding, error) {
	if snapshotID == "" {
		return nil, fmt.Errorf("store.MemStore.LoadFindings: %w", ErrInvalidInput)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	src := m.findings[snapshotID]
	result := make([]*model.Finding, len(src))
	for i, f := range src {
		result[i] = cloneFinding(f)
	}
	return result, nil
}

// SaveAttackPaths appends a batch of AttackPath records to the in-memory store,
// replacing any existing path that has the same ID.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//   - paths: the batch to save; must be non-nil; each element must have a non-empty ID.
//
// Errors:
//   - ErrInvalidInput if paths is nil or any element has an empty ID.
func (m *MemStore) SaveAttackPaths(_ context.Context, paths []*model.AttackPath) error {
	if paths == nil {
		return fmt.Errorf("store.MemStore.SaveAttackPaths: %w", ErrInvalidInput)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ap := range paths {
		if ap == nil || ap.ID == "" {
			return fmt.Errorf("store.MemStore.SaveAttackPaths: %w", ErrInvalidInput)
		}
		snapshotPaths := m.attackPaths[ap.SnapshotID]
		replaced := false
		for i, existing := range snapshotPaths {
			if existing.ID == ap.ID {
				snapshotPaths[i] = cloneAttackPath(ap)
				replaced = true
				break
			}
		}
		if !replaced {
			m.attackPaths[ap.SnapshotID] = append(snapshotPaths, cloneAttackPath(ap))
		}
	}
	return nil
}

// LoadAttackPaths returns all attack paths for the given snapshot ID.
//
// Paths that reference principal or resource IDs not found in the stored snapshot
// are silently skipped; a warning is emitted via slog.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//   - snapshotID: the snapshot to query; must be non-empty.
//
// Returns:
//   - A slice of *model.AttackPath; empty slice (not nil) when none exist.
//
// Errors:
//   - ErrInvalidInput if snapshotID is empty.
func (m *MemStore) LoadAttackPaths(ctx context.Context, snapshotID string) ([]*model.AttackPath, error) {
	if snapshotID == "" {
		return nil, fmt.Errorf("store.MemStore.LoadAttackPaths: %w", ErrInvalidInput)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Build reference sets from the stored snapshot (if present).
	principalIDs := make(map[string]bool)
	resourceIDs := make(map[string]bool)
	if snap, ok := m.snapshots[snapshotID]; ok {
		for _, p := range snap.Principals {
			principalIDs[p.ID] = true
		}
		for _, r := range snap.Resources {
			resourceIDs[r.ID] = true
		}
	}

	src := m.attackPaths[snapshotID]
	result := make([]*model.AttackPath, 0, len(src))
	for _, ap := range src {
		if len(principalIDs) > 0 && !principalIDs[ap.FromPrincipalID] {
			slog.WarnContext(ctx, "store.MemStore.LoadAttackPaths: skipping path with missing from_principal_id",
				slog.String("path_id", ap.ID),
				slog.String("from_principal_id", ap.FromPrincipalID),
			)
			continue
		}
		if len(resourceIDs) > 0 && !resourceIDs[ap.ToResourceID] {
			slog.WarnContext(ctx, "store.MemStore.LoadAttackPaths: skipping path with missing to_resource_id",
				slog.String("path_id", ap.ID),
				slog.String("to_resource_id", ap.ToResourceID),
			)
			continue
		}
		result = append(result, cloneAttackPath(ap))
	}
	return result, nil
}

// SaveBenchmarkResult stores a single BenchmarkResult, keyed by RunID.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//   - r: the result to save; must be non-nil with a non-empty ID and ScenarioID.
//
// Errors:
//   - ErrInvalidInput if r is nil, r.ID is empty, or r.ScenarioID is empty.
func (m *MemStore) SaveBenchmarkResult(_ context.Context, r *model.BenchmarkResult) error {
	if r == nil || r.ID == "" || r.ScenarioID == "" {
		return fmt.Errorf("store.MemStore.SaveBenchmarkResult: %w", ErrInvalidInput)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	runResults := m.benchmarkResults[r.RunID]
	replaced := false
	for i, existing := range runResults {
		if existing.ID == r.ID {
			c := *r
			runResults[i] = &c
			replaced = true
			break
		}
	}
	if !replaced {
		c := *r
		m.benchmarkResults[r.RunID] = append(runResults, &c)
	}
	return nil
}

// LoadBenchmarkResults returns all benchmark results for the given run ID.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//   - runID: the benchmark run to query; must be non-empty.
//
// Returns:
//   - A slice of *model.BenchmarkResult; empty slice (not nil) when none exist.
//
// Errors:
//   - ErrInvalidInput if runID is empty.
func (m *MemStore) LoadBenchmarkResults(_ context.Context, runID string) ([]*model.BenchmarkResult, error) {
	if runID == "" {
		return nil, fmt.Errorf("store.MemStore.LoadBenchmarkResults: %w", ErrInvalidInput)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	src := m.benchmarkResults[runID]
	result := make([]*model.BenchmarkResult, len(src))
	for i, r := range src {
		c := *r
		result[i] = &c
	}
	return result, nil
}

// SaveScenario stores a copy of the given Scenario, replacing any existing
// scenario with the same ID.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//   - s: the scenario to save; must be non-nil with a non-empty ID.
//
// Errors:
//   - ErrInvalidInput if s is nil or s.ID is empty.
func (m *MemStore) SaveScenario(_ context.Context, s *model.Scenario) error {
	if s == nil || s.ID == "" {
		return fmt.Errorf("store.MemStore.SaveScenario: %w", ErrInvalidInput)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	c := cloneScenario(s)
	m.scenarios[s.ID] = c
	return nil
}

// LoadScenario returns the Scenario with the given ID, or ErrNotFound.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//   - id: the scenario ID to look up; must be non-empty.
//
// Returns:
//   - A copy of the stored *model.Scenario on success.
//
// Errors:
//   - ErrInvalidInput if id is empty.
//   - ErrNotFound if no scenario with the given ID exists.
func (m *MemStore) LoadScenario(_ context.Context, id string) (*model.Scenario, error) {
	if id == "" {
		return nil, fmt.Errorf("store.MemStore.LoadScenario: %w", ErrInvalidInput)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.scenarios[id]
	if !ok {
		return nil, fmt.Errorf("store.MemStore.LoadScenario: %w", ErrNotFound)
	}
	return cloneScenario(s), nil
}

// ListScenarios returns all stored scenarios sorted by ID ascending.
//
// Parameters:
//   - ctx: context (unused; present for interface compliance).
//
// Returns:
//   - A slice of copies of all stored *model.Scenario; empty slice (not nil) when none exist.
func (m *MemStore) ListScenarios(_ context.Context) ([]*model.Scenario, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*model.Scenario, 0, len(m.scenarios))
	for _, s := range m.scenarios {
		result = append(result, cloneScenario(s))
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result, nil
}

// SaveClassMetrics persists per-class recall for one (tool, class) pair.
func (m *MemStore) SaveClassMetrics(_ context.Context, runID string, tool model.ToolName, class model.ChainLengthClass, cm *model.ClassMetrics) error {
	if runID == "" || cm == nil {
		return fmt.Errorf("store.MemStore.SaveClassMetrics: %w", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.classMetrics[runID] == nil {
		m.classMetrics[runID] = make(map[model.ToolName]map[model.ChainLengthClass]*model.ClassMetrics)
	}
	if m.classMetrics[runID][tool] == nil {
		m.classMetrics[runID][tool] = make(map[model.ChainLengthClass]*model.ClassMetrics)
	}
	c := *cm
	m.classMetrics[runID][tool][class] = &c
	return nil
}

// LoadClassMetrics returns all class metrics for the given run ID.
func (m *MemStore) LoadClassMetrics(_ context.Context, runID string) (map[model.ToolName]map[model.ChainLengthClass]*model.ClassMetrics, error) {
	if runID == "" {
		return nil, fmt.Errorf("store.MemStore.LoadClassMetrics: %w", ErrInvalidInput)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[model.ToolName]map[model.ChainLengthClass]*model.ClassMetrics)
	for tool, classes := range m.classMetrics[runID] {
		result[tool] = make(map[model.ChainLengthClass]*model.ClassMetrics)
		for class, cm := range classes {
			c := *cm
			result[tool][class] = &c
		}
	}
	return result, nil
}

// SaveToolMetrics persists tool-level aggregated precision/recall/F1.
func (m *MemStore) SaveToolMetrics(_ context.Context, runID string, tool model.ToolName, tm *model.ToolMetrics) error {
	if tm == nil || runID == "" || tool == "" {
		return fmt.Errorf("store.MemStore.SaveToolMetrics: %w", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.toolMetrics[runID] == nil {
		m.toolMetrics[runID] = make(map[model.ToolName]*model.ToolMetrics)
	}
	c := *tm
	m.toolMetrics[runID][tool] = &c
	return nil
}

// LoadToolMetrics returns all tool metrics for the given run ID.
func (m *MemStore) LoadToolMetrics(_ context.Context, runID string) (map[model.ToolName]*model.ToolMetrics, error) {
	if runID == "" {
		return nil, fmt.Errorf("store.MemStore.LoadToolMetrics: %w", ErrInvalidInput)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[model.ToolName]*model.ToolMetrics)
	for tool, tm := range m.toolMetrics[runID] {
		c := *tm
		result[tool] = &c
	}
	return result, nil
}

// SaveFalsePositiveRate persists FPR computed from TN environments.
func (m *MemStore) SaveFalsePositiveRate(_ context.Context, runID string, tool model.ToolName, fpr *model.FalsePositiveRate) error {
	if fpr == nil || runID == "" || tool == "" {
		return fmt.Errorf("store.MemStore.SaveFalsePositiveRate: %w", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.falsePositiveRates[runID] == nil {
		m.falsePositiveRates[runID] = make(map[model.ToolName]*model.FalsePositiveRate)
	}
	c := *fpr
	m.falsePositiveRates[runID][tool] = &c
	return nil
}

// LoadFalsePositiveRates returns all FPR entries for the given run ID.
func (m *MemStore) LoadFalsePositiveRates(_ context.Context, runID string) (map[model.ToolName]*model.FalsePositiveRate, error) {
	if runID == "" {
		return nil, fmt.Errorf("store.MemStore.LoadFalsePositiveRates: %w", ErrInvalidInput)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[model.ToolName]*model.FalsePositiveRate)
	for tool, fpr := range m.falsePositiveRates[runID] {
		c := *fpr
		result[tool] = &c
	}
	return result, nil
}

// Close is a no-op for MemStore; the store is reclaimed by the garbage collector.
//
// Returns:
//   - Always nil.
func (m *MemStore) Close() error {
	return nil
}

// cloneSnapshot returns a deep copy of s including all nested slices and maps.
//
// Parameters:
//   - s: the Snapshot to copy; must not be nil.
//
// Returns:
//   - A new *model.Snapshot that does not share any mutable memory with s.
func cloneSnapshot(s *model.Snapshot) *model.Snapshot {
	c := *s

	c.Principals = make([]*model.Principal, len(s.Principals))
	for i, p := range s.Principals {
		c.Principals[i] = clonePrincipal(p)
	}

	c.Policies = make([]*model.Policy, len(s.Policies))
	for i, pol := range s.Policies {
		c.Policies[i] = clonePolicy(pol)
	}

	c.Resources = make([]*model.Resource, len(s.Resources))
	for i, r := range s.Resources {
		rc := *r
		c.Resources[i] = &rc
	}

	c.Edges = make([]*model.Edge, len(s.Edges))
	for i, e := range s.Edges {
		c.Edges[i] = cloneEdge(e)
	}

	return &c
}

// clonePrincipal returns a deep copy of p including its RawProps map.
//
// Parameters:
//   - p: the Principal to copy; must not be nil.
//
// Returns:
//   - A new *model.Principal that does not share any mutable memory with p.
func clonePrincipal(p *model.Principal) *model.Principal {
	c := *p
	if p.RawProps != nil {
		c.RawProps = make(map[string]string, len(p.RawProps))
		for k, v := range p.RawProps {
			c.RawProps[k] = v
		}
	}
	return &c
}

// clonePolicy returns a deep copy of pol including its Permissions slice.
//
// Parameters:
//   - pol: the Policy to copy; must not be nil.
//
// Returns:
//   - A new *model.Policy that does not share any mutable memory with pol.
func clonePolicy(pol *model.Policy) *model.Policy {
	c := *pol
	c.Permissions = make([]*model.Permission, len(pol.Permissions))
	for i, perm := range pol.Permissions {
		c.Permissions[i] = clonePermission(perm)
	}
	return &c
}

// clonePermission returns a deep copy of perm including its Conditions map.
//
// Parameters:
//   - perm: the Permission to copy; must not be nil.
//
// Returns:
//   - A new *model.Permission that does not share any mutable memory with perm.
func clonePermission(perm *model.Permission) *model.Permission {
	c := *perm
	if perm.Conditions != nil {
		c.Conditions = make(map[string]string, len(perm.Conditions))
		for k, v := range perm.Conditions {
			c.Conditions[k] = v
		}
	}
	return &c
}

// cloneEdge returns a deep copy of e including its Metadata map.
//
// Parameters:
//   - e: the Edge to copy; must not be nil.
//
// Returns:
//   - A new *model.Edge that does not share any mutable memory with e.
func cloneEdge(e *model.Edge) *model.Edge {
	c := *e
	if e.Metadata != nil {
		c.Metadata = make(map[string]string, len(e.Metadata))
		for k, v := range e.Metadata {
			c.Metadata[k] = v
		}
	}
	return &c
}

// cloneFinding returns a shallow copy of f (Finding has no pointer fields).
//
// Parameters:
//   - f: the Finding to copy; must not be nil.
//
// Returns:
//   - A new *model.Finding.
func cloneFinding(f *model.Finding) *model.Finding {
	c := *f
	return &c
}

// cloneAttackPath returns a deep copy of ap including its PathNodes and PathEdges slices.
//
// Parameters:
//   - ap: the AttackPath to copy; must not be nil.
//
// Returns:
//   - A new *model.AttackPath that does not share any mutable memory with ap.
func cloneAttackPath(ap *model.AttackPath) *model.AttackPath {
	c := *ap
	if ap.PathNodes != nil {
		c.PathNodes = make([]string, len(ap.PathNodes))
		copy(c.PathNodes, ap.PathNodes)
	}
	if ap.PathEdges != nil {
		c.PathEdges = make([]string, len(ap.PathEdges))
		copy(c.PathEdges, ap.PathEdges)
	}
	return &c
}

// cloneScenario returns a deep copy of s including its ExpectedAttackPath slice.
//
// Parameters:
//   - s: the Scenario to copy; must not be nil.
//
// Returns:
//   - A new *model.Scenario that does not share any mutable memory with s.
func cloneScenario(s *model.Scenario) *model.Scenario {
	c := *s
	if s.ExpectedAttackPath != nil {
		c.ExpectedAttackPath = make([]string, len(s.ExpectedAttackPath))
		copy(c.ExpectedAttackPath, s.ExpectedAttackPath)
	}
	return &c
}
