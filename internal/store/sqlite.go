package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// Compile-time assertion that Store satisfies the DataStore interface.
var _ DataStore = (*Store)(nil)

// Store is the SQLite-backed implementation of DataStore.
//
// Store uses the modernc.org/sqlite CGo-free driver registered under the name
// "sqlite". All writes that span multiple tables are executed inside a single
// database transaction to maintain consistency.
//
// Callers must call Close when the Store is no longer needed to release the
// underlying database connection pool.
type Store struct {
	db *sql.DB
}

// New opens (or creates) the SQLite database at dbPath, applies the schema, and
// returns a ready-to-use Store.
//
// Parameters:
//   - dbPath: filesystem path to the SQLite file; use ":memory:" for a transient
//     in-process database. Must not be empty.
//
// Returns:
//   - A *Store with an open connection pool on success.
//
// Errors:
//   - ErrInvalidInput if dbPath is empty.
//   - Any driver-level error encountered while opening or migrating the database.
func New(ctx context.Context, dbPath string) (*Store, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, fmt.Errorf("store.New: %w", ErrInvalidInput)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("store.New: open database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)

	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store.New: enable foreign keys: %w", err)
	}

	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode = WAL;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store.New: enable WAL mode: %w", err)
	}

	if err := applySchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store.New: apply schema: %w", err)
	}

	if dbPath != ":memory:" {
		if err := os.Chmod(dbPath, 0o600); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store.New: chmod database file: %w", err)
		}
	}

	return &Store{db: db}, nil
}

// applySchema executes the schemaSQL DDL against db.
//
// Parameters:
//   - db: an open *sql.DB to run the DDL against.
//
// Errors:
//   - Any error returned by the database while executing the schema statements.
func applySchema(ctx context.Context, db *sql.DB) error {
	// Split on semicolons so we can execute each statement individually;
	// modernc.org/sqlite does not support multi-statement Exec in all versions.
	stmts := strings.Split(schemaSQL, ";")
	for _, stmt := range stmts {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute DDL %q: %w", stmt[:min(len(stmt), 60)], err)
		}
	}
	return nil
}

// Close closes the underlying database connection pool.
//
// Returns:
//   - nil on success or if the pool was already closed.
//   - A wrapped driver error on failure.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store.Close: %w", err)
	}
	return nil
}

// SaveSnapshot persists a Snapshot and all of its nested entities atomically.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - s: the Snapshot to persist; must be non-nil with a non-empty ID.
//
// Errors:
//   - ErrInvalidInput if s is nil or s.ID is empty.
//   - Any database error encountered during the transaction.
func (s *Store) SaveSnapshot(ctx context.Context, snap *model.Snapshot) error {
	if snap == nil || snap.ID == "" {
		return fmt.Errorf("store.SaveSnapshot: %w", ErrInvalidInput)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.SaveSnapshot: begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// -- snapshots --
	_, err = tx.ExecContext(ctx,
		`INSERT OR REPLACE INTO snapshots (id, label, provider, source_path, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		snap.ID, snap.Label, snap.Provider, snap.SourcePath,
		snap.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("store.SaveSnapshot: insert snapshot: %w", err)
	}

	// -- principals --
	for _, p := range snap.Principals {
		rawProps, merr := marshalStringMap(p.RawProps)
		if merr != nil {
			err = merr
			return fmt.Errorf("store.SaveSnapshot: marshal principal raw_props: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO principals
			   (id, snapshot_id, kind, arn, name, account_id, raw_props)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			p.ID, snap.ID, string(p.Kind), p.ARN, p.Name, p.AccountID, rawProps,
		)
		if err != nil {
			return fmt.Errorf("store.SaveSnapshot: insert principal %q: %w", p.ID, err)
		}
	}

	// -- policies and permissions --
	for _, pol := range snap.Policies {
		isInline := boolToInt(pol.IsInline)
		_, err = tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO policies
			   (id, snapshot_id, arn, name, is_inline, json_raw)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			pol.ID, snap.ID, pol.ARN, pol.Name, isInline, pol.JSONRaw,
		)
		if err != nil {
			return fmt.Errorf("store.SaveSnapshot: insert policy %q: %w", pol.ID, err)
		}

		for _, perm := range pol.Permissions {
			conds, merr := marshalStringMap(perm.Conditions)
			if merr != nil {
				err = merr
				return fmt.Errorf("store.SaveSnapshot: marshal permission conditions: %w", err)
			}
			_, err = tx.ExecContext(ctx,
				`INSERT OR REPLACE INTO permissions
				   (id, policy_id, action, resource_pattern, effect, conditions)
				 VALUES (?, ?, ?, ?, ?, ?)`,
				perm.ID, pol.ID, perm.Action, perm.ResourcePattern, perm.Effect, conds,
			)
			if err != nil {
				return fmt.Errorf("store.SaveSnapshot: insert permission %q: %w", perm.ID, err)
			}
		}
	}

	// -- resources --
	for _, r := range snap.Resources {
		_, err = tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO resources
			   (id, snapshot_id, arn, kind, is_sensitive)
			 VALUES (?, ?, ?, ?, ?)`,
			r.ID, snap.ID, r.ARN, r.Kind, boolToInt(r.IsSensitive),
		)
		if err != nil {
			return fmt.Errorf("store.SaveSnapshot: insert resource %q: %w", r.ID, err)
		}
	}

	// -- edges --
	for _, e := range snap.Edges {
		meta, merr := marshalStringMap(e.Metadata)
		if merr != nil {
			err = merr
			return fmt.Errorf("store.SaveSnapshot: marshal edge metadata: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO edges
			   (id, snapshot_id, from_node_id, to_node_id, kind, weight, metadata)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			e.ID, snap.ID, e.FromNodeID, e.ToNodeID, string(e.Kind), e.Weight, meta,
		)
		if err != nil {
			return fmt.Errorf("store.SaveSnapshot: insert edge %q: %w", e.ID, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("store.SaveSnapshot: commit: %w", err)
	}
	return nil
}

// loadSnapshotRow reads the base snapshot row and populates scalar fields.
// It does NOT populate nested slices.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - row: a *sql.Row from a query that selected id, label, provider, source_path, created_at.
//
// Returns:
//   - A partially populated *model.Snapshot on success.
//
// Errors:
//   - ErrNotFound if the row contains sql.ErrNoRows.
//   - Any scan or time-parse error.
func loadSnapshotRow(row *sql.Row) (*model.Snapshot, error) {
	var (
		snap      model.Snapshot
		createdAt string
	)
	err := row.Scan(&snap.ID, &snap.Label, &snap.Provider, &snap.SourcePath, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan snapshot row: %w", err)
	}
	t, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		// Fallback to RFC3339 without nanoseconds.
		t, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse snapshot created_at %q: %w", createdAt, err)
		}
	}
	snap.CreatedAt = t.UTC()
	return &snap, nil
}

// populateSnapshot loads all nested entities for snap from the database.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - db: the database to query.
//   - snap: a Snapshot whose ID is set; nested slices will be populated.
//
// Errors:
//   - Any database or unmarshal error encountered during the queries.
func populateSnapshot(ctx context.Context, db *sql.DB, snap *model.Snapshot) error {
	var err error

	snap.Principals, err = loadPrincipals(ctx, db, snap.ID)
	if err != nil {
		return err
	}
	snap.Policies, err = loadPolicies(ctx, db, snap.ID)
	if err != nil {
		return err
	}
	snap.Resources, err = loadResources(ctx, db, snap.ID)
	if err != nil {
		return err
	}
	snap.Edges, err = loadEdges(ctx, db, snap.ID)
	return err
}

// loadPrincipals queries all principals for the given snapshotID.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - db: the database to query.
//   - snapshotID: the snapshot whose principals to load.
//
// Returns:
//   - A slice of *model.Principal; nil on error.
//
// Errors:
//   - Any database or JSON unmarshal error.
func loadPrincipals(ctx context.Context, db *sql.DB, snapshotID string) ([]*model.Principal, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, snapshot_id, kind, arn, name, account_id, raw_props
		   FROM principals WHERE snapshot_id = ?`, snapshotID)
	if err != nil {
		return nil, fmt.Errorf("loadPrincipals: query: %w", err)
	}
	defer rows.Close()

	var principals []*model.Principal
	for rows.Next() {
		var (
			p        model.Principal
			rawProps string
		)
		if err := rows.Scan(&p.ID, &p.SnapshotID, (*string)(&p.Kind), &p.ARN, &p.Name, &p.AccountID, &rawProps); err != nil {
			return nil, fmt.Errorf("loadPrincipals: scan: %w", err)
		}
		if err := unmarshalStringMap(rawProps, &p.RawProps); err != nil {
			return nil, fmt.Errorf("loadPrincipals: unmarshal raw_props: %w", err)
		}
		principals = append(principals, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadPrincipals: rows: %w", err)
	}
	if principals == nil {
		principals = []*model.Principal{}
	}
	return principals, nil
}

// loadPolicies queries all policies (with their permissions) for the given snapshotID.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - db: the database to query.
//   - snapshotID: the snapshot whose policies to load.
//
// Returns:
//   - A slice of *model.Policy with Permissions populated; nil on error.
//
// Errors:
//   - Any database or JSON unmarshal error.
func loadPolicies(ctx context.Context, db *sql.DB, snapshotID string) ([]*model.Policy, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, snapshot_id, arn, name, is_inline, json_raw
		   FROM policies WHERE snapshot_id = ?`, snapshotID)
	if err != nil {
		return nil, fmt.Errorf("loadPolicies: query: %w", err)
	}
	defer rows.Close()

	var policies []*model.Policy
	for rows.Next() {
		var (
			pol      model.Policy
			isInline int
		)
		if err := rows.Scan(&pol.ID, &pol.SnapshotID, &pol.ARN, &pol.Name, &isInline, &pol.JSONRaw); err != nil {
			return nil, fmt.Errorf("loadPolicies: scan: %w", err)
		}
		pol.IsInline = isInline != 0

		perms, err := loadPermissions(ctx, db, pol.ID)
		if err != nil {
			return nil, err
		}
		pol.Permissions = perms
		policies = append(policies, &pol)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadPolicies: rows: %w", err)
	}
	if policies == nil {
		policies = []*model.Policy{}
	}
	return policies, nil
}

// loadPermissions queries all permissions for the given policyID.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - db: the database to query.
//   - policyID: the policy whose permissions to load.
//
// Returns:
//   - A slice of *model.Permission; empty slice (not nil) when none exist.
//
// Errors:
//   - Any database or JSON unmarshal error.
func loadPermissions(ctx context.Context, db *sql.DB, policyID string) ([]*model.Permission, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, policy_id, action, resource_pattern, effect, conditions
		   FROM permissions WHERE policy_id = ?`, policyID)
	if err != nil {
		return nil, fmt.Errorf("loadPermissions: query: %w", err)
	}
	defer rows.Close()

	var perms []*model.Permission
	for rows.Next() {
		var (
			perm  model.Permission
			conds string
		)
		if err := rows.Scan(&perm.ID, &perm.PolicyID, &perm.Action, &perm.ResourcePattern, &perm.Effect, &conds); err != nil {
			return nil, fmt.Errorf("loadPermissions: scan: %w", err)
		}
		if err := unmarshalStringMap(conds, &perm.Conditions); err != nil {
			return nil, fmt.Errorf("loadPermissions: unmarshal conditions: %w", err)
		}
		perms = append(perms, &perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadPermissions: rows: %w", err)
	}
	if perms == nil {
		perms = []*model.Permission{}
	}
	return perms, nil
}

// loadResources queries all resources for the given snapshotID.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - db: the database to query.
//   - snapshotID: the snapshot whose resources to load.
//
// Returns:
//   - A slice of *model.Resource; empty slice (not nil) when none exist.
//
// Errors:
//   - Any database error.
func loadResources(ctx context.Context, db *sql.DB, snapshotID string) ([]*model.Resource, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, snapshot_id, arn, kind, is_sensitive
		   FROM resources WHERE snapshot_id = ?`, snapshotID)
	if err != nil {
		return nil, fmt.Errorf("loadResources: query: %w", err)
	}
	defer rows.Close()

	var resources []*model.Resource
	for rows.Next() {
		var (
			r           model.Resource
			isSensitive int
		)
		if err := rows.Scan(&r.ID, &r.SnapshotID, &r.ARN, &r.Kind, &isSensitive); err != nil {
			return nil, fmt.Errorf("loadResources: scan: %w", err)
		}
		r.IsSensitive = isSensitive != 0
		resources = append(resources, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadResources: rows: %w", err)
	}
	if resources == nil {
		resources = []*model.Resource{}
	}
	return resources, nil
}

// loadEdges queries all edges for the given snapshotID.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - db: the database to query.
//   - snapshotID: the snapshot whose edges to load.
//
// Returns:
//   - A slice of *model.Edge; empty slice (not nil) when none exist.
//
// Errors:
//   - Any database or JSON unmarshal error.
func loadEdges(ctx context.Context, db *sql.DB, snapshotID string) ([]*model.Edge, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, snapshot_id, from_node_id, to_node_id, kind, weight, metadata
		   FROM edges WHERE snapshot_id = ?`, snapshotID)
	if err != nil {
		return nil, fmt.Errorf("loadEdges: query: %w", err)
	}
	defer rows.Close()

	var edges []*model.Edge
	for rows.Next() {
		var (
			e    model.Edge
			meta string
		)
		if err := rows.Scan(&e.ID, &e.SnapshotID, &e.FromNodeID, &e.ToNodeID, (*string)(&e.Kind), &e.Weight, &meta); err != nil {
			return nil, fmt.Errorf("loadEdges: scan: %w", err)
		}
		if err := unmarshalStringMap(meta, &e.Metadata); err != nil {
			return nil, fmt.Errorf("loadEdges: unmarshal metadata: %w", err)
		}
		edges = append(edges, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadEdges: rows: %w", err)
	}
	if edges == nil {
		edges = []*model.Edge{}
	}
	return edges, nil
}

// LoadSnapshot retrieves a fully populated Snapshot by its unique ID.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - id: the snapshot ID to retrieve; must be non-empty.
//
// Returns:
//   - A fully populated *model.Snapshot on success.
//
// Errors:
//   - ErrInvalidInput if id is empty.
//   - ErrNotFound if no snapshot with the given ID exists.
//   - Any database error encountered during loading.
func (s *Store) LoadSnapshot(ctx context.Context, id string) (*model.Snapshot, error) {
	if id == "" {
		return nil, fmt.Errorf("store.LoadSnapshot: %w", ErrInvalidInput)
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT id, label, provider, source_path, created_at FROM snapshots WHERE id = ?`, id)
	snap, err := loadSnapshotRow(row)
	if err != nil {
		return nil, fmt.Errorf("store.LoadSnapshot: %w", err)
	}

	if err := populateSnapshot(ctx, s.db, snap); err != nil {
		return nil, fmt.Errorf("store.LoadSnapshot: populate: %w", err)
	}
	return snap, nil
}

// LoadSnapshotByLabel retrieves a fully populated Snapshot by its human-readable label.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - label: the snapshot label to retrieve; must be non-empty.
//
// Returns:
//   - A fully populated *model.Snapshot on success.
//
// Errors:
//   - ErrInvalidInput if label is empty.
//   - ErrNotFound if no snapshot with the given label exists.
//   - Any database error encountered during loading.
func (s *Store) LoadSnapshotByLabel(ctx context.Context, label string) (*model.Snapshot, error) {
	if label == "" {
		return nil, fmt.Errorf("store.LoadSnapshotByLabel: %w", ErrInvalidInput)
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT id, label, provider, source_path, created_at FROM snapshots WHERE label = ? ORDER BY created_at DESC LIMIT 1`, label)
	snap, err := loadSnapshotRow(row)
	if err != nil {
		return nil, fmt.Errorf("store.LoadSnapshotByLabel: %w", err)
	}

	if err := populateSnapshot(ctx, s.db, snap); err != nil {
		return nil, fmt.Errorf("store.LoadSnapshotByLabel: populate: %w", err)
	}
	return snap, nil
}

// ListSnapshots returns all stored snapshots, ordered by creation time descending,
// with all nested fields populated.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//
// Returns:
//   - A slice of fully populated *model.Snapshot; empty slice (not nil) when none exist.
//
// Errors:
//   - Any database error encountered during loading.
func (s *Store) ListSnapshots(ctx context.Context) ([]*model.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, label, provider, source_path, created_at
		   FROM snapshots ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store.ListSnapshots: query: %w", err)
	}
	defer rows.Close()

	var snapshots []*model.Snapshot
	for rows.Next() {
		var (
			snap      model.Snapshot
			createdAt string
		)
		if err := rows.Scan(&snap.ID, &snap.Label, &snap.Provider, &snap.SourcePath, &createdAt); err != nil {
			return nil, fmt.Errorf("store.ListSnapshots: scan: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			t, err = time.Parse(time.RFC3339, createdAt)
			if err != nil {
				return nil, fmt.Errorf("store.ListSnapshots: parse created_at %q: %w", createdAt, err)
			}
		}
		snap.CreatedAt = t.UTC()
		snapshots = append(snapshots, &snap)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListSnapshots: rows: %w", err)
	}

	for _, snap := range snapshots {
		if err := populateSnapshot(ctx, s.db, snap); err != nil {
			return nil, fmt.Errorf("store.ListSnapshots: populate snapshot %q: %w", snap.ID, err)
		}
	}

	if snapshots == nil {
		snapshots = []*model.Snapshot{}
	}
	return snapshots, nil
}

// SaveFindings persists a batch of Finding records using INSERT OR REPLACE.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - findings: the batch to save; must be non-nil; each element must have a non-empty ID.
//
// Errors:
//   - ErrInvalidInput if findings is nil or any element has an empty ID.
//   - Any database error encountered during the batch insert.
func (s *Store) SaveFindings(ctx context.Context, findings []*model.Finding) error {
	if findings == nil {
		return fmt.Errorf("store.SaveFindings: %w", ErrInvalidInput)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.SaveFindings: begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	for _, f := range findings {
		if f == nil || f.ID == "" {
			err = ErrInvalidInput
			return fmt.Errorf("store.SaveFindings: %w", ErrInvalidInput)
		}
		_, err = tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO findings
			   (id, snapshot_id, rule_id, severity, entity_ref, reason, remediation)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			f.ID, f.SnapshotID, f.RuleID, string(f.Severity), f.EntityRef, f.Reason, f.Remediation,
		)
		if err != nil {
			return fmt.Errorf("store.SaveFindings: insert finding %q: %w", f.ID, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("store.SaveFindings: commit: %w", err)
	}
	return nil
}

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
//   - Any database error.
func (s *Store) LoadFindings(ctx context.Context, snapshotID string) ([]*model.Finding, error) {
	if snapshotID == "" {
		return nil, fmt.Errorf("store.LoadFindings: %w", ErrInvalidInput)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, snapshot_id, rule_id, severity, entity_ref, reason, remediation
		   FROM findings WHERE snapshot_id = ?`, snapshotID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadFindings: query: %w", err)
	}
	defer rows.Close()

	var findings []*model.Finding
	for rows.Next() {
		var f model.Finding
		if err := rows.Scan(&f.ID, &f.SnapshotID, &f.RuleID, (*string)(&f.Severity),
			&f.EntityRef, &f.Reason, &f.Remediation); err != nil {
			return nil, fmt.Errorf("store.LoadFindings: scan: %w", err)
		}
		findings = append(findings, &f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadFindings: rows: %w", err)
	}
	if findings == nil {
		findings = []*model.Finding{}
	}
	return findings, nil
}

// SaveAttackPaths persists a batch of AttackPath records using INSERT OR REPLACE.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - paths: the batch to save; must be non-nil; each element must have a non-empty ID.
//
// Errors:
//   - ErrInvalidInput if paths is nil or any element has an empty ID.
//   - Any database error encountered during the batch insert.
func (s *Store) SaveAttackPaths(ctx context.Context, paths []*model.AttackPath) error {
	if paths == nil {
		return fmt.Errorf("store.SaveAttackPaths: %w", ErrInvalidInput)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.SaveAttackPaths: begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	for _, ap := range paths {
		if ap == nil || ap.ID == "" {
			err = ErrInvalidInput
			return fmt.Errorf("store.SaveAttackPaths: %w", ErrInvalidInput)
		}
		pathNodes, merr := marshalStringSlice(ap.PathNodes)
		if merr != nil {
			err = merr
			return fmt.Errorf("store.SaveAttackPaths: marshal path_nodes: %w", err)
		}
		pathEdges, merr := marshalStringSlice(ap.PathEdges)
		if merr != nil {
			err = merr
			return fmt.Errorf("store.SaveAttackPaths: marshal path_edges: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO attack_paths
			   (id, snapshot_id, from_principal_id, to_resource_id, hop_count,
			    path_nodes, path_edges, is_privilege_escalation)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			ap.ID, ap.SnapshotID, ap.FromPrincipalID, ap.ToResourceID, ap.HopCount,
			pathNodes, pathEdges, boolToInt(ap.IsPrivilegeEscalation),
		)
		if err != nil {
			return fmt.Errorf("store.SaveAttackPaths: insert path %q: %w", ap.ID, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("store.SaveAttackPaths: commit: %w", err)
	}
	return nil
}

// LoadAttackPaths retrieves all attack paths for the given snapshot ID.
//
// Paths that reference principal or resource IDs that no longer exist in the
// snapshot are silently skipped; a warning is emitted via slog.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - snapshotID: the snapshot to query; must be non-empty.
//
// Returns:
//   - A slice of *model.AttackPath; empty slice (not nil) when none exist.
//
// Errors:
//   - ErrInvalidInput if snapshotID is empty.
//   - Any database error.
func (s *Store) LoadAttackPaths(ctx context.Context, snapshotID string) ([]*model.AttackPath, error) {
	if snapshotID == "" {
		return nil, fmt.Errorf("store.LoadAttackPaths: %w", ErrInvalidInput)
	}

	// Build sets of known principal IDs and resource IDs for this snapshot so we
	// can skip orphaned paths without returning an error.
	principalIDs, err := loadIDSet(ctx, s.db, "principals", snapshotID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadAttackPaths: load principal ids: %w", err)
	}
	resourceIDs, err := loadIDSet(ctx, s.db, "resources", snapshotID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadAttackPaths: load resource ids: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, snapshot_id, from_principal_id, to_resource_id, hop_count,
		        path_nodes, path_edges, is_privilege_escalation
		   FROM attack_paths WHERE snapshot_id = ?`, snapshotID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadAttackPaths: query: %w", err)
	}
	defer rows.Close()

	var paths []*model.AttackPath
	for rows.Next() {
		var (
			ap            model.AttackPath
			pathNodesJSON string
			pathEdgesJSON string
			isPrivEsc     int
		)
		if err := rows.Scan(
			&ap.ID, &ap.SnapshotID, &ap.FromPrincipalID, &ap.ToResourceID, &ap.HopCount,
			&pathNodesJSON, &pathEdgesJSON, &isPrivEsc,
		); err != nil {
			return nil, fmt.Errorf("store.LoadAttackPaths: scan: %w", err)
		}

		// Skip paths that reference entities no longer present in the snapshot.
		if !principalIDs[ap.FromPrincipalID] {
			slog.WarnContext(ctx, "store.LoadAttackPaths: skipping path with missing from_principal_id",
				slog.String("path_id", ap.ID),
				slog.String("from_principal_id", ap.FromPrincipalID),
			)
			continue
		}
		if !resourceIDs[ap.ToResourceID] {
			slog.WarnContext(ctx, "store.LoadAttackPaths: skipping path with missing to_resource_id",
				slog.String("path_id", ap.ID),
				slog.String("to_resource_id", ap.ToResourceID),
			)
			continue
		}

		if err := unmarshalStringSlice(pathNodesJSON, &ap.PathNodes); err != nil {
			return nil, fmt.Errorf("store.LoadAttackPaths: unmarshal path_nodes for %q: %w", ap.ID, err)
		}
		if err := unmarshalStringSlice(pathEdgesJSON, &ap.PathEdges); err != nil {
			return nil, fmt.Errorf("store.LoadAttackPaths: unmarshal path_edges for %q: %w", ap.ID, err)
		}
		ap.IsPrivilegeEscalation = isPrivEsc != 0

		paths = append(paths, &ap)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadAttackPaths: rows: %w", err)
	}
	if paths == nil {
		paths = []*model.AttackPath{}
	}
	return paths, nil
}

// loadIDSet returns a set (map[string]bool) of all IDs in the given table for snapshotID.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - db: the database to query.
//   - table: the table name; must be a trusted constant (not user input).
//   - snapshotID: the snapshot to filter by.
//
// Returns:
//   - A non-nil map whose keys are the IDs present in the table.
//
// Errors:
//   - Any database error.
func loadIDSet(ctx context.Context, db *sql.DB, table, snapshotID string) (map[string]bool, error) {
	var query string
	switch table {
	case "principals":
		query = "SELECT id FROM principals WHERE snapshot_id = ?"
	case "resources":
		query = "SELECT id FROM resources WHERE snapshot_id = ?"
	case "policies":
		query = "SELECT id FROM policies WHERE snapshot_id = ?"
	case "edges":
		query = "SELECT id FROM edges WHERE snapshot_id = ?"
	default:
		return nil, fmt.Errorf("loadIDSet: unknown table %q", table)
	}
	rows, err := db.QueryContext(ctx, query, snapshotID)
	if err != nil {
		return nil, fmt.Errorf("loadIDSet(%s): %w", table, err)
	}
	defer rows.Close()

	set := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("loadIDSet(%s): scan: %w", table, err)
		}
		set[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadIDSet(%s): rows: %w", table, err)
	}
	return set, nil
}

// SaveBenchmarkResult persists a single BenchmarkResult using INSERT OR REPLACE.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - r: the result to save; must be non-nil with a non-empty ID and ScenarioID.
//
// Errors:
//   - ErrInvalidInput if r is nil, r.ID is empty, or r.ScenarioID is empty.
//   - Any database error.
func (s *Store) SaveBenchmarkResult(ctx context.Context, r *model.BenchmarkResult) error {
	if r == nil || r.ID == "" || r.ScenarioID == "" {
		return fmt.Errorf("store.SaveBenchmarkResult: %w", ErrInvalidInput)
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO benchmark_results
		   (id, run_id, result_id, scenario_id, tool_name,
		    detection_label, timeout_kind, classification_override, is_true_negative,
		    detection_latency_ms, chain_length_class, category, run_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.RunID, r.ResultID, r.ScenarioID, string(r.ToolName),
		string(r.DetectionLabel), string(r.TimeoutKind), string(r.ClassificationOverride),
		boolToInt(r.IsTrueNegative),
		r.DetectionLatencyMs, string(r.ChainLengthClass), string(r.Category),
		r.RunAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("store.SaveBenchmarkResult: insert: %w", err)
	}
	return nil
}

// LoadBenchmarkResults retrieves all benchmark results for the given scenario ID.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - scenarioID: the scenario to query; must be non-empty.
//
// Returns:
//   - A slice of *model.BenchmarkResult; empty slice (not nil) when none exist.
//
// Errors:
//   - ErrInvalidInput if scenarioID is empty.
//   - Any database error.
func (s *Store) LoadBenchmarkResults(ctx context.Context, runID string) ([]*model.BenchmarkResult, error) {
	if runID == "" {
		return nil, fmt.Errorf("store.LoadBenchmarkResults: %w", ErrInvalidInput)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, run_id, result_id, scenario_id, tool_name,
		        detection_label, timeout_kind, classification_override, is_true_negative,
		        detection_latency_ms, chain_length_class, category, run_at
		   FROM benchmark_results WHERE run_id = ?`, runID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadBenchmarkResults: query: %w", err)
	}
	defer rows.Close()

	var results []*model.BenchmarkResult
	for rows.Next() {
		var (
			r     model.BenchmarkResult
			isTN  int
			runAt string
		)
		if err := rows.Scan(
			&r.ID, &r.RunID, &r.ResultID, &r.ScenarioID, (*string)(&r.ToolName),
			(*string)(&r.DetectionLabel), (*string)(&r.TimeoutKind), (*string)(&r.ClassificationOverride),
			&isTN,
			&r.DetectionLatencyMs, (*string)(&r.ChainLengthClass), (*string)(&r.Category), &runAt,
		); err != nil {
			return nil, fmt.Errorf("store.LoadBenchmarkResults: scan: %w", err)
		}
		r.IsTrueNegative = isTN != 0

		t, err := time.Parse(time.RFC3339Nano, runAt)
		if err != nil {
			t, err = time.Parse(time.RFC3339, runAt)
			if err != nil {
				return nil, fmt.Errorf("store.LoadBenchmarkResults: parse run_at %q: %w", runAt, err)
			}
		}
		r.RunAt = t.UTC()

		results = append(results, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadBenchmarkResults: rows: %w", err)
	}
	if results == nil {
		results = []*model.BenchmarkResult{}
	}
	return results, nil
}

// SaveScenario persists a Scenario using INSERT OR REPLACE.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - s: the scenario to save; must be non-nil with a non-empty ID.
//
// Errors:
//   - ErrInvalidInput if s is nil or s.ID is empty.
//   - Any database error.
func (s *Store) SaveScenario(ctx context.Context, sc *model.Scenario) error {
	if sc == nil || sc.ID == "" {
		return fmt.Errorf("store.SaveScenario: %w", ErrInvalidInput)
	}

	expectedPath, err := marshalStringSlice(sc.ExpectedAttackPath)
	if err != nil {
		return fmt.Errorf("store.SaveScenario: marshal expected_attack_path: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO scenarios
		   (id, name, source, chain_length_class, expected_attack_path, description, category)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sc.ID, sc.Name, sc.Source, string(sc.ChainLength), expectedPath, sc.Description, string(sc.Category),
	)
	if err != nil {
		return fmt.Errorf("store.SaveScenario: insert: %w", err)
	}
	return nil
}

// LoadScenario retrieves a Scenario by its unique ID.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//   - id: the scenario ID to retrieve; must be non-empty.
//
// Returns:
//   - A *model.Scenario on success.
//
// Errors:
//   - ErrInvalidInput if id is empty.
//   - ErrNotFound if no scenario with the given ID exists.
//   - Any database error.
func (s *Store) LoadScenario(ctx context.Context, id string) (*model.Scenario, error) {
	if id == "" {
		return nil, fmt.Errorf("store.LoadScenario: %w", ErrInvalidInput)
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, source, chain_length_class, expected_attack_path, description, category
		   FROM scenarios WHERE id = ?`, id)

	var (
		sc           model.Scenario
		expectedPath string
	)
	if err := row.Scan(&sc.ID, &sc.Name, &sc.Source, (*string)(&sc.ChainLength), &expectedPath, &sc.Description, (*string)(&sc.Category)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("store.LoadScenario: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("store.LoadScenario: scan: %w", err)
	}
	if err := unmarshalStringSlice(expectedPath, &sc.ExpectedAttackPath); err != nil {
		return nil, fmt.Errorf("store.LoadScenario: unmarshal expected_attack_path: %w", err)
	}
	return &sc, nil
}

// ListScenarios returns all stored scenarios.
//
// Parameters:
//   - ctx: context for cancellation/deadline propagation.
//
// Returns:
//   - A slice of *model.Scenario; empty slice (not nil) when none exist.
//
// Errors:
//   - Any database error.
func (s *Store) ListScenarios(ctx context.Context) ([]*model.Scenario, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, source, chain_length_class, expected_attack_path, description, category
		   FROM scenarios ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store.ListScenarios: query: %w", err)
	}
	defer rows.Close()

	var scenarios []*model.Scenario
	for rows.Next() {
		var (
			sc           model.Scenario
			expectedPath string
		)
		if err := rows.Scan(&sc.ID, &sc.Name, &sc.Source, (*string)(&sc.ChainLength), &expectedPath, &sc.Description, (*string)(&sc.Category)); err != nil {
			return nil, fmt.Errorf("store.ListScenarios: scan: %w", err)
		}
		if err := unmarshalStringSlice(expectedPath, &sc.ExpectedAttackPath); err != nil {
			return nil, fmt.Errorf("store.ListScenarios: unmarshal expected_attack_path for %q: %w", sc.ID, err)
		}
		scenarios = append(scenarios, &sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListScenarios: rows: %w", err)
	}
	if scenarios == nil {
		scenarios = []*model.Scenario{}
	}
	return scenarios, nil
}

// SaveClassMetrics persists per-class recall for one (tool, class) pair.
func (s *Store) SaveClassMetrics(ctx context.Context, runID string, tool model.ToolName, class model.ChainLengthClass, m *model.ClassMetrics) error {
	if runID == "" || m == nil {
		return fmt.Errorf("store.SaveClassMetrics: %w", ErrInvalidInput)
	}
	id := "cm-" + uuid.NewString()
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO class_metrics
           (id, run_id, tool_name, chain_length_class, tp, fn, timeouts,
            recall_val, recall_low, recall_high)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, runID, string(tool), string(class),
		m.TP, m.FN, m.Timeouts,
		float64(m.Recall),
		float64(m.RecallLow), float64(m.RecallHigh),
	)
	if err != nil {
		return fmt.Errorf("store.SaveClassMetrics: insert: %w", err)
	}
	return nil
}

// LoadClassMetrics returns all class metrics for the given run ID.
func (s *Store) LoadClassMetrics(ctx context.Context, runID string) (map[model.ToolName]map[model.ChainLengthClass]*model.ClassMetrics, error) {
	if runID == "" {
		return nil, fmt.Errorf("store.LoadClassMetrics: %w", ErrInvalidInput)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT tool_name, chain_length_class, tp, fn, timeouts,
                recall_val, recall_low, recall_high
           FROM class_metrics WHERE run_id = ?`, runID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadClassMetrics: query: %w", err)
	}
	defer rows.Close()
	result := make(map[model.ToolName]map[model.ChainLengthClass]*model.ClassMetrics)
	for rows.Next() {
		var (
			toolName  string
			class     string
			m         model.ClassMetrics
			r, rl, rh float64
		)
		if err := rows.Scan(&toolName, &class, &m.TP, &m.FN, &m.Timeouts,
			&r, &rl, &rh); err != nil {
			return nil, fmt.Errorf("store.LoadClassMetrics: scan: %w", err)
		}
		m.Recall = model.MetricFloat(r)
		m.RecallLow = model.MetricFloat(rl)
		m.RecallHigh = model.MetricFloat(rh)
		tn := model.ToolName(toolName)
		cl := model.ChainLengthClass(class)
		if result[tn] == nil {
			result[tn] = make(map[model.ChainLengthClass]*model.ClassMetrics)
		}
		mc := m
		result[tn][cl] = &mc
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadClassMetrics: rows: %w", err)
	}
	return result, nil
}

// SaveToolMetrics persists tool-level aggregated precision/recall/F1.
func (s *Store) SaveToolMetrics(ctx context.Context, runID string, tool model.ToolName, m *model.ToolMetrics) error {
	if m == nil || runID == "" || tool == "" {
		return fmt.Errorf("store.SaveToolMetrics: %w", ErrInvalidInput)
	}
	id := "tm-" + uuid.NewString()
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO tool_metrics
           (id, run_id, tool_name, tp, fn, timeouts,
            precision_val, recall_val, f1_val, precision_low, precision_high, recall_low, recall_high)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, runID, string(tool),
		m.TP, m.FN, m.Timeouts,
		float64(m.Precision), float64(m.Recall), float64(m.F1),
		float64(m.PrecisionLow), float64(m.PrecisionHigh),
		float64(m.RecallLow), float64(m.RecallHigh),
	)
	if err != nil {
		return fmt.Errorf("store.SaveToolMetrics: insert: %w", err)
	}
	return nil
}

// LoadToolMetrics returns all tool metrics for the given run ID.
func (s *Store) LoadToolMetrics(ctx context.Context, runID string) (map[model.ToolName]*model.ToolMetrics, error) {
	if runID == "" {
		return nil, fmt.Errorf("store.LoadToolMetrics: %w", ErrInvalidInput)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT tool_name, tp, fn, timeouts,
                precision_val, recall_val, f1_val, precision_low, precision_high, recall_low, recall_high
           FROM tool_metrics WHERE run_id = ?`, runID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadToolMetrics: query: %w", err)
	}
	defer rows.Close()
	result := make(map[model.ToolName]*model.ToolMetrics)
	for rows.Next() {
		var (
			toolName                string
			m                       model.ToolMetrics
			p, r, f, pl, ph, rl, rh float64
		)
		if err := rows.Scan(&toolName, &m.TP, &m.FN, &m.Timeouts,
			&p, &r, &f, &pl, &ph, &rl, &rh); err != nil {
			return nil, fmt.Errorf("store.LoadToolMetrics: scan: %w", err)
		}
		m.Precision = model.MetricFloat(p)
		m.Recall = model.MetricFloat(r)
		m.F1 = model.MetricFloat(f)
		m.PrecisionLow = model.MetricFloat(pl)
		m.PrecisionHigh = model.MetricFloat(ph)
		m.RecallLow = model.MetricFloat(rl)
		m.RecallHigh = model.MetricFloat(rh)
		mc := m
		result[model.ToolName(toolName)] = &mc
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadToolMetrics: rows: %w", err)
	}
	return result, nil
}

// SaveFalsePositiveRate persists FPR computed from TN environments.
func (s *Store) SaveFalsePositiveRate(ctx context.Context, runID string, tool model.ToolName, fpr *model.FalsePositiveRate) error {
	if fpr == nil || runID == "" || tool == "" {
		return fmt.Errorf("store.SaveFalsePositiveRate: %w", ErrInvalidInput)
	}
	id := "fpr-" + uuid.NewString()
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO false_positive_rates (id, run_id, tool_name, fpr, fpr_low, fpr_high)
         VALUES (?, ?, ?, ?, ?, ?)`,
		id, runID, string(tool),
		float64(fpr.FPR), float64(fpr.FPRLow), float64(fpr.FPRHigh),
	)
	if err != nil {
		return fmt.Errorf("store.SaveFalsePositiveRate: insert: %w", err)
	}
	return nil
}

// LoadFalsePositiveRates returns all FPR entries for the given run ID.
func (s *Store) LoadFalsePositiveRates(ctx context.Context, runID string) (map[model.ToolName]*model.FalsePositiveRate, error) {
	if runID == "" {
		return nil, fmt.Errorf("store.LoadFalsePositiveRates: %w", ErrInvalidInput)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT tool_name, fpr, fpr_low, fpr_high FROM false_positive_rates WHERE run_id = ?`, runID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadFalsePositiveRates: query: %w", err)
	}
	defer rows.Close()
	result := make(map[model.ToolName]*model.FalsePositiveRate)
	for rows.Next() {
		var (
			toolName    string
			fpr, fl, fh float64
		)
		if err := rows.Scan(&toolName, &fpr, &fl, &fh); err != nil {
			return nil, fmt.Errorf("store.LoadFalsePositiveRates: scan: %w", err)
		}
		result[model.ToolName(toolName)] = &model.FalsePositiveRate{
			FPR:     model.MetricFloat(fpr),
			FPRLow:  model.MetricFloat(fl),
			FPRHigh: model.MetricFloat(fh),
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadFalsePositiveRates: rows: %w", err)
	}
	return result, nil
}

// marshalStringMap serializes a map[string]string to a compact JSON string.
// A nil map is serialized as "{}".
//
// Parameters:
//   - m: the map to serialize.
//
// Returns:
//   - The JSON string representation.
//
// Errors:
//   - Any JSON marshal error.
func marshalStringMap(m map[string]string) (string, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// unmarshalStringMap deserializes a JSON string into a map[string]string.
// An empty string or "{}" produces an empty (non-nil) map.
//
// Parameters:
//   - s: the JSON string to parse.
//   - dst: pointer to the destination map; must not be nil.
//
// Errors:
//   - Any JSON unmarshal error.
func unmarshalStringMap(s string, dst *map[string]string) error {
	if s == "" || s == "{}" {
		*dst = map[string]string{}
		return nil
	}
	return json.Unmarshal([]byte(s), dst)
}

// marshalStringSlice serializes a []string to a compact JSON array string.
// A nil slice is serialized as "[]".
//
// Parameters:
//   - sl: the slice to serialize.
//
// Returns:
//   - The JSON array string representation.
//
// Errors:
//   - Any JSON marshal error.
func marshalStringSlice(sl []string) (string, error) {
	if sl == nil {
		return "[]", nil
	}
	b, err := json.Marshal(sl)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// unmarshalStringSlice deserializes a JSON array string into a []string.
// An empty string or "[]" produces an empty (non-nil) slice.
//
// Parameters:
//   - s: the JSON string to parse.
//   - dst: pointer to the destination slice; must not be nil.
//
// Errors:
//   - Any JSON unmarshal error.
func unmarshalStringSlice(s string, dst *[]string) error {
	if s == "" || s == "[]" {
		*dst = []string{}
		return nil
	}
	return json.Unmarshal([]byte(s), dst)
}

// boolToInt converts a bool to SQLite's integer representation (0 or 1).
//
// Parameters:
//   - b: the boolean value.
//
// Returns:
//   - 1 if b is true, 0 otherwise.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
