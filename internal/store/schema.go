// Package store provides persistence abstractions for AccessGraph domain entities.
//
// The store package defines the DataStore interface and its two implementations:
// a SQLite-backed Store for production use and an in-memory MemStore for tests.
// All reads and writes accept a context.Context so callers can apply deadlines
// and cancellation.
//
// Dependency rule: this package imports only internal/model. This package must
// not import internal/graph, internal/analyzer, internal/policy, internal/benchmark,
// internal/report, or any cmd package.
package store

// schemaSQL is the complete DDL for the AccessGraph SQLite database.
//
// Every table uses IF NOT EXISTS so that schema initialization is idempotent
// and safe to call on an existing database. Foreign-key columns are declared
// but SQLite FK enforcement is enabled separately via PRAGMA at connection
// open time.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS snapshots (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    provider TEXT NOT NULL,
    source_path TEXT NOT NULL,
    created_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS principals (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
    kind TEXT NOT NULL,
    arn TEXT NOT NULL,
    name TEXT NOT NULL,
    account_id TEXT NOT NULL,
    raw_props TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
    arn TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    is_inline INTEGER NOT NULL DEFAULT 0,
    json_raw TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL REFERENCES policies(id),
    action TEXT NOT NULL,
    resource_pattern TEXT NOT NULL,
    effect TEXT NOT NULL,
    conditions TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS resources (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
    arn TEXT NOT NULL,
    kind TEXT NOT NULL,
    is_sensitive INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS edges (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
    from_node_id TEXT NOT NULL,
    to_node_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    entity_ref TEXT NOT NULL,
    reason TEXT NOT NULL,
    remediation TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attack_paths (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
    from_principal_id TEXT NOT NULL,
    to_resource_id TEXT NOT NULL,
    hop_count INTEGER NOT NULL,
    path_nodes TEXT NOT NULL DEFAULT '[]',
    path_edges TEXT NOT NULL DEFAULT '[]',
    is_privilege_escalation INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scenarios (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    chain_length_class TEXT NOT NULL,
    expected_attack_path TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS benchmark_results (
    id                      TEXT    NOT NULL PRIMARY KEY,
    run_id                  TEXT    NOT NULL DEFAULT '',
    result_id               TEXT    NOT NULL DEFAULT '',
    scenario_id             TEXT    NOT NULL REFERENCES scenarios(id),
    tool_name               TEXT    NOT NULL,
    detection_label         TEXT    NOT NULL DEFAULT '',
    timeout_kind            TEXT    NOT NULL DEFAULT 'none',
    classification_override TEXT    NOT NULL DEFAULT '',
    is_true_negative        INTEGER NOT NULL DEFAULT 0,
    detection_latency_ms    INTEGER NOT NULL DEFAULT 0,
    chain_length_class      TEXT    NOT NULL,
    category                TEXT    NOT NULL DEFAULT '',
    run_at                  DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS class_metrics (
    id                  TEXT NOT NULL PRIMARY KEY,
    run_id              TEXT NOT NULL,
    tool_name           TEXT NOT NULL,
    chain_length_class  TEXT NOT NULL,
    tp                  INTEGER NOT NULL DEFAULT 0,
    fn                  INTEGER NOT NULL DEFAULT 0,
    timeouts            INTEGER NOT NULL DEFAULT 0,
    recall_val          REAL NOT NULL DEFAULT 0.0,
    recall_low          REAL NOT NULL DEFAULT 0.0,
    recall_high         REAL NOT NULL DEFAULT 0.0
);
CREATE TABLE IF NOT EXISTS tool_metrics (
    id              TEXT NOT NULL PRIMARY KEY,
    run_id          TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    tp              INTEGER NOT NULL DEFAULT 0,
    fn              INTEGER NOT NULL DEFAULT 0,
    timeouts        INTEGER NOT NULL DEFAULT 0,
    precision_val   REAL NOT NULL DEFAULT 0.0,
    recall_val      REAL NOT NULL DEFAULT 0.0,
    f1_val          REAL NOT NULL DEFAULT 0.0,
    precision_low   REAL NOT NULL DEFAULT 0.0,
    precision_high  REAL NOT NULL DEFAULT 0.0,
    recall_low      REAL NOT NULL DEFAULT 0.0,
    recall_high     REAL NOT NULL DEFAULT 0.0
);
CREATE TABLE IF NOT EXISTS false_positive_rates (
    id        TEXT NOT NULL PRIMARY KEY,
    run_id    TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    fpr       REAL NOT NULL DEFAULT 0.0,
    fpr_low   REAL NOT NULL DEFAULT 0.0,
    fpr_high  REAL NOT NULL DEFAULT 0.0
);
`
