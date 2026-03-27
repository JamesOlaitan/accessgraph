package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ComputeFindingID returns the deterministic content hash for a Finding.
// The ID is sha256(json.Marshal([]any{snapshotID, ruleID, entityRef})) truncated
// to 32 hex characters, matching the specification in findings_schema.md.
func ComputeFindingID(snapshotID, ruleID, entityRef string) string {
	key, _ := json.Marshal([]any{snapshotID, ruleID, entityRef})
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:16])
}

// Severity classifies the risk level of a policy finding produced by OPA evaluation.
type Severity string

const (
	// SeverityLow indicates a minor policy violation with limited individual blast radius.
	SeverityLow Severity = "LOW"

	// SeverityMedium indicates a notable policy violation that may be leveraged in a chain.
	SeverityMedium Severity = "MEDIUM"

	// SeverityHigh indicates a policy violation that likely enables privilege escalation.
	SeverityHigh Severity = "HIGH"

	// SeverityCritical indicates a policy violation that directly grants or enables admin access.
	SeverityCritical Severity = "CRITICAL"
)

// Finding represents a policy violation surfaced by an OPA rule evaluation.
//
// Findings are produced by the FindingEvaluator and stored per snapshot. Each
// finding references exactly one entity in violation and carries enough context
// for a human reader to understand and remediate the issue without consulting
// the raw policy JSON.
//
// Fields:
//   - ID: unique identifier within the snapshot.
//   - SnapshotID: the snapshot this finding belongs to.
//   - RuleID: the OPA rule that generated this finding (e.g., "IAM.WildcardAction").
//   - Severity: the risk classification (see Severity constants).
//   - EntityRef: the ARN or ID of the entity in violation.
//   - Reason: human-readable explanation of why this is a violation.
//   - Remediation: suggested corrective action.
type Finding struct {
	ID          string   `json:"finding_id"`
	SnapshotID  string   `json:"-"`
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"severity"`
	EntityRef   string   `json:"entity_ref"`
	Reason      string   `json:"reason"`
	Remediation string   `json:"remediation"`
}
