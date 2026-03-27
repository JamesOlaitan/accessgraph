package analyzer

import (
	"fmt"
	"strings"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// ClassifySensitiveResources applies hardcoded heuristics to mark Resource
// nodes in the snapshot as IsSensitive = true before graph traversal begins.
//
// This pre-classification is complementary to the OPA rules in
// internal/policy: the heuristics here ensure that the BFS traversal
// performed by BlastRadiusAnalyzer.Analyze has accurate IsSensitive flags on
// Resource nodes without requiring an OPA evaluation round-trip. The OPA rules
// independently produce human-readable Finding records; both mechanisms can
// flag the same resource.
//
// A Resource is marked IsSensitive = true when ANY of the following is true:
//
//  1. Its ARN contains ":role/" and its Kind is "IAMRole" AND the name
//     component (after the last "/" or ":") exactly matches "admin",
//     "administrator", or contains "administratoraccess" (case-insensitive).
//  2. Its ARN contains "iam::aws:policy/AdministratorAccess" or the name
//     component exactly matches "AdministratorAccess" (case-insensitive).
//  3. Its ARN contains ":secret:" (AWS Secrets Manager secrets).
//  4. Its ARN contains ":key/" and its Kind is "KMSKey".
//
// Parameters:
//   - snapshot: the point-in-time snapshot whose Resources are to be classified;
//     must not be nil.
//
// Returns:
//   - nil on success.
//   - ErrInvalidInput if snapshot is nil.
func ClassifySensitiveResources(snapshot *model.Snapshot) error {
	if snapshot == nil {
		return fmt.Errorf("ClassifySensitiveResources: %w: snapshot must not be nil", ErrInvalidInput)
	}

	for _, r := range snapshot.Resources {
		if r == nil {
			continue
		}
		if isSensitiveResource(r) {
			r.IsSensitive = true
		}
	}

	return nil
}

// arnName extracts the name component from an ARN — everything after the last
// "/" or ":" in the resource portion. For an ARN like
// "arn:aws:iam::123:role/DevRole" it returns "DevRole". For a plain string
// with no "/" it returns the string unchanged.
func arnName(arn string) string {
	if idx := strings.LastIndex(arn, "/"); idx >= 0 {
		return arn[idx+1:]
	}
	if idx := strings.LastIndex(arn, ":"); idx >= 0 {
		return arn[idx+1:]
	}
	return arn
}

// isAdminName returns true when the name component of an ARN matches a known
// admin identifier. Only the name component (not the full ARN) is tested to
// prevent false positives from account IDs or path segments that incidentally
// contain "admin".
func isAdminName(name string) bool {
	lower := strings.ToLower(name)
	return lower == "admin" ||
		lower == "administrator" ||
		strings.Contains(lower, "administratoraccess")
}

// isSensitiveResource returns true when the resource matches any of the
// hardcoded sensitivity heuristics.
func isSensitiveResource(r *model.Resource) bool {
	arn := r.ARN
	kind := r.Kind
	name := arnName(arn)

	// Rule 1: IAMRole whose name component indicates admin-level access.
	if strings.Contains(arn, ":role/") && kind == "IAMRole" && isAdminName(name) {
		return true
	}

	// Rule 2: ARN contains the canonical AdministratorAccess policy path, or
	// the name component exactly matches AdministratorAccess.
	if strings.Contains(arn, "iam::aws:policy/AdministratorAccess") ||
		strings.EqualFold(name, "AdministratorAccess") {
		return true
	}

	// Rule 3: Secrets Manager secret ARN.
	if strings.Contains(arn, ":secret:") {
		return true
	}

	// Rule 4: KMS key ARN.
	if strings.Contains(arn, ":key/") && kind == "KMSKey" {
		return true
	}

	return false
}
