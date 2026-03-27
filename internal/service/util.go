package service

import (
	"fmt"

	"github.com/JamesOlaitan/accessgraph/internal/model"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// ResolvePrincipalByARN returns the internal principal ID for the given ARN
// within snapshot. It is used by both the analysis service and the benchmark
// self-evaluation service to resolve a starting ARN to a graph node ID.
//
// Parameters:
//   - snapshot: the snapshot to search within; must not be nil.
//   - arn: the ARN to resolve; must not be empty.
//
// Errors:
//   - store.ErrNotFound-wrapped error if no principal with that ARN exists.
func ResolvePrincipalByARN(snapshot *model.Snapshot, arn string) (string, error) {
	if arn == "" {
		return "", fmt.Errorf("ARN must not be empty")
	}
	for _, p := range snapshot.Principals {
		if p != nil && p.ARN == arn {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("no principal with ARN %q found in snapshot %q: %w",
		arn, snapshot.ID, store.ErrNotFound)
}
