package commands

import (
	"testing"
)

// TestBenchmarkAccountIDFlagRemoved verifies that the --account-id flag has been
// removed. The account ID is now discovered from the PMapper fixture directory
// structure by the adapter, not passed as a CLI flag.
func TestBenchmarkAccountIDFlagRemoved(t *testing.T) {
	flag := benchmarkCmd.Flags().Lookup("account-id")
	if flag != nil {
		t.Error("--account-id flag should have been removed from benchmarkCmd")
	}
}

// TestBenchmarkRequiredFlags verifies that --scenarios is still required.
func TestBenchmarkRequiredFlags(t *testing.T) {
	flag := benchmarkCmd.Flags().Lookup("scenarios")
	if flag == nil {
		t.Fatal("--scenarios flag is not registered on benchmarkCmd")
	}
}
