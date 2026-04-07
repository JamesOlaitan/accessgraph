package commands

import (
	"testing"
)

// TestBenchmarkAccountIDFlag verifies that --account-id is registered on the
// benchmark command and that its value is stored in benchmarkOpts.accountID
// after parsing.
func TestBenchmarkAccountIDFlag(t *testing.T) {
	flag := benchmarkCmd.Flags().Lookup("account-id")
	if flag == nil {
		t.Fatal("--account-id flag is not registered on benchmarkCmd")
	}

	const wantUsage = "AWS account ID of the test account; used by live-AWS fixture capture"
	if flag.Usage != wantUsage {
		t.Errorf("--account-id usage: got %q want %q", flag.Usage, wantUsage)
	}

	// Default must be empty string.
	if flag.DefValue != "" {
		t.Errorf("--account-id default: got %q want empty string", flag.DefValue)
	}

	// Parse the flag and assert the value lands in benchmarkOpts.
	const testAccountID = "123456789012"
	if err := benchmarkCmd.Flags().Set("account-id", testAccountID); err != nil {
		t.Fatalf("Set --account-id: %v", err)
	}
	if benchmarkOpts.accountID != testAccountID {
		t.Errorf("benchmarkOpts.accountID: got %q want %q", benchmarkOpts.accountID, testAccountID)
	}
}
