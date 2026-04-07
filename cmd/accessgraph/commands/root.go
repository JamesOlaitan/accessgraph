// Package commands contains all cobra command definitions for the accessgraph CLI.
//
// Architecture rules enforced in this package:
//   - os.Exit is never called here; only main.go may call it.
//   - Concrete types from internal/ are instantiated exclusively in this package.
//   - Each command's RunE calls exactly one service function or orchestration step.
//   - No business logic lives here; commands perform flag parsing, service wiring,
//     and output writing only.
//   - All normal output goes to cmd.OutOrStdout(); errors go to cmd.ErrOrStderr().
package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/JamesOlaitan/accessgraph/internal/config"
)

// Version is set at build time via -ldflags "-X github.com/JamesOlaitan/accessgraph/cmd/accessgraph/commands.Version=<tag>".
// It defaults to "dev" for local builds.
var Version = "dev"

// cfg holds the runtime configuration loaded during PersistentPreRunE.
// It is package-level so that every sub-command can read it without having
// to pass it through cobra's context or global state individually.
var cfg *config.Config

// rootCmd is the base command for the accessgraph CLI.
var rootCmd = &cobra.Command{
	Use:   "accessgraph",
	Short: "AccessGraph — IAM permission graph analyser and benchmark harness",
	Long: `AccessGraph builds a directed permission graph from IAM environment snapshots,
detects privilege-escalation paths via BFS traversal, evaluates policy violations
using Open Policy Agent rules, and benchmarks detection accuracy against
IAMVulnerable scenarios relative to Prowler, PMapper, and Checkov.

Sub-commands:
  ingest     Parse an IAM export JSON file and persist it as a snapshot.
  analyze    Build the permission graph and compute blast-radius metrics.
  benchmark  Run precision/recall benchmarks against IAMVulnerable scenarios.
  report     Render a previously computed report from stored data.

Version: ` + Version,
	// SilenceUsage suppresses the usage message on RunE errors so that the
	// structured error output written to ErrOrStderr is the only output.
	SilenceUsage: true,
	// SilenceErrors prevents cobra from printing the error a second time
	// after RunE returns it; the command itself writes the error message.
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg = config.Load()

		// Allow --db and --policy-dir flags to override the env-loaded config.
		if dbFlag := cmd.Root().PersistentFlags().Lookup("db"); dbFlag != nil && dbFlag.Changed {
			cfg.DBPath = dbFlag.Value.String()
		}
		if pdFlag := cmd.Root().PersistentFlags().Lookup("policy-dir"); pdFlag != nil && pdFlag.Changed {
			cfg.PolicyDir = pdFlag.Value.String()
		}

		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().String("db", "accessgraph.db",
		"path to the SQLite database file (overrides ACCESSGRAPH_DB)")

	rootCmd.PersistentFlags().String("policy-dir", "policy",
		"directory containing OPA Rego rules (overrides ACCESSGRAPH_POLICY_DIR)")

	rootCmd.AddCommand(ingestCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(benchmarkCmd)
	rootCmd.AddCommand(reportCmd)
}

// Execute runs the root command and returns any error produced by the selected
// sub-command. The caller (main.go) is responsible for mapping the error to an
// appropriate exit code.
//
// Returns:
//   - nil on success.
//   - A non-nil error if command parsing or execution fails.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		// rootCmd.Execute() itself only returns an error when SilenceErrors is true
		// and a RunE returned an error; the sub-command has already written the
		// human-readable message to ErrOrStderr.
		return fmt.Errorf("%w", err)
	}
	return nil
}
