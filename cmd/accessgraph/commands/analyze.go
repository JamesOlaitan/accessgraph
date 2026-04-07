package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/JamesOlaitan/accessgraph/internal/service"
)

// analyzeCmd implements "accessgraph analyze".
//
// It loads a snapshot by label, builds the permission graph, synthesizes
// escalation edges, computes blast-radius metrics, evaluates OPA policy rules,
// persists the derived data, assembles a model.Report, and renders it in the
// requested output format.
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Build the permission graph and compute blast-radius metrics",
	Long: `analyze loads the named snapshot, builds an in-memory permission graph,
synthesizes privilege-escalation edges, runs a BFS-based blast-radius analysis
from the supplied principal ARN, evaluates OPA policy rules, and renders the
combined report.

Example:
  accessgraph analyze --label prod-2024-01 --from arn:aws:iam::123456789012:user/alice
  accessgraph analyze --label prod-2024-01 --from arn:aws:iam::123456789012:user/alice --max-hops 6 --output json`,
	SilenceUsage: true,
	RunE:         runAnalyze,
}

// analyzeFlags holds the parsed flag values for the analyze command.
type analyzeFlags struct {
	label   string
	fromARN string
	maxHops int
	output  string
}

// analyzeOpts is the flag-value container populated by cobra during flag parsing.
var analyzeOpts analyzeFlags

func init() {
	analyzeCmd.Flags().StringVar(&analyzeOpts.label, "label", "",
		"snapshot label to analyze (required)")
	analyzeCmd.Flags().StringVar(&analyzeOpts.fromARN, "from", "",
		"ARN of the compromised principal to start blast-radius analysis from (required)")
	analyzeCmd.Flags().IntVar(&analyzeOpts.maxHops, "max-hops", 8,
		"maximum BFS depth for attack path detection")
	analyzeCmd.Flags().StringVar(&analyzeOpts.output, "output", "terminal",
		`output format: "terminal", "json", or "dot"`)

	if err := analyzeCmd.MarkFlagRequired("label"); err != nil {
		panic(fmt.Sprintf("accessgraph: failed to mark --label as required: %v", err))
	}
	if err := analyzeCmd.MarkFlagRequired("from"); err != nil {
		panic(fmt.Sprintf("accessgraph: failed to mark --from as required: %v", err))
	}
}

func runAnalyze(cmd *cobra.Command, _ []string) error {
	if analyzeOpts.maxHops < 1 {
		return fmt.Errorf("--max-hops must be >= 1, got %d", analyzeOpts.maxHops)
	}

	return service.RunAnalysis(cmd.Context(), service.AnalysisInput{
		Label:        analyzeOpts.label,
		FromARN:      analyzeOpts.fromARN,
		MaxHops:      analyzeOpts.maxHops,
		OutputFormat: analyzeOpts.output,
		Cfg:          cfg,
	}, cmd.OutOrStdout())
}
