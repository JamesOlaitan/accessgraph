package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/JamesOlaitan/accessgraph/internal/service"
)

var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Run precision/recall benchmarks against IAMVulnerable scenarios",
	Long: `benchmark loads IAMVulnerable scenarios from --scenarios, runs each selected
tool against them, runs AccessGraph itself, computes TP/FP/FN per tool per
chain-length class, and renders a comparison table.

External tool invocations require a binary built with -tags integration.

Example:
  accessgraph benchmark --scenarios ./scenarios --tools prowler,pmapper,accessgraph
  accessgraph benchmark --scenarios ./scenarios --output json`,
	SilenceUsage: true,
	RunE:         runBenchmark,
}

type benchmarkFlags struct {
	scenariosDir string
	tools        string
	output       string
	accountID    string
}

var benchmarkOpts benchmarkFlags

func init() {
	benchmarkCmd.Flags().StringVar(&benchmarkOpts.scenariosDir, "scenarios", "",
		"directory containing IAMVulnerable scenario subdirectories (required)")
	benchmarkCmd.Flags().StringVar(&benchmarkOpts.tools, "tools", "accessgraph",
		`comma-separated list of tools: accessgraph, prowler, pmapper, checkov`)
	benchmarkCmd.Flags().StringVar(&benchmarkOpts.output, "output", "terminal",
		`output format: "terminal" or "json"`)
	benchmarkCmd.Flags().StringVar(&benchmarkOpts.accountID, "account-id", "",
		"AWS account ID of the test account; used by live-AWS fixture capture")

	if err := benchmarkCmd.MarkFlagRequired("scenarios"); err != nil {
		panic(fmt.Sprintf("accessgraph: failed to mark --scenarios as required: %v", err))
	}
}

func runBenchmark(cmd *cobra.Command, _ []string) error {
	return service.RunBenchmark(cmd.Context(), service.BenchmarkInput{
		ScenariosDir: benchmarkOpts.scenariosDir,
		Tools:        benchmarkOpts.tools,
		Output:       benchmarkOpts.output,
		AccountID:    benchmarkOpts.accountID,
		Cfg:          cfg,
	}, cmd.OutOrStdout())
}
