package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/JamesOlaitan/accessgraph/internal/service"
)

// reportCmd implements "accessgraph report".
//
// It loads a previously computed snapshot, its attack paths, and its findings
// from the configured store, assembles a model.Report, and renders it in the
// requested output format. No re-analysis is performed; this command renders
// only data that was stored by a prior "analyze" invocation.
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Render a previously computed report from stored data",
	Long: `report loads the snapshot identified by --snapshot from the store, retrieves
the associated attack paths and findings saved by a prior "analyze" run, and
renders the assembled report.

Example:
  accessgraph report --snapshot snap-123456789012-1700000000000000000
  accessgraph report --snapshot snap-123456789012-1700000000000000000 --output json`,
	SilenceUsage: true,
	RunE:         runReport,
}

// reportFlags holds the parsed flag values for the report command.
type reportFlags struct {
	snapshotID string
	output     string
}

// reportOpts is the flag-value container populated by cobra during flag parsing.
var reportOpts reportFlags

func init() {
	reportCmd.Flags().StringVar(&reportOpts.snapshotID, "snapshot", "",
		"snapshot ID to load and render (required)")
	reportCmd.Flags().StringVar(&reportOpts.output, "output", "terminal",
		`output format: "terminal", "json", or "dot"`)

	if err := reportCmd.MarkFlagRequired("snapshot"); err != nil {
		panic(fmt.Sprintf("accessgraph: failed to mark --snapshot as required: %v", err))
	}
}

func runReport(cmd *cobra.Command, _ []string) error {
	switch reportOpts.output {
	case "terminal", "json", "dot":
	default:
		return fmt.Errorf("--output must be one of: terminal, json, dot; got %q", reportOpts.output)
	}
	return service.RunReport(context.Background(), service.ReportInput{
		SnapshotID:   reportOpts.snapshotID,
		OutputFormat: reportOpts.output,
		Cfg:          cfg,
	}, cmd.OutOrStdout())
}
