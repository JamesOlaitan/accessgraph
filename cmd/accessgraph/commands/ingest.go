package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/JamesOlaitan/accessgraph/internal/service"
)

// ingestCmd implements "accessgraph ingest".
//
// It reads a JSON IAM export file, parses it into a model.Snapshot, classifies
// sensitive resources, persists the snapshot to the configured store, and prints
// a one-line summary of the ingested data to stdout.
var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Parse an IAM export JSON file and persist it as a snapshot",
	Long: `ingest reads the JSON file at --source, parses it with the AWS IAM parser,
classifies sensitive resources, opens the configured store, saves the snapshot,
and prints a summary line.

Example:
  accessgraph ingest --source ./iam-export.json --label prod-2024-01 --provider aws`,
	SilenceUsage: true,
	RunE:         runIngest,
}

// ingestFlags holds the parsed flag values for the ingest command.
// Using a dedicated struct keeps the RunE body free of flag-lookup boilerplate.
type ingestFlags struct {
	source   string
	label    string
	provider string
}

// ingestOpts is the flag-value container populated by cobra during flag parsing.
var ingestOpts ingestFlags

func init() {
	ingestCmd.Flags().StringVar(&ingestOpts.source, "source", "",
		"path to the IAM export JSON file (required)")
	ingestCmd.Flags().StringVar(&ingestOpts.label, "label", "",
		"human-readable name for the snapshot (required)")
	ingestCmd.Flags().StringVar(&ingestOpts.provider, "provider", "aws",
		`cloud provider of the export; currently only "aws" is supported`)

	if err := ingestCmd.MarkFlagRequired("source"); err != nil {
		panic(fmt.Sprintf("accessgraph: failed to mark --source as required: %v", err))
	}
	if err := ingestCmd.MarkFlagRequired("label"); err != nil {
		panic(fmt.Sprintf("accessgraph: failed to mark --label as required: %v", err))
	}
}

func runIngest(cmd *cobra.Command, _ []string) error {
	if ingestOpts.source == "" {
		return fmt.Errorf("--source must not be empty")
	}
	if ingestOpts.label == "" {
		return fmt.Errorf("--label must not be empty")
	}
	return service.RunIngest(context.Background(), service.IngestInput{
		Source:   ingestOpts.source,
		Label:    ingestOpts.label,
		Provider: ingestOpts.provider,
		Cfg:      cfg,
	}, cmd.OutOrStdout())
}
