package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/JamesOlaitan/accessgraph/internal/service"
)

// exportIAMCmd implements "accessgraph export-iam".
var exportIAMCmd = &cobra.Command{
	Use:   "export-iam",
	Short: "Export IAM configuration from an AWS account as JSON",
	Long: `export-iam connects to a live AWS account using the default credential chain
and exports the full IAM configuration (users, roles, groups, and managed
policies) as a single JSON file. The output format matches the schema
expected by accessgraph ingest, so the exported file can be fed directly
into the analysis pipeline.

The command calls GetAccountAuthorizationDetails with pagination to
retrieve all IAM entities, URL-decodes embedded policy documents, and
emits the result to stdout (or to the file specified by --output).
Progress is logged to stderr.

Typical usage:

  accessgraph export-iam > iam-export.json
  accessgraph export-iam --profile prod --output iam-export.json
  accessgraph export-iam --endpoint-url http://localhost:4566  # LocalStack

Required AWS permissions: ReadOnlyAccess or SecurityAudit managed policy
(specifically iam:GetAccountAuthorizationDetails and sts:GetCallerIdentity).`,
	SilenceUsage: true,
	RunE:         runExportIAM,
}

type exportIAMFlags struct {
	profile     string
	output      string
	region      string
	endpointURL string
}

var exportIAMOpts exportIAMFlags

func init() {
	exportIAMCmd.Flags().StringVar(&exportIAMOpts.profile, "profile", "",
		"AWS profile name (uses default credential chain if omitted)")
	exportIAMCmd.Flags().StringVar(&exportIAMOpts.output, "output", "",
		"output file path (default: stdout)")
	exportIAMCmd.Flags().StringVar(&exportIAMOpts.region, "region", "us-east-1",
		"AWS region for STS (IAM is global but STS needs a region)")
	exportIAMCmd.Flags().StringVar(&exportIAMOpts.endpointURL, "endpoint-url", "",
		"custom AWS endpoint URL for LocalStack development")
}

func runExportIAM(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()

	w := cmd.OutOrStdout()
	if exportIAMOpts.output != "" {
		f, err := os.Create(exportIAMOpts.output)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	stats, err := service.RunExportIAM(ctx, service.ExportIAMInput{
		Profile:     exportIAMOpts.profile,
		Region:      exportIAMOpts.region,
		EndpointURL: exportIAMOpts.endpointURL,
	}, w)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "exported %d users, %d roles, %d groups, %d policies\n",
		stats.Users, stats.Roles, stats.Groups, stats.Policies)

	return nil
}
