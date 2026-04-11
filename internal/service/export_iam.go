package service

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/JamesOlaitan/accessgraph/internal/iamexport"
)

// ExportIAMInput holds the parameters required by the export-iam service.
type ExportIAMInput struct {
	Profile     string
	Region      string
	EndpointURL string
}

// RunExportIAM loads AWS credentials, creates IAM and STS clients, and
// exports the full IAM configuration as JSON to w.
func RunExportIAM(ctx context.Context, in ExportIAMInput, w io.Writer) (iamexport.Stats, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(in.Region),
	}
	if in.Profile != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(in.Profile))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return iamexport.Stats{}, fmt.Errorf("service.RunExportIAM: load AWS config: %w", err)
	}

	iamClient := iam.NewFromConfig(awsCfg, func(o *iam.Options) {
		if in.EndpointURL != "" {
			o.BaseEndpoint = aws.String(in.EndpointURL)
		}
	})
	stsClient := sts.NewFromConfig(awsCfg, func(o *sts.Options) {
		if in.EndpointURL != "" {
			o.BaseEndpoint = aws.String(in.EndpointURL)
		}
	})

	exp := &iamexport.Exporter{IAM: iamClient, STS: stsClient}
	return exp.Export(ctx, w)
}
