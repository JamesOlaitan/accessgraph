// Package service provides facade services that orchestrate the multi-step
// data flows required by each CLI command. Each facade exposes a single Run
// method so that command handlers contain no business logic.
//
// Dependency rule: this package may import from internal/model, internal/store,
// internal/parser, internal/analyzer, internal/graph, internal/policy,
// internal/report, internal/benchmark, and internal/config. It must not import
// from cmd/.
package service

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/JamesOlaitan/accessgraph/internal/analyzer"
	"github.com/JamesOlaitan/accessgraph/internal/config"
	"github.com/JamesOlaitan/accessgraph/internal/parser"
	"github.com/JamesOlaitan/accessgraph/internal/store"
)

// IngestInput holds the parameters required by the ingest service.
//
// Fields:
//   - Source: filesystem path to the IAM export JSON file.
//   - Label: human-readable snapshot label.
//   - Provider: cloud provider identifier (currently only "aws").
//   - Cfg: global configuration (DBPath, etc.).
type IngestInput struct {
	Source   string
	Label    string
	Provider string
	Cfg      *config.Config
}

// RunIngest executes the full ingest service: read file, parse, classify, persist.
//
// It writes a one-line summary to w on success.
//
// Parameters:
//   - ctx: context for cancellation.
//   - in: ingest parameters.
//   - w: writer for the success summary line.
//
// Errors:
//   - Any I/O, parse, classification, or store error.
func RunIngest(ctx context.Context, in IngestInput, w io.Writer) error {
	data, err := os.ReadFile(in.Source)
	if err != nil {
		return fmt.Errorf("service.RunIngest: read source %q: %w", in.Source, err)
	}

	p := parser.NewAWSIAMParser()
	snapshot, err := p.ParseAWSIAM(ctx, data, in.Label)
	if err != nil {
		return fmt.Errorf("service.RunIngest: parse IAM export: %w", err)
	}

	if err := analyzer.ClassifySensitiveResources(snapshot); err != nil {
		return fmt.Errorf("service.RunIngest: classify sensitive resources: %w", err)
	}

	var ds store.DataStore
	sqliteStore, err := store.New(ctx, in.Cfg.DBPath)
	if err != nil {
		return fmt.Errorf("service.RunIngest: open store at %q: %w", in.Cfg.DBPath, err)
	}
	ds = sqliteStore
	defer sqliteStore.Close()

	if err := ds.SaveSnapshot(ctx, snapshot); err != nil {
		return fmt.Errorf("service.RunIngest: save snapshot: %w", err)
	}

	fmt.Fprintf(w,
		"Snapshot ingested: id=%s label=%s principals=%d policies=%d resources=%d edges=%d\n",
		snapshot.ID,
		snapshot.Label,
		len(snapshot.Principals),
		len(snapshot.Policies),
		len(snapshot.Resources),
		len(snapshot.Edges),
	)
	return nil
}
