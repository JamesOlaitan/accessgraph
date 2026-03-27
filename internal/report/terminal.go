package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// RenderTerminal writes a human-readable, colored report to w.
//
// The output is structured in four sections:
//  1. A header showing the snapshot label and generation timestamp.
//  2. A BLAST RADIUS SUMMARY table with per-principal reachability metrics.
//  3. An ATTACK PATHS section listing each discovered path with hop count,
//     privilege-escalation flag, and the ordered chain of node IDs.
//  4. A FINDINGS section listing OPA rule violations with severity coloring.
//
// Severity coloring:
//   - CRITICAL and HIGH: red
//   - MEDIUM: yellow
//   - LOW: cyan
//
// Parameters:
//   - w: destination writer; must not be nil.
//   - report: the analysis report to render; must not be nil.
//
// Returns ErrRenderFailed (wrapped) on any I/O error encountered while
// writing to w.
func (r *DefaultReporter) RenderTerminal(w io.Writer, report *model.Report) error {
	if err := renderHeader(w, report); err != nil {
		return fmt.Errorf("%w: header: %v", ErrRenderFailed, err)
	}
	if err := renderBlastRadiusSummary(w, report); err != nil {
		return fmt.Errorf("%w: blast radius summary: %v", ErrRenderFailed, err)
	}
	if err := renderAttackPaths(w, report); err != nil {
		return fmt.Errorf("%w: attack paths: %v", ErrRenderFailed, err)
	}
	if err := renderFindings(w, report); err != nil {
		return fmt.Errorf("%w: findings: %v", ErrRenderFailed, err)
	}
	return nil
}

// renderHeader writes the report header containing the snapshot label and the
// UTC generation timestamp.
//
// Parameters:
//   - w: destination writer.
//   - report: the report whose metadata is rendered.
//
// Returns the first I/O error encountered.
func renderHeader(w io.Writer, report *model.Report) error {
	bold := color.New(color.Bold)

	snapshotLabel := ""
	snapshotID := ""
	if report.Snapshot != nil {
		snapshotLabel = report.Snapshot.Label
		snapshotID = report.Snapshot.ID
	}

	if _, err := bold.Fprintf(w, "AccessGraph Analysis Report\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Snapshot : %s (%s)\n", snapshotLabel, snapshotID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Generated: %s\n\n", report.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z")); err != nil {
		return err
	}
	return nil
}

// renderBlastRadiusSummary writes the BLAST RADIUS SUMMARY section as an
// aligned tabular table.
//
// Columns:
//   - Principal ARN
//   - Reachable Resources
//   - % Environment
//   - Min Hops to Admin  (-1 rendered as "unreachable")
//   - Distinct Paths
//
// Parameters:
//   - w: destination writer.
//   - report: the report whose BlastRadius is rendered.
//
// Returns the first I/O error encountered.
func renderBlastRadiusSummary(w io.Writer, report *model.Report) error {
	sectionHeader := color.New(color.Bold, color.FgCyan)
	if _, err := sectionHeader.Fprintf(w, "BLAST RADIUS SUMMARY\n"); err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	if _, err := fmt.Fprintln(tw, "PRINCIPAL ARN\tREACHABLE RESOURCES\t% ENVIRONMENT\tMIN HOPS TO ADMIN\tDISTINCT PATHS"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(tw, "-------------\t-------------------\t-------------\t-----------------\t--------------"); err != nil {
		return err
	}

	if report.BlastRadius != nil {
		br := report.BlastRadius

		minHops := fmt.Sprintf("%d", br.MinHopToAdmin)
		if br.MinHopToAdmin == -1 {
			minHops = "unreachable"
		}

		if _, err := fmt.Fprintf(tw, "%s\t%d\t%.1f%%\t%s\t%d\n",
			br.PrincipalID,
			br.ReachableResourceCount,
			float64(br.PctEnvironmentReachable),
			minHops,
			br.DistinctPathCount,
		); err != nil {
			return err
		}
	}

	if err := tw.Flush(); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	return nil
}

// renderAttackPaths writes the ATTACK PATHS section.
//
// Each path is rendered as a numbered entry showing:
//   - Hop count
//   - ESCALATION label (in red) when IsPrivilegeEscalation is true
//   - Path nodes joined with " → "
//
// Parameters:
//   - w: destination writer.
//   - report: the report whose BlastRadius.Paths are rendered.
//
// Returns the first I/O error encountered.
func renderAttackPaths(w io.Writer, report *model.Report) error {
	sectionHeader := color.New(color.Bold, color.FgCyan)
	if _, err := sectionHeader.Fprintf(w, "ATTACK PATHS\n"); err != nil {
		return err
	}

	if report.BlastRadius == nil || len(report.BlastRadius.Paths) == 0 {
		if _, err := fmt.Fprintln(w, "  (none)"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		return nil
	}

	red := color.New(color.FgRed)

	for i, path := range report.BlastRadius.Paths {
		escalationLabel := ""
		if path.IsPrivilegeEscalation {
			escalationLabel = " [ESCALATION]"
		}

		chain := strings.Join(path.PathNodes, " → ")
		if _, err := fmt.Fprintf(w, "  [%d] hops=%d", i+1, path.HopCount); err != nil {
			return err
		}
		if path.IsPrivilegeEscalation {
			if _, err := red.Fprintf(w, "%s", escalationLabel); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "\n      %s\n", chain); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	return nil
}

// renderFindings writes the FINDINGS section.
//
// Each finding is rendered as a row in a shared tab-aligned table with:
//   - Severity (colored per level)
//   - Rule ID
//   - Entity reference
//   - Reason
//
// All rows — header, divider, and data — share a single tabwriter so that
// column widths are computed globally and every row aligns correctly.
// Severity text is written without ANSI codes inside the tabwriter to prevent
// invisible escape bytes from skewing column-width measurements; coloring is
// applied via a separate write after the tabwriter flushes.
//
// Severity coloring:
//   - CRITICAL / HIGH : red
//   - MEDIUM          : yellow
//   - LOW             : cyan
//
// Parameters:
//   - w: destination writer.
//   - report: the report whose Findings are rendered.
//
// Returns the first I/O error encountered.
func renderFindings(w io.Writer, report *model.Report) error {
	sectionHeader := color.New(color.Bold, color.FgCyan)
	if _, err := sectionHeader.Fprintf(w, "FINDINGS\n"); err != nil {
		return err
	}

	if len(report.Findings) == 0 {
		if _, err := fmt.Fprintln(w, "  (none)"); err != nil {
			return err
		}
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SEVERITY\tRULE ID\tENTITY\tREASON"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(tw, "--------\t-------\t------\t------"); err != nil {
		return err
	}
	for _, f := range report.Findings {
		if err := renderFinding(tw, f); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// renderFinding writes a single finding row to tw.
//
// Severity text is written as a plain string (no ANSI codes) so that
// tabwriter can measure column widths accurately. The caller must flush tw
// after all rows have been written.
//
// Parameters:
//   - tw: the shared tabwriter that owns the findings table.
//   - f: the finding to render; must not be nil.
//
// Returns the first I/O error encountered.
func renderFinding(tw *tabwriter.Writer, f *model.Finding) error {
	if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
		string(f.Severity), f.RuleID, f.EntityRef, f.Reason,
	); err != nil {
		return err
	}
	return nil
}
