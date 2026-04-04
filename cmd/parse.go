package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/0xc0de1ab/vdexcli/internal/extractor"
	"github.com/0xc0de1ab/vdexcli/internal/model"
	"github.com/0xc0de1ab/vdexcli/internal/parser"
	"github.com/0xc0de1ab/vdexcli/internal/presenter"
)

var parseCmd = &cobra.Command{
	Use:   "parse [flags] <file.vdex>",
	Short: "Parse and print VDEX structure",
	Long: `Parse a VDEX file and print its full structure — header, sections,
checksums, embedded DEX files, verifier dependencies, type lookup tables,
and byte-level coverage.

Output format is controlled by --format (or --json as shorthand for --format json).

Supported formats:
  text      Human-readable full dump (default)
  json      Pretty-printed JSON with all fields
  jsonl     Compact single-line JSON for log pipelines
  summary   One-line key=value for CI gates and monitoring
  sections  TSV table of section headers for grep/awk
  coverage  Byte coverage report only
  table     Aligned columns with ANSI color`,
	Example: `  vdexcli parse app.vdex
  vdexcli parse --json app.vdex
  vdexcli parse --format summary app.vdex
  vdexcli parse --format sections app.vdex | awk -F'\t' '$4 > 0'
  vdexcli parse --format coverage app.vdex
  vdexcli parse --format jsonl app.vdex >> parse.log
  vdexcli parse --strict --strict-warn "checksum,version" app.vdex
  vdexcli parse --extract-dex ./out app.vdex`,
	Args: cobra.MaximumNArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if _, err := resolveInputPath(cmd, args); err != nil {
			return err
		}
		g := getGlobalOpts(cmd)
		return presenter.ValidateFormat(g.Format)
	},
	RunE: runParse,
}

func init() {
	rootCmd.RunE = runParse
}

func runParse(cmd *cobra.Command, args []string) error {
	path, err := resolveInputPath(cmd, args)
	if err != nil {
		return err
	}
	p := getParseOpts(cmd)

	report, raw, err := parser.ParseVdex(path, p.Meanings)
	parseErr := err

	var extractErr error
	if report != nil && p.ExtractDir != "" {
		opts := extractor.Options{
			NameTemplate:    p.ExtractTmpl,
			ContinueOnError: p.ExtractCont,
		}
		res, e := extractor.Extract(path, raw, report, p.ExtractDir, opts)
		if e != nil {
			extractErr = e
			fmt.Fprintf(os.Stderr, "extract error: %v\n", e)
		}
		report.Warnings = append(report.Warnings, res.Warnings...)
		if resolvedFormat(cmd) == FormatText {
			fmt.Printf("extract summary: success=%d failed=%d\n", res.Extracted, res.Failed)
		}
	}

	if report != nil {
		report.WarningsByCategory = presenter.GroupWarnings(report.Warnings)
	}

	strictMatched := applyStrict(cmd, report)

	if err := renderParseOutput(cmd, report); err != nil {
		return err
	}

	if len(strictMatched) > 0 {
		return fmt.Errorf("strict mode: %d matching warning(s): %v", len(strictMatched), strictMatched)
	}
	if parseErr != nil {
		return parseErr
	}
	return extractErr
}

func renderParseOutput(cmd *cobra.Command, report *model.VdexReport) error {
	w := os.Stdout
	switch resolvedFormat(cmd) {
	case FormatJSON:
		return presenter.WriteJSON(w, report)
	case FormatJSONL:
		return presenter.WriteJSONL(w, report)
	case FormatSummary:
		presenter.WriteSummary(w, report)
	case FormatSections:
		presenter.WriteSections(w, report)
	case FormatCoverage:
		presenter.WriteCoverage(w, report)
	case FormatTable:
		presenter.WriteTable(w, report)
	default:
		presenter.PrintText(report)
	}
	return nil
}

func applyStrict(cmd *cobra.Command, report *model.VdexReport) []string {
	p := getParseOpts(cmd)
	if !p.Strict || report == nil {
		return nil
	}
	matched, filterWarn := presenter.StrictMatchingWarnings(report.Warnings, p.StrictWarn)
	if len(filterWarn) > 0 {
		report.Warnings = append(report.Warnings, filterWarn...)
		report.WarningsByCategory = presenter.GroupWarnings(report.Warnings)
	}
	return matched
}
