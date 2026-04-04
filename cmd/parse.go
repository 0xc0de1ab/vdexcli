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
  coverage  Byte coverage report only`,
	Example: `  vdexcli parse app.vdex
  vdexcli parse --json app.vdex
  vdexcli parse --format summary app.vdex
  vdexcli parse --format sections app.vdex | awk -F'\t' '$4 > 0'
  vdexcli parse --format coverage app.vdex
  vdexcli parse --format jsonl app.vdex >> parse.log
  vdexcli parse --strict --strict-warn "checksum,version" app.vdex
  vdexcli parse --extract-dex ./out app.vdex`,
	Args: cobra.MaximumNArgs(1),
	PreRunE: func(_ *cobra.Command, args []string) error {
		if _, err := resolveInputPath(args); err != nil {
			return err
		}
		return presenter.ValidateFormat(flagFormat)
	},
	RunE: runParse,
}

func init() {
	rootCmd.RunE = runParse

	// Extract flags also available on parse subcommand (shared with root).
	pf := parseCmd.Flags()
	pf.StringVar(&flagExtractDir, "extract-dex", "", "extract embedded dex files into this directory")
	pf.StringVar(&flagExtractTmpl, "extract-name-template", model.DefaultNameTemplate,
		"template for extracted dex file names: {base}, {index}, {checksum}, {checksum_hex}, {offset}, {size}")
	pf.BoolVar(&flagExtractCont, "extract-continue-on-error", false, "continue extracting when one dex fails")
}

func runParse(_ *cobra.Command, args []string) error {
	path, _ := resolveInputPath(args)

	report, raw, err := parser.ParseVdex(path, flagMeanings)
	parseErr := err
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
	}

	var extractErr error
	if report != nil && flagExtractDir != "" {
		opts := extractor.Options{
			NameTemplate:    flagExtractTmpl,
			ContinueOnError: flagExtractCont,
		}
		res, e := extractor.Extract(path, raw, report, flagExtractDir, opts)
		if e != nil {
			extractErr = e
			fmt.Fprintf(os.Stderr, "extract error: %v\n", e)
		}
		report.Warnings = append(report.Warnings, res.Warnings...)
		if resolvedFormat() == FormatText {
			fmt.Printf("extract summary: success=%d failed=%d\n", res.Extracted, res.Failed)
		}
	}

	if report != nil {
		report.WarningsByCategory = presenter.GroupWarnings(report.Warnings)
	}

	strictMatched := applyStrict(report)

	if err := renderParseOutput(report); err != nil {
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

func renderParseOutput(report *model.VdexReport) error {
	w := os.Stdout
	switch resolvedFormat() {
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

func applyStrict(report *model.VdexReport) []string {
	if !flagStrict || report == nil {
		return nil
	}
	matched, filterWarn := presenter.StrictMatchingWarnings(report.Warnings, flagStrictWarn)
	if len(filterWarn) > 0 {
		report.Warnings = append(report.Warnings, filterWarn...)
		report.WarningsByCategory = presenter.GroupWarnings(report.Warnings)
	}
	return matched
}
