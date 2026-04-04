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

var extractDexCmd = &cobra.Command{
	Use:   "extract-dex <file.vdex> <out-dir>",
	Short: "Extract embedded DEX files from a VDEX container",
	Long: `Extract all DEX files embedded in a VDEX file into the specified
output directory. Each DEX file is written as a separate file.

Use --extract-name-template to customize output filenames.
Use --extract-continue-on-error to skip failures and continue.`,
	Example: `  vdexcli extract-dex app.vdex ./dex-output/
  vdexcli extract-dex --json app.vdex ./out/
  vdexcli extract-dex --extract-name-template "{base}_{index}_{checksum_hex}.dex" app.vdex ./out/
  vdexcli extract-dex --extract-continue-on-error app.vdex ./out/`,
	Args: cobra.ExactArgs(2),
	RunE: runExtractDex,
}

func runExtractDex(_ *cobra.Command, args []string) error {
	vdexPath := args[0]
	outDir := args[1]

	report, raw, err := parser.ParseVdex(vdexPath, flagMeanings)
	parseErr := err
	if err != nil && report == nil {
		return err
	}
	if report == nil {
		return fmt.Errorf("no parse result for %s", vdexPath)
	}
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	}

	opts := extractor.Options{
		NameTemplate:    flagExtractTmpl,
		ContinueOnError: flagExtractCont,
	}
	res, err := extractor.Extract(vdexPath, raw, report, outDir, opts)
	report.Warnings = append(report.Warnings, res.Warnings...)
	report.WarningsByCategory = presenter.GroupWarnings(report.Warnings)
	if err != nil {
		return fmt.Errorf("extract-dex: %w", err)
	}

	if strictMatched := applyStrict(report); len(strictMatched) > 0 {
		return fmt.Errorf("strict mode: %d matching warning(s): %v", len(strictMatched), strictMatched)
	}

	summary := model.ExtractSummary{
		SchemaVersion:      model.VdexSchemaVersion,
		File:               vdexPath,
		Size:               len(raw),
		ExtractDir:         outDir,
		NameTemplate:       flagExtractTmpl,
		Extracted:          res.Extracted,
		Failed:             res.Failed,
		Warnings:           report.Warnings,
		WarningsByCategory: report.WarningsByCategory,
		Errors:             report.Errors,
	}

	w := os.Stdout
	switch resolvedFormat() {
	case FormatJSON:
		return presenter.WriteJSON(w, summary)
	case FormatJSONL:
		return presenter.WriteJSONL(w, summary)
	case FormatSummary:
		presenter.WriteExtractSummary(w, summary)
	default:
		fmt.Printf("extracted %d dex files to %s\n", res.Extracted, outDir)
		if res.Failed > 0 {
			fmt.Printf("  failed: %d\n", res.Failed)
		}
		if len(report.Warnings) > 0 {
			presenter.PrintGroupedWarnings(report.Warnings)
		}
	}
	if parseErr != nil {
		return parseErr
	}
	return nil
}
