// Package cmd implements the cobra CLI commands for vdexcli.
package cmd

import (
	"fmt"
	"os"

	"github.com/0xc0de1ab/vdexcli/internal/model"
	"github.com/spf13/cobra"
)

// OutputFormat enumerates supported --format values.
type OutputFormat string

const (
	FormatText     OutputFormat = "text"
	FormatJSON     OutputFormat = "json"
	FormatJSONL    OutputFormat = "jsonl"
	FormatSummary  OutputFormat = "summary"
	FormatSections OutputFormat = "sections"
	FormatCoverage OutputFormat = "coverage"
)

// Shared flags bound at the root level.
var (
	flagJSON        bool
	flagFormat      string
	flagMeanings    bool
	flagStrict      bool
	flagStrictWarn  string
	flagInputPath   string
	flagExtractDir  string
	flagExtractTmpl string
	flagExtractCont bool
)

// resolvedFormat returns the effective output format considering both --json and --format.
func resolvedFormat() OutputFormat {
	if flagFormat != "" {
		return OutputFormat(flagFormat)
	}
	if flagJSON {
		return FormatJSON
	}
	return FormatText
}

var rootCmd = &cobra.Command{
	Use:   "vdexcli [flags] <file.vdex>",
	Short: "Parse Android ART vdex files and print semantic structure",
	Long: `vdexcli parses, extracts, and modifies Android ART VDEX (v027) files.

It reads every byte of a VDEX file — header, section table, checksums,
embedded DEX files, verifier dependencies, and type lookup tables — and
reports structural details in text or JSON.

When run without a subcommand, it behaves like "vdexcli parse".`,
	Args:    cobra.MaximumNArgs(1),
	Version: model.CLIVersion,
}

// Execute is the main entry point called from main().
func Execute() {
	rootCmd.SetVersionTemplate("vdexcli version {{.Version}}\n")
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVarP(&flagInputPath, "in", "i", "", "input vdex path (alternative to positional arg)")
	pf.BoolVar(&flagJSON, "json", false, "shorthand for --format json")
	pf.StringVar(&flagFormat, "format", "", "output format: text, json, jsonl, summary, sections, coverage")
	pf.BoolVar(&flagMeanings, "show-meaning", true, "include field descriptions in output")
	pf.BoolVar(&flagStrict, "strict", false, "treat matched warnings as fatal errors")
	pf.StringVar(&flagStrictWarn, "strict-warn", "", `comma-separated patterns; prefix "re:" for regex`)
	pf.StringVar(&flagExtractDir, "extract-dex", "", "extract embedded dex files into this directory (parse only)")
	pf.StringVar(&flagExtractTmpl, "extract-name-template", model.DefaultNameTemplate,
		"template for extracted dex file names: {base}, {index}, {checksum}, {checksum_hex}, {offset}, {size}")
	pf.BoolVar(&flagExtractCont, "extract-continue-on-error", false, "continue extracting when one dex fails")

	rootCmd.AddCommand(parseCmd, extractDexCmd, modifyCmd, dumpCmd, versionCmd)
}

// resolveInputPath returns the VDEX file path from --in flag or first positional arg.
func resolveInputPath(args []string) (string, error) {
	if flagInputPath != "" {
		return flagInputPath, nil
	}
	if len(args) > 0 {
		return args[0], nil
	}
	return "", fmt.Errorf("input vdex path is required (pass as argument or use --in)")
}
