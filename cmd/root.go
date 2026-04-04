// Package cmd implements the cobra CLI commands for vdexcli.
package cmd

import (
	"fmt"
	"os"

	"github.com/0xc0de1ab/vdexcli/internal/model"
	"github.com/0xc0de1ab/vdexcli/internal/presenter"
	"github.com/dh-kam/refutils/flagsbinder"
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
	FormatTable    OutputFormat = "table"
)

// GlobalOpts holds flags applicable to all subcommands.
type GlobalOpts struct {
	JSON   bool   `flag:"json"`
	Format string `flag:"format"`
	Color  string `flag:"color"`
}

// ParseOpts holds flags for commands that process VDEX files.
type ParseOpts struct {
	InputPath   string `flag:"in"`
	Meanings    bool   `flag:"show-meaning"`
	Strict      bool   `flag:"strict"`
	StrictWarn  string `flag:"strict-warn"`
	ExtractDir  string `flag:"extract-dex"`
	ExtractTmpl string `flag:"extract-name-template"`
	ExtractCont bool   `flag:"extract-continue-on-error"`
}

// ModifyOpts holds flags specific to the modify subcommand.
type ModifyOpts struct {
	VerifierJSON string `flag:"verifier-json"`
	Mode         string `flag:"mode"`
	DryRun       bool   `flag:"dry-run"`
	Verify       bool   `flag:"verify"`
	Quiet        bool   `flag:"quiet"`
	Force        bool   `flag:"force"`
	LogFile      string `flag:"log-file"`
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
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, _ []string) {
		g := getGlobalOpts(cmd)
		switch g.Color {
		case "always":
			presenter.SetColor(true)
		case "never":
			presenter.SetColor(false)
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Global flags — defined via flagsbinder chaining, applied to PersistentFlags.
	globalBinder := flagsbinder.NewViperCobraFlagsBinder().
		Bool("json", false, "shorthand for --format json").
		String("format", "", "output format: text, json, jsonl, summary, sections, coverage, table").
		String("color", "auto", "color output: auto, always, never")
	globalBinder.SetTo(rootCmd.PersistentFlags())

	// Parse flags — shared by parse, extract-dex, modify.
	parseBinder := flagsbinder.NewViperCobraFlagsBinder().
		StringP("in", "i", "", "input vdex path (alternative to positional arg)").
		Bool("show-meaning", true, "include field descriptions in output").
		Bool("strict", false, "treat matched warnings as fatal errors").
		String("strict-warn", "", `comma-separated patterns; prefix "re:" for regex`)
	parseBinder.SetTo(rootCmd.PersistentFlags())

	// Extract flags — only on root (for root-as-parse) and parseCmd.
	extractBinder := flagsbinder.NewViperCobraFlagsBinder().
		String("extract-dex", "", "extract embedded dex files into this directory").
		String("extract-name-template", model.DefaultNameTemplate,
			"template for extracted dex file names: {base}, {index}, {checksum}, {checksum_hex}, {offset}, {size}").
		Bool("extract-continue-on-error", false, "continue extracting when one dex fails")
	extractBinder.SetTo(rootCmd.Flags())
	extractBinder.SetTo(parseCmd.Flags())

	// Modify flags — only on modifyCmd.
	modifyBinder := flagsbinder.NewViperCobraFlagsBinder().
		String("verifier-json", "", "path to verifier patch JSON (use - for stdin)").
		String("mode", "replace", "patch mode: replace|merge").
		Bool("dry-run", false, "validate and report changes without writing").
		Bool("verify", false, "alias for --dry-run").
		Bool("quiet", false, "suppress text-mode summary output").
		Bool("force", false, "allow output path equal to input path").
		String("log-file", "", "append result as NDJSON to file")
	modifyBinder.SetTo(modifyCmd.Flags())

	rootCmd.AddCommand(parseCmd, extractDexCmd, modifyCmd, dumpCmd, versionCmd)
}

// getGlobalOpts reads global flags from the command's inherited flag set.
func getGlobalOpts(cmd *cobra.Command) GlobalOpts {
	flags := cmd.Flags()
	json, _ := flags.GetBool("json")
	format, _ := flags.GetString("format")
	color, _ := flags.GetString("color")
	return GlobalOpts{JSON: json, Format: format, Color: color}
}

// getParseOpts reads parse-related flags from the command.
func getParseOpts(cmd *cobra.Command) ParseOpts {
	flags := cmd.Flags()
	in, _ := flags.GetString("in")
	meanings, _ := flags.GetBool("show-meaning")
	strict, _ := flags.GetBool("strict")
	strictWarn, _ := flags.GetString("strict-warn")
	extractDir, _ := flags.GetString("extract-dex")
	extractTmpl, _ := flags.GetString("extract-name-template")
	extractCont, _ := flags.GetBool("extract-continue-on-error")
	return ParseOpts{
		InputPath: in, Meanings: meanings, Strict: strict, StrictWarn: strictWarn,
		ExtractDir: extractDir, ExtractTmpl: extractTmpl, ExtractCont: extractCont,
	}
}

// getModifyOpts reads modify-specific flags from the command.
func getModifyOpts(cmd *cobra.Command) ModifyOpts {
	flags := cmd.Flags()
	vj, _ := flags.GetString("verifier-json")
	mode, _ := flags.GetString("mode")
	dryRun, _ := flags.GetBool("dry-run")
	verify, _ := flags.GetBool("verify")
	quiet, _ := flags.GetBool("quiet")
	force, _ := flags.GetBool("force")
	logFile, _ := flags.GetString("log-file")
	return ModifyOpts{
		VerifierJSON: vj, Mode: mode, DryRun: dryRun, Verify: verify,
		Quiet: quiet, Force: force, LogFile: logFile,
	}
}

// resolvedFormat returns the effective output format.
func resolvedFormat(cmd *cobra.Command) OutputFormat {
	g := getGlobalOpts(cmd)
	if g.Format != "" {
		return OutputFormat(g.Format)
	}
	if g.JSON {
		return FormatJSON
	}
	return FormatText
}

// resolveInputPath returns the VDEX file path from --in flag or first positional arg.
func resolveInputPath(cmd *cobra.Command, args []string) (string, error) {
	p := getParseOpts(cmd)
	if p.InputPath != "" {
		return p.InputPath, nil
	}
	if len(args) > 0 {
		return args[0], nil
	}
	return "", fmt.Errorf("input vdex path is required (pass as argument or use --in)")
}
