package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/0xc0de1ab/vdexcli/internal/parser"
	"github.com/0xc0de1ab/vdexcli/internal/presenter"
)

var diffCmd = &cobra.Command{
	Use:   "diff <file-a.vdex> <file-b.vdex>",
	Short: "Compare two VDEX files and show structural differences",
	Long: `Compare two VDEX files section by section and report differences
in headers, section sizes, checksums, DEX files, verifier dependencies,
and type lookup tables.

Exit code 0 if identical, 1 if different.`,
	Example: `  vdexcli diff before.vdex after.vdex
  vdexcli diff --json before.vdex after.vdex
  vdexcli diff --format summary before.vdex after.vdex`,
	Args: cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		g := getGlobalOpts(cmd)
		return presenter.ValidateFormat(g.Format)
	},
	RunE: runDiff,
}

func init() {
	rootCmd.AddCommand(diffCmd)
}

func runDiff(cmd *cobra.Command, args []string) error {
	pathA, pathB := args[0], args[1]
	p := getParseOpts(cmd)

	reportA, _, errA := parser.ParseVdex(pathA, p.Meanings)
	if errA != nil && reportA == nil {
		return fmt.Errorf("parse %s: %w", pathA, errA)
	}
	reportB, _, errB := parser.ParseVdex(pathB, p.Meanings)
	if errB != nil && reportB == nil {
		return fmt.Errorf("parse %s: %w", pathB, errB)
	}

	diff := parser.Diff(reportA, reportB)

	w := os.Stdout
	switch resolvedFormat(cmd) {
	case FormatJSON:
		if err := presenter.WriteJSON(w, diff); err != nil {
			return err
		}
	case FormatJSONL:
		if err := presenter.WriteJSONL(w, diff); err != nil {
			return err
		}
	case FormatSummary:
		status := "identical"
		if !diff.Summary.Identical {
			status = "different"
		}
		warnA := len(reportA.Warnings)
		warnB := len(reportB.Warnings)
		fmt.Fprintf(w, "status=%s file_a=%s file_b=%s size_a=%d size_b=%d sections=%d checksums=%d dexes=%d verifier=%d typelookup=%d warnings_a=%d warnings_b=%d\n",
			status, diff.FileA, diff.FileB, diff.SizeA, diff.SizeB,
			diff.Summary.SectionsChanged, diff.Summary.ChecksumsChanged,
			diff.Summary.DexFilesChanged, diff.Summary.VerifierChanged,
			diff.Summary.TypeLookupChanged, warnA, warnB)
	default:
		presenter.WriteDiffText(w, diff)
	}

	if !diff.Summary.Identical {
		return fmt.Errorf("files differ")
	}
	return nil
}
