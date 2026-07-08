package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/0xc0de1ab/vdexcli/internal/parser"
	"github.com/0xc0de1ab/vdexcli/internal/presenter"
)

var offsetStr string

var explainCmd = &cobra.Command{
	Use:   "explain [flags] <file.vdex>",
	Short: "Explain VDEX byte-level structure with primitive fields",
	Long: `Explain a VDEX file by parsing it down to primitive fields, mapping every byte.
Displays an aligned, color-coded hex dump table indicating the type, path, and parsed value of each field.
Supports querying a specific offset, and outputting to JSON.`,
	Example: `  vdexcli explain app.vdex
  vdexcli explain --offset 0x3c app.vdex
  vdexcli explain --format json app.vdex`,
	Args: cobra.MaximumNArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if _, err := resolveInputPath(cmd, args); err != nil {
			return err
		}
		g := getGlobalOpts(cmd)
		return presenter.ValidateFormat(g.Format)
	},
	RunE: runExplain,
}

func init() {
	explainCmd.Flags().StringVar(&offsetStr, "offset", "", "Start offset of the primitive field to query (supports hex with 0x)")
}

func runExplain(cmd *cobra.Command, args []string) error {
	path, err := resolveInputPath(cmd, args)
	if err != nil {
		return err
	}

	pm, err := parser.ExplainVdex(path)
	if err != nil {
		return err
	}

	var offsetFilter *uint32
	if offsetStr != "" {
		val, err := strconv.ParseUint(offsetStr, 0, 32)
		if err != nil {
			return fmt.Errorf("invalid offset value %q: %w", offsetStr, err)
		}
		uVal := uint32(val)
		offsetFilter = &uVal
	}

	format := string(resolvedFormat(cmd))
	return presenter.WriteExplain(os.Stdout, pm, format, offsetFilter)
}
