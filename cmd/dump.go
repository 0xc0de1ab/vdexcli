package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/0xc0de1ab/vdexcli/internal/parser"
	"github.com/0xc0de1ab/vdexcli/internal/presenter"
)

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Print human-readable descriptions of all parsed fields",
	Long: `Dump the meaning of every field that vdexcli emits in parse output.
Useful for understanding the JSON schema without a real VDEX file.`,
	Example: `  vdexcli dump
  vdexcli dump --json
  vdexcli dump --format jsonl`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		m := parser.NewParserMeanings()
		switch resolvedFormat(cmd) {
		case FormatJSON:
			return presenter.WriteJSON(os.Stdout, m)
		case FormatJSONL:
			return presenter.WriteJSONL(os.Stdout, m)
		default:
			presenter.PrintTextMeanings(m)
			return nil
		}
	},
}
