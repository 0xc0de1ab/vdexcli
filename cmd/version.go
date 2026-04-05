package cmd

import (
	"fmt"

	"github.com/0xc0de1ab/vdexcli/internal/model"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print vdexcli version",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		fmt.Printf("vdexcli version %s (%s)\n", model.CLIVersion, model.GitCommit)
		return nil
	},
}
