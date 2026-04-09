package commands

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "argane",
	Short: "Argane evaluates Kubernetes pod specs against the Kubernetes Pod Security Standards.",
}

func NewArganeCommand() *cobra.Command {
	return rootCmd
}

func Execute() {
	if err := NewArganeCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {}
