package commands

import (
	"fmt"

	"github.com/kkrypt0nn/argane/internal/buildinfo"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of Argane.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s %s\n", buildinfo.ApplicationName, buildinfo.Version)
		fmt.Printf("  commit:    %s\n", buildinfo.GitCommit)
		fmt.Printf("  built:     %s\n", buildinfo.BuildDate)
		fmt.Printf("  go:        %s\n", buildinfo.GoVersion)
		fmt.Printf("  compiler:  %s\n", buildinfo.Compiler)
		fmt.Printf("  platform:  %s\n", buildinfo.Platform)
	},
}
