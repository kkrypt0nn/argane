package commands

import (
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(NewCompletionCmd())
}

func NewCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion",
		Short: "Generate the autocompletion script for argane for the specified shell.",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "bash",
		Short: "Generate the autocompletion script for the bash shell.",
		Run: func(cmd *cobra.Command, args []string) {
			_ = rootCmd.GenBashCompletion(os.Stdout)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "fish",
		Short: "Generate the autocompletion script for the fish shell.",
		Run: func(cmd *cobra.Command, args []string) {
			_ = rootCmd.GenFishCompletion(os.Stdout, true)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "powershell",
		Short: "Generate the autocompletion script for powershell.",
		Run: func(cmd *cobra.Command, args []string) {
			_ = rootCmd.GenPowerShellCompletion(os.Stdout)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "zsh",
		Short: "Generate the autocompletion script for the zsh shell.",
		Run: func(cmd *cobra.Command, args []string) {
			_ = rootCmd.GenZshCompletion(os.Stdout)
		},
	})

	return cmd
}
