package commands

import (
	"github.com/spf13/cobra"
)

var (
	evalOptOutput         string
	evalOptPolicy         string
	evalOptViolationsOnly bool
	evalOptDisabledRules  []string
)

func init() {
	rootCmd.AddCommand(evalCmd)

	evalCmd.PersistentFlags().StringVarP(
		&evalOptOutput,
		"output",
		"o",
		"stdout",
		"Output format: stdout or json",
	)
	evalCmd.PersistentFlags().StringVarP(
		&evalOptPolicy,
		"policy",
		"p",
		"restricted",
		"Policy to evaluate against: baseline, restricted or any Y(A)ML file",
	)
	evalCmd.PersistentFlags().BoolVarP(
		&evalOptViolationsOnly,
		"violations",
		"V",
		false,
		"Show only rule violations",
	)
	evalCmd.PersistentFlags().StringSliceVar(
		&evalOptDisabledRules,
		"disable-rule",
		nil,
		"Disable a specific rule by ID (e.g. pss:baseline:apparmor)",
	)
}

var evalCmd = &cobra.Command{
	Use:   "eval",
	Short: "Evaluate Kubernetes resources against Pod Security Standards.",
}
