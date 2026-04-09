package commands

import (
	"fmt"
	"os"

	"github.com/kkrypt0nn/argane/internal/decoder"
	"github.com/kkrypt0nn/argane/internal/engine"
	"github.com/kkrypt0nn/argane/internal/policies"
	"github.com/kkrypt0nn/argane/internal/reporters"
	"github.com/kkrypt0nn/argane/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	evalCmd.AddCommand(evalFileCmd)
}

var evalFileCmd = &cobra.Command{
	Use:   "file <path>",
	Short: "Evaluate a pod-compatible spec file against the Kubernetes Pod Security Standards.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		file := args[0]

		selectedPolicy := policies.GetPolicyFromChoice(evalOptPolicy, evalOptDisabledRules)
		if selectedPolicy == nil {
			util.LogError("Invalid policy. Must be 'baseline', 'restricted' or a Y(A)ML file")
			os.Exit(1)
		}

		data, err := os.ReadFile(file)
		if err != nil {
			util.LogError(fmt.Sprintf("Failed to read file: %v", err))
			os.Exit(1)
		}

		specs, err := decoder.DecodePodSpecs(data)
		if err != nil {
			util.LogError(fmt.Sprintf("Failed to decode pod specs: %v", err))
			os.Exit(1)
		}

		e := engine.New(selectedPolicy)
		reporter := reporters.NewReporter(evalOptOutput, selectedPolicy, evalOptViolationsOnly)

		var allResults []*engine.Result
		exitCode := 0

		for _, spec := range specs {
			result := e.Evaluate(spec, file)
			allResults = append(allResults, result)

			if !result.IsClean() {
				exitCode = 1
			}
		}

		reporter.Print(allResults)
		os.Exit(exitCode)
	},
}
