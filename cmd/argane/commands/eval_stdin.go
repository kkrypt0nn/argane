package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/kkrypt0nn/argane/internal/decoder"
	"github.com/kkrypt0nn/argane/internal/engine"
	"github.com/kkrypt0nn/argane/internal/policies"
	"github.com/kkrypt0nn/argane/internal/reporters"
	"github.com/kkrypt0nn/argane/internal/util"
	"github.com/spf13/cobra"
)

func init() {
	evalCmd.AddCommand(evalStdinCmd)
}

var evalStdinCmd = &cobra.Command{
	Use:   "stdin",
	Short: "Evaluate a pod-compatible spec YAML from stdin against the Kubernetes Pod Security Standards.",
	Run: func(cmd *cobra.Command, args []string) {
		stdinInfo, err := os.Stdin.Stat()
		if err != nil {
			util.LogError(fmt.Sprintf("Failed to stat stdin: %v", err))
			os.Exit(1)
		}
		if stdinInfo.Mode()&os.ModeCharDevice != 0 {
			util.LogError("No input in stdin")
			os.Exit(1)
		}

		selectedPolicy := policies.GetPolicyFromChoice(evalOptPolicy, evalOptDisabledRules)
		if selectedPolicy == nil {
			util.LogError("Invalid policy. Must be 'baseline', 'restricted' or a Y(A)ML file")
			os.Exit(1)
		}

		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			util.LogError(fmt.Sprintf("Failed to read stdin: %v", err))
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
			result := e.Evaluate(spec, "stdin")
			allResults = append(allResults, result)

			if !result.IsClean() {
				exitCode = 1
			}
		}

		reporter.Print(allResults)
		os.Exit(exitCode)
	},
}
