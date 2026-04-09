package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/kkrypt0nn/argane/internal/decoder"
	"github.com/kkrypt0nn/argane/internal/engine"
	"github.com/kkrypt0nn/argane/internal/helmsdk"
	"github.com/kkrypt0nn/argane/internal/policies"
	"github.com/kkrypt0nn/argane/internal/reporters"
	"github.com/kkrypt0nn/argane/internal/util"
	"github.com/spf13/cobra"
	"helm.sh/helm/v4/pkg/cli"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

// https://helm.sh/docs/sdk/gosdk

var (
	values  string
	version string
)

func init() {
	evalCmd.AddCommand(evalHelmCmd)

	evalHelmCmd.PersistentFlags().StringVarP(
		&values,
		"values",
		"v",
		"",
		"The values of the chart",
	)

	evalHelmCmd.PersistentFlags().StringVar(
		&version,
		"version",
		"",
		"The version of the chart",
	)
}

var evalHelmCmd = &cobra.Command{
	Use:   "helm <repository>/<chart>",
	Short: "Render a chart with the given values and evaluates against the Kubernetes Pod Security Standards.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		parts := strings.SplitN(args[0], "/", 2)
		if len(parts) != 2 {
			util.LogError("Invalid input, expected format <repository>/<chart>")
			os.Exit(1)
		}
		chartRef := fmt.Sprintf("%s/%s", parts[0], parts[1])

		selectedPolicy := policies.GetPolicyFromChoice(evalOptPolicy, evalOptDisabledRules)
		if selectedPolicy == nil {
			util.LogError("Invalid policy. Must be 'baseline', 'restricted' or a Y(A)ML file")
			os.Exit(1)
		}

		valuesMap := map[string]any{}
		if values != "" {
			data, err := os.ReadFile(values)
			if err != nil {
				util.LogError(fmt.Sprintf("Failed to read values file: %v", err))
				os.Exit(1)
			}
			if err := k8syaml.Unmarshal(data, &valuesMap); err != nil {
				util.LogError(fmt.Sprintf("Failed to parse values file: %v", err))
				os.Exit(1)
			}
		}

		yamlManifests, err := helmsdk.RenderChart(cmd.Context(), cli.New(), chartRef, version, valuesMap)
		if err != nil {
			util.LogError(fmt.Sprintf("Failed to render chart: %v", err))
			os.Exit(1)
		}

		specs, err := decoder.DecodePodSpecs([]byte(yamlManifests))
		if err != nil {
			util.LogError(fmt.Sprintf("Failed to decode pod specs: %v", err))
			os.Exit(1)
		}

		e := engine.New(selectedPolicy)
		reporter := reporters.NewReporter(evalOptOutput, selectedPolicy, evalOptViolationsOnly)

		var allResults []*engine.Result
		exitCode := 0

		for i, spec := range specs {
			resourceName := chartRef
			if len(specs) > 1 {
				resourceName = fmt.Sprintf("%s[%d]", chartRef, i)
			}

			result := e.Evaluate(spec, resourceName)
			allResults = append(allResults, result)

			if !result.IsClean() {
				exitCode = 1
			}
		}

		reporter.Print(allResults)
		os.Exit(exitCode)
	},
}
