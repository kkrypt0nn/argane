package helmsdk

import (
	"context"
	"fmt"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/chart/loader"
	"helm.sh/helm/v4/pkg/cli"
	v1 "helm.sh/helm/v4/pkg/release/v1"
)

func RenderChart(
	ctx context.Context,
	settings *cli.EnvSettings,
	chartRef string,
	chartVersion string,
	values map[string]any,
) (string, error) {
	actionConfig, err := initActionConfig(settings)
	if err != nil {
		return "", fmt.Errorf("failed to init action config: %v", err)
	}

	installClient := action.NewInstall(actionConfig)
	installClient.DryRunStrategy = action.DryRunClient
	installClient.ReleaseName = "argane-eval"
	installClient.Namespace = "default"
	installClient.Version = chartVersion
	installClient.IncludeCRDs = false // Maybe later?
	installClient.IsUpgrade = true
	installClient.DependencyUpdate = true

	chartPath, err := installClient.LocateChart(chartRef, settings)
	if err != nil {
		return "", err
	}

	charter, err := loader.Load(chartPath)
	if err != nil {
		return "", err
	}

	releaser, err := installClient.Run(charter, values)
	if err != nil {
		return "", err
	}

	accessor, ok := releaser.(*v1.Release)
	if !ok {
		return "", fmt.Errorf("unexpected release type: %T", releaser)
	}

	return accessor.Manifest, nil
}
