package helmsdk

import (
	"os"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cli"
)

var helmDriver string = os.Getenv("HELM_DRIVER")

func initActionConfig(settings *cli.EnvSettings) (*action.Configuration, error) {
	return initActionConfigList(settings, false)
}

func initActionConfigList(settings *cli.EnvSettings, allNamespaces bool) (*action.Configuration, error) {
	actionConfig := new(action.Configuration)
	namespace := func() string {
		if allNamespaces {
			return ""
		}
		return settings.Namespace()
	}()
	if err := actionConfig.Init(
		settings.RESTClientGetter(),
		namespace,
		helmDriver); err != nil {
		return nil, err
	}
	return actionConfig, nil
}
