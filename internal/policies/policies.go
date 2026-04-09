package policies

import (
	"os"
	"strings"

	"github.com/kkrypt0nn/argane/internal/policies/baseline"
	"github.com/kkrypt0nn/argane/internal/policies/restricted"
	"github.com/kkrypt0nn/argane/internal/rule"

	"sigs.k8s.io/yaml"
)

func GetPolicyFromChoice(choice string, disabledRules []string) []rule.Rule {
	switch choice {
	case "baseline":
		return BaselinePolicy(disabledRules)
	case "restricted":
		return RestrictedPolicy(disabledRules)
	default:
		if strings.HasSuffix(choice, ".yaml") || strings.HasSuffix(choice, ".yml") {
			customPolicy, err := ParseCustomPolicy(choice)
			if err != nil {
				return nil
			}
			return customPolicy.GetRules(disabledRules)
		}
		return nil
	}
}

func ParseCustomPolicy(filePath string) (*CustomPolicy, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var customPolicy CustomPolicy
	if err := yaml.Unmarshal(file, &customPolicy); err != nil {
		return nil, err
	}

	return &customPolicy, nil
}

func BaselinePolicy(disabledIDs []string) []rule.Rule {
	baselineRules := []rule.Rule{
		baseline.AppArmorRule{},
		baseline.CapabilitiesRule{},
		baseline.HostNamespacesRule{},
		baseline.HostPortsRule{},
		baseline.HostProbesRule{},
		baseline.HostProcessRule{},
		baseline.HostpathVolumesRule{},
		baseline.PrivilegedContainersRule{},
		baseline.ProcMountTypeRule{},
		baseline.SeccompRule{},
		baseline.SELinuxRule{},
		baseline.SysctlsRule{},
	}
	return filterRules(baselineRules, disabledIDs)
}

func RestrictedPolicy(disabledIDs []string) []rule.Rule {
	restrictedRules := append(
		BaselinePolicy(disabledIDs),
		restricted.CapabilitiesRule{},
		restricted.PrivilegeEscalationRule{},
		restricted.RunningAsNonRootRule{},
		restricted.RunningAsNonRootUserRule{},
		restricted.SeccompRule{},
		restricted.VolumeTypesRule{},
	)
	return filterRules(restrictedRules, disabledIDs)
}

func filterRules(rules []rule.Rule, disabledIDs []string) []rule.Rule {
	if len(disabledIDs) == 0 {
		return rules
	}

	disabled := make(map[string]struct{}, len(disabledIDs))
	for _, id := range disabledIDs {
		disabled[id] = struct{}{}
	}

	filtered := make([]rule.Rule, 0, len(rules))
	for _, r := range rules {
		if _, found := disabled[r.ID()]; !found {
			filtered = append(filtered, r)
		}
	}

	return filtered
}
