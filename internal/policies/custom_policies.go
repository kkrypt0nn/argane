package policies

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kkrypt0nn/argane/internal/rule"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/jsonpath"
)

type CustomPolicy struct {
	Extends string       `yaml:"extends,omitempty"`
	Rules   []CustomRule `yaml:"rules"`
}

func (p *CustomPolicy) GetRules(disabledRules []string) []rule.Rule {
	var rules []rule.Rule

	switch p.Extends {
	case "baseline":
		rules = append(rules, BaselinePolicy(disabledRules)...)
	case "restricted":
		rules = append(rules, RestrictedPolicy(disabledRules)...)
	}

	for _, r := range p.Rules {
		rules = append(rules, r)
	}

	return filterRules(rules, disabledRules)
}

type CustomRule struct {
	RuleID        string   `yaml:"id"`
	Path          string   `yaml:"path"`
	AllowedValues []string `yaml:"allowedValues"`
	DeniedValues  []string `yaml:"deniedValues"`
}

func (r CustomRule) ID() string {
	return r.RuleID
}

func (r CustomRule) MarkdownDescription() string {
	return fmt.Sprintf(
		"Custom rule targeting path `%s`",
		r.Path,
	)
}

func (r CustomRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	jsonPath := jsonpath.New(r.RuleID)
	err := jsonPath.Parse(normalizeJSONPath(r.Path))
	if err != nil {
		return nil, err
	}

	results, err := jsonPath.FindResults(podSpec)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}

	var violations []rule.Violation

	for _, result := range results {
		for _, value := range result {
			stringValue := fmt.Sprintf("%v", value.Interface())
			if slices.Contains(r.DeniedValues, stringValue) {
				violations = append(violations, rule.Violation{
					RuleID:  r.RuleID,
					Message: fmt.Sprintf("value '%s' is in deniedValues", value),
					Field:   fmt.Sprintf("spec.%s", r.Path),
				})
				continue
			}
			if len(r.AllowedValues) > 0 && !slices.Contains(r.AllowedValues, stringValue) {
				violations = append(violations, rule.Violation{
					RuleID:  r.RuleID,
					Message: fmt.Sprintf("value '%s' is not in allowedValues", value),
					Field:   fmt.Sprintf("spec.%s", r.Path),
				})
			}
		}
	}

	return violations, nil
}

func normalizeJSONPath(jsonPath string) string {
	if strings.HasPrefix(jsonPath, "{") {
		return jsonPath
	}
	if strings.HasPrefix(jsonPath, ".") {
		return "{" + jsonPath + "}"
	}
	return "{." + jsonPath + "}"
}
