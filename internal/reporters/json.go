package reporters

import (
	"encoding/json"
	"fmt"

	"github.com/kkrypt0nn/argane/internal/engine"
	"github.com/kkrypt0nn/argane/internal/rule"
)

type JSONReporter struct {
	Policy         []rule.Rule
	ViolationsOnly bool
}

type ManifestResult struct {
	Manifest int               `json:"manifest"`
	Rules    []rule.RuleResult `json:"rules"`
}

func (rep *JSONReporter) Print(results []*engine.Result) {
	var out []ManifestResult

	for i, result := range results {
		var rules []rule.RuleResult

		for _, r := range rep.Policy {
			ruleResult := rule.RuleResult{
				RuleID: r.ID(),
			}

			if violations, failed := result.ByRule()[r.ID()]; failed {
				ruleResult.Passed = false
				for _, v := range violations {
					ruleResult.Details = append(ruleResult.Details, fmt.Sprintf("%s (%s)", v.Message, v.Field))
				}
				rules = append(rules, ruleResult)
			} else if !rep.ViolationsOnly {
				ruleResult.Passed = true
				rules = append(rules, ruleResult)
			}
		}

		out = append(out, ManifestResult{
			Manifest: i,
			Rules:    rules,
		})
	}

	jsonData, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(jsonData))
}
