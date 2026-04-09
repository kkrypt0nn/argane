package tests

import (
	"path/filepath"
	"testing"

	"github.com/kkrypt0nn/argane/internal/engine"
	"github.com/kkrypt0nn/argane/internal/policies"
	"github.com/kkrypt0nn/argane/internal/rule"
)

func TestBaselineRulesValid(t *testing.T) {
	rules := policies.BaselinePolicy([]string{})

	for _, r := range rules {
		t.Run(r.ID(), func(t *testing.T) {
			policy, filename := ruleIDToFilename(r.ID())
			path := filepath.Join("../../../fixtures", policy, "valid", filename)

			specs := loadPodSpecs(t, path)
			e := engine.New([]rule.Rule{r})

			for i, spec := range specs {
				result := e.Evaluate(spec, "")
				if _, failed := result.ByRule()[r.ID()]; failed {
					t.Fatalf(
						"expected rule %s to PASS for %s[%d]",
						r.ID(),
						filename,
						i,
					)
				}
			}
		})
	}
}

func TestBaselineRulesInvalid(t *testing.T) {
	rules := policies.BaselinePolicy([]string{})
	for _, r := range rules {
		t.Run(r.ID(), func(t *testing.T) {
			policy, filename := ruleIDToFilename(r.ID())
			path := filepath.Join("../../../fixtures", policy, "invalid", filename)

			specs := loadPodSpecs(t, path)
			e := engine.New([]rule.Rule{r})

			failed := false
			for _, spec := range specs {
				result := e.Evaluate(spec, "")
				if _, ok := result.ByRule()[r.ID()]; ok {
					failed = true
					break
				}
			}

			if !failed {
				t.Fatalf(
					"expected rule %s to FAIL for %s, but it passed",
					r.ID(),
					filename,
				)
			}
		})
	}
}
