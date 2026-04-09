package engine

import (
	"github.com/kkrypt0nn/argane/internal/rule"
)

type Result struct {
	Origin       string
	ResourceName string
	Violations   []rule.Violation
}

func (r Result) IsClean() bool {
	return len(r.Violations) == 0
}

func (r Result) ByRule() map[string][]rule.Violation {
	out := make(map[string][]rule.Violation)

	for _, v := range r.Violations {
		out[v.RuleID] = append(out[v.RuleID], v)
	}

	return out
}
