package engine

import (
	"github.com/kkrypt0nn/argane/internal/decoder"
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
)

type Engine struct {
	Rules []rule.Rule
}

func New(rules []rule.Rule) *Engine {
	return &Engine{
		Rules: rules,
	}
}

func (e *Engine) Evaluate(spec *decoder.PodSpecWithMetadata, origin string) *Result {
	var violations []rule.Violation

	for _, r := range e.Rules {
		results, err := r.Evaluate(spec.Spec)
		if err != nil {
			util.LogError(err.Error())
			continue
		}
		violations = append(violations, results...)
	}

	kind := spec.Kind
	if kind == "" {
		kind = "<unknown>"
	}

	name := spec.Name
	if name == "" {
		name = "<unnamed>"
	}

	return &Result{
		Origin:       origin,
		ResourceName: kind + "/" + name,
		Violations:   violations,
	}
}
