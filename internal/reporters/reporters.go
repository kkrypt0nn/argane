package reporters

import (
	"os"

	"github.com/kkrypt0nn/argane/internal/engine"
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
)

type Reporter interface {
	Print(results []*engine.Result)
}

func NewReporter(output string, policy []rule.Rule, violationsOnly bool) Reporter {
	switch output {
	case "stdout":
		return &StdoutReporter{Policy: policy, ViolationsOnly: violationsOnly}
	case "json":
		return &JSONReporter{Policy: policy, ViolationsOnly: violationsOnly}
	case "table":
		return &TableReporter{Policy: policy, ViolationsOnly: violationsOnly}
	default:
		util.LogError("Invalid output format. Must be 'stdout', 'json' or 'table'")
		os.Exit(1)
		return nil // For some reason it needs that, so here you go
	}
}
