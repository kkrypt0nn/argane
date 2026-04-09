package reporters

import (
	"fmt"

	"github.com/kkrypt0nn/argane/internal/engine"
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
)

type StdoutReporter struct {
	Policy         []rule.Rule
	ViolationsOnly bool
}

func (rep *StdoutReporter) Print(results []*engine.Result) {
	for _, result := range results {
		for _, rRule := range rep.Policy {
			if vs, failed := result.ByRule()[rRule.ID()]; failed {
				var messages []string
				for _, v := range vs {
					messages = append(messages, fmt.Sprintf("%s (%s)", v.Message, v.Field))
				}
				util.PrintResult(util.StatusFail, rRule.ID(), result.Origin, result.ResourceName, messages)
			} else if !rep.ViolationsOnly {
				util.PrintResult(
					util.StatusPass,
					rRule.ID(),
					result.Origin,
					result.ResourceName,
					nil,
				)
			}
		}
	}
}
