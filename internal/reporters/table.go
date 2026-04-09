package reporters

import (
	"os"
	"text/tabwriter"

	"github.com/kkrypt0nn/argane/internal/engine"
	"github.com/kkrypt0nn/argane/internal/rule"
)

type TableReporter struct {
	Policy         []rule.Rule
	ViolationsOnly bool
}

func (rep *TableReporter) Print(results []*engine.Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = w.Write([]byte("RESOURCE\tRULE\tSTATUS\n"))
	for _, result := range results {
		for _, rRule := range rep.Policy {
			status := "PASS"
			if _, failed := result.ByRule()[rRule.ID()]; failed {
				status = "FAIL"
			} else if rep.ViolationsOnly {
				continue
			}
			_, _ = w.Write([]byte(result.ResourceName + "\t" + rRule.ID() + "\t" + status + "\n"))
		}
	}
	_ = w.Flush()
}
