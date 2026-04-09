package util

import "github.com/kkrypt0nn/argane/internal/rule"

func AppendIfViolation(violations *[]rule.Violation, v *rule.Violation) {
	if v != nil {
		*violations = append(*violations, *v)
	}
}

func AppendViolations(violations *[]rule.Violation, v []rule.Violation) {
	if len(v) > 0 {
		*violations = append(*violations, v...)
	}
}
