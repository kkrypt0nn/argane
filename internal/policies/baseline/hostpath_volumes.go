package baseline

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type HostpathVolumesRule struct{}

func (r HostpathVolumesRule) ID() string {
	return "pss:baseline:hostpath_volumes"
}

func (r HostpathVolumesRule) MarkdownDescription() string {
	return `Ensures that Pods do not use HostPath volumes.

Allowed values:

- undefined/nil

The rule checks the following fields:

- ` + "`spec.volumes[*].hostPath`"
}

func (r HostpathVolumesRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	for i, v := range podSpec.Volumes {
		util.AppendIfViolation(
			&violations,
			r.check(
				util.FieldPath("spec.volumes", i, "hostPath"),
				v.HostPath,
			),
		)
	}

	return violations, nil
}

func (r HostpathVolumesRule) check(field string, hostPath *corev1.HostPathVolumeSource) *rule.Violation {
	if hostPath == nil {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: "hostPath volumes must be unset",
		Field:   field,
	}
}
