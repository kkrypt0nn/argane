package baseline

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type ProcMountTypeRule struct{}

func (r ProcMountTypeRule) ID() string {
	return "pss:baseline:proc_mount_type"
}

func (r ProcMountTypeRule) MarkdownDescription() string {
	return `Ensures that containers use the default /proc mount type.

Allowed values:

- undefined/nil
- ` + "`Default`" + `

The rule checks the following fields:

- ` + "`spec.containers[*].securityContext.procMount`" + `
- ` + "`spec.initContainers[*].securityContext.procMount`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.procMount`"
}

func (r ProcMountTypeRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	r.checkContainers(&violations, podSpec.Containers, "spec.containers")
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers")
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers")

	return violations, nil
}

func (r ProcMountTypeRule) check(field string, procMount *corev1.ProcMountType) *rule.Violation {
	if procMount == nil || *procMount == "Default" {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: "procMount must be unset or Default",
		Field:   field,
	}
}

func (r ProcMountTypeRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.ProcMount == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.procMount"),
				c.SecurityContext.ProcMount,
			),
		)
	}
}

func (r ProcMountTypeRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.ProcMount == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.procMount"),
				c.SecurityContext.ProcMount,
			),
		)
	}
}
