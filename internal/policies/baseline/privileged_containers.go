package baseline

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type PrivilegedContainersRule struct{}

func (r PrivilegedContainersRule) ID() string {
	return "pss:baseline:privileged_containers"
}

func (r PrivilegedContainersRule) MarkdownDescription() string {
	return `Ensures that containers do not run in privileged mode.

Allowed values:

- undefined/nil
- ` + "`false`" + `

The rule checks the following fields:

- ` + "`spec.containers[*].securityContext.privileged`" + `
- ` + "`spec.initContainers[*].securityContext.privileged`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.privileged`"
}

func (r PrivilegedContainersRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	r.checkContainers(&violations, podSpec.Containers, "spec.containers")
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers")
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers")

	return violations, nil
}

func (r PrivilegedContainersRule) check(field string, privileged *bool) *rule.Violation {
	if privileged == nil || !*privileged {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: "privileged must be unset or false",
		Field:   field,
	}
}

func (r PrivilegedContainersRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.Privileged == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.privileged"),
				c.SecurityContext.Privileged,
			),
		)
	}
}

func (r PrivilegedContainersRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.Privileged == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.privileged"),
				c.SecurityContext.Privileged,
			),
		)
	}
}
