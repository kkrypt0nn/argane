package baseline

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

var allowedSeccompProfileTypes = map[corev1.SeccompProfileType]bool{
	"":                                      true,
	corev1.SeccompProfileTypeRuntimeDefault: true,
	corev1.SeccompProfileTypeLocalhost:      true,
}

type SeccompRule struct{}

func (r SeccompRule) ID() string {
	return "pss:baseline:seccomp"
}

func (r SeccompRule) MarkdownDescription() string {
	return `Ensures that containers use an allowed Seccomp profile.

Allowed values:

- undefined/nil
- ` + "`RuntimeDefault`" + `
- ` + "`Localhost`" + `

The rule checks the following fields:

- ` + "`spec.securityContext.seccompProfile.type`" + `
- ` + "`spec.containers[*].securityContext.seccompProfile.type`" + `
- ` + "`spec.initContainers[*].securityContext.seccompProfile.type`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.seccompProfile.type`"
}

func (r SeccompRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	if podSpec.SecurityContext != nil && podSpec.SecurityContext.SeccompProfile != nil {
		util.AppendIfViolation(
			&violations,
			r.check(
				"spec.securityContext.seccompProfile.type",
				podSpec.SecurityContext.SeccompProfile.Type,
			),
		)
	}

	r.checkContainers(&violations, podSpec.Containers, "spec.containers")
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers")
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers")

	return violations, nil
}

func (r SeccompRule) check(field string, profileType corev1.SeccompProfileType) *rule.Violation {
	if allowedSeccompProfileTypes[profileType] {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: "Seccomp profile type must be one of: RuntimeDefault, Localhost or unset",
		Field:   field,
	}
}

func (r SeccompRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.SeccompProfile == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.seccompProfile.type"),
				c.SecurityContext.SeccompProfile.Type,
			),
		)
	}
}

func (r SeccompRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.SeccompProfile == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.seccompProfile.type"),
				c.SecurityContext.SeccompProfile.Type,
			),
		)
	}
}
