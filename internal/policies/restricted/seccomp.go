package restricted

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

var allowedSeccompProfileTypes = map[corev1.SeccompProfileType]bool{
	corev1.SeccompProfileTypeRuntimeDefault: true,
	corev1.SeccompProfileTypeLocalhost:      true,
}

type SeccompRule struct{}

func (r SeccompRule) ID() string {
	return "pss:restricted:seccomp"
}

func (r SeccompRule) MarkdownDescription() string {
	return `Ensures that pods use a restricted Seccomp profile.

Allowed values:

- ` + "`RuntimeDefault`" + `
- ` + "`Localhost`" + `

The rule checks the following fields:

- ` + "`spec.securityContext.seccompProfile.type`" + `
- ` + "`spec.containers[*].securityContext.seccompProfile.type`" + `
- ` + "`spec.initContainers[*].securityContext.seccompProfile.type`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.seccompProfile.type`"
}

func (r SeccompRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	if util.IsWindows(podSpec.OS) {
		return nil, nil
	}

	var violations []rule.Violation

	var podProfile *corev1.SeccompProfileType
	if podSpec.SecurityContext != nil && podSpec.SecurityContext.SeccompProfile != nil {
		podProfile = &podSpec.SecurityContext.SeccompProfile.Type
		util.AppendIfViolation(
			&violations,
			r.check("spec.securityContext.seccompProfile.type", podProfile),
		)
	}

	r.checkContainers(&violations, podSpec.Containers, "spec.containers", podProfile)
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers", podProfile)
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers", podProfile)

	return violations, nil
}

func (r SeccompRule) check(field string, profileType *corev1.SeccompProfileType) *rule.Violation {
	if profileType == nil {
		return nil
	}

	if !allowedSeccompProfileTypes[*profileType] {
		return &rule.Violation{
			RuleID:  r.ID(),
			Message: "Seccomp profile type must be one of: RuntimeDefault or Localhost",
			Field:   field,
		}
	}

	return nil
}

func (r SeccompRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
	podProfile *corev1.SeccompProfileType,
) {
	for i, c := range containers {
		var profile *corev1.SeccompProfileType
		if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
			profile = &c.SecurityContext.SeccompProfile.Type
		}

		if v := r.check(util.FieldPath(base, i, "securityContext.seccompProfile.type"), profile); v != nil {
			util.AppendIfViolation(violations, v)
		} else if profile == nil && podProfile == nil {
			util.AppendIfViolation(violations, &rule.Violation{
				RuleID:  r.ID(),
				Message: "Seccomp profile type must be set at either pod or container level",
				Field:   util.FieldPath(base, i, "securityContext.seccompProfile.type"),
			})
		}
	}
}

func (r SeccompRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
	podProfile *corev1.SeccompProfileType,
) {
	for i, c := range containers {
		var profile *corev1.SeccompProfileType
		if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
			profile = &c.SecurityContext.SeccompProfile.Type
		}

		if v := r.check(util.FieldPath(base, i, "securityContext.seccompProfile.type"), profile); v != nil {
			util.AppendIfViolation(violations, v)
		} else if profile == nil && podProfile == nil {
			util.AppendIfViolation(violations, &rule.Violation{
				RuleID:  r.ID(),
				Message: "Seccomp profile type must be set at either pod or ephemeral container level",
				Field:   util.FieldPath(base, i, "securityContext.seccompProfile.type"),
			})
		}
	}
}
