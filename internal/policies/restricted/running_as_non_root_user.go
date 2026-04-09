package restricted

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type RunningAsNonRootUserRule struct{}

func (r RunningAsNonRootUserRule) ID() string {
	return "pss:restricted:running_as_non_root_user"
}

func (r RunningAsNonRootUserRule) MarkdownDescription() string {
	return `Ensures that containers do not run as the root user.

Allowed values:

- any non-zero value
- undefined/nil

The rule checks the following fields:

- ` + "`spec.securityContext.runAsUser`" + `
- ` + "`spec.containers[*].securityContext.runAsUser`" + `
- ` + "`spec.initContainers[*].securityContext.runAsUser`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.runAsUser`"
}

func (r RunningAsNonRootUserRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	if podSpec.SecurityContext != nil {
		util.AppendIfViolation(
			&violations,
			r.check("spec.securityContext.runAsUser", podSpec.SecurityContext.RunAsUser),
		)
	}

	r.checkContainers(&violations, podSpec.Containers, "spec.containers")
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers")
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers")

	return violations, nil
}

func (r RunningAsNonRootUserRule) check(field string, runAsNonRootUser *int64) *rule.Violation {
	if runAsNonRootUser == nil || *runAsNonRootUser != 0 {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: "runAsUser must be unset or any non-zero value",
		Field:   field,
	}
}

func (r RunningAsNonRootUserRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil {
			continue
		}
		util.AppendIfViolation(
			violations,
			r.check(util.FieldPath(base, i, "securityContext.runAsUser"), c.SecurityContext.RunAsUser),
		)
	}
}

func (r RunningAsNonRootUserRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil {
			continue
		}
		util.AppendIfViolation(
			violations,
			r.check(util.FieldPath(base, i, "securityContext.runAsUser"), c.SecurityContext.RunAsUser),
		)
	}
}
