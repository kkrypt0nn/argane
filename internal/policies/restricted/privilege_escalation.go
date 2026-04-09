package restricted

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type PrivilegeEscalationRule struct{}

func (r PrivilegeEscalationRule) ID() string {
	return "pss:restricted:privilege_escalation"
}

func (r PrivilegeEscalationRule) MarkdownDescription() string {
	return `Ensures that containers do not allow privilege escalation.

Allowed values:

- ` + "`false`" + `

The rule checks the following fields:

- ` + "`spec.containers[*].securityContext.allowPrivilegeEscalation`" + `
- ` + "`spec.initContainers[*].securityContext.allowPrivilegeEscalation`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.allowPrivilegeEscalation`"
}

func (r PrivilegeEscalationRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	if util.IsWindows(podSpec.OS) {
		return nil, nil
	}

	var violations []rule.Violation

	r.checkContainers(&violations, podSpec.Containers, "spec.containers")
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers")
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers")

	return violations, nil
}

func (r PrivilegeEscalationRule) check(field string, allowPrivilegeEscalation *bool) *rule.Violation {
	if allowPrivilegeEscalation == nil || *allowPrivilegeEscalation {
		return &rule.Violation{
			RuleID:  r.ID(),
			Message: "allowPrivilegeEscalation must be false",
			Field:   field,
		}
	}

	return nil
}

func (r PrivilegeEscalationRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
) {
	for i, c := range containers {
		path := util.FieldPath(base, i, "securityContext.allowPrivilegeEscalation")

		if c.SecurityContext == nil {
			util.AppendViolations(violations, []rule.Violation{
				{
					RuleID:  r.ID(),
					Message: "allowPrivilegeEscalation must be false",
					Field:   path,
				},
			})
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				path,
				c.SecurityContext.AllowPrivilegeEscalation,
			),
		)
	}
}

func (r PrivilegeEscalationRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
) {
	for i, c := range containers {
		path := util.FieldPath(base, i, "securityContext.allowPrivilegeEscalation")

		if c.SecurityContext == nil {
			util.AppendViolations(violations, []rule.Violation{
				{
					RuleID:  r.ID(),
					Message: "allowPrivilegeEscalation must be false",
					Field:   path,
				},
			})
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				path,
				c.SecurityContext.AllowPrivilegeEscalation,
			),
		)
	}
}
