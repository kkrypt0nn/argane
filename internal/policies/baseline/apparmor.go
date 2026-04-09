package baseline

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

var allowedApparmorProfiles = map[corev1.AppArmorProfileType]bool{
	"":                                       true,
	corev1.AppArmorProfileTypeRuntimeDefault: true,
	corev1.AppArmorProfileTypeLocalhost:      true,
}

type AppArmorRule struct{}

func (r AppArmorRule) ID() string {
	return "pss:baseline:apparmor"
}

func (r AppArmorRule) MarkdownDescription() string {
	return `Ensures that containers do not disable or override the default AppArmor confinement with an unsafe profile.

Allowed values:

- undefined/nil
- ` + "`RuntimeDefault`" + `
- ` + "`Localhost`" + `

The rule checks the following fields:

- ` + "`spec.securityContext.appArmorProfile.type`" + `
- ` + "`spec.containers[*].securityContext.appArmorProfile.type`" + `
- ` + "`spec.initContainers[*].securityContext.appArmorProfile.type`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.appArmorProfile.type`"
}

func (r AppArmorRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	if podSpec.SecurityContext != nil && podSpec.SecurityContext.AppArmorProfile != nil {
		util.AppendIfViolation(
			&violations,
			r.check(
				"spec.securityContext.appArmorProfile.type",
				podSpec.SecurityContext.AppArmorProfile.Type,
			),
		)
	}

	r.checkContainers(&violations, podSpec.Containers, "spec.containers")
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers")
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers")

	return violations, nil
}

func (r AppArmorRule) check(field string, profileType corev1.AppArmorProfileType) *rule.Violation {
	if !allowedApparmorProfiles[profileType] {
		return &rule.Violation{
			RuleID:  r.ID(),
			Message: "AppArmor profile type must be RuntimeDefault or Localhost",
			Field:   field,
		}
	}
	return nil
}

func (r AppArmorRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.AppArmorProfile == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.appArmorProfile.type"),
				c.SecurityContext.AppArmorProfile.Type,
			),
		)
	}
}

func (r AppArmorRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.AppArmorProfile == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.appArmorProfile.type"),
				c.SecurityContext.AppArmorProfile.Type,
			),
		)
	}
}
