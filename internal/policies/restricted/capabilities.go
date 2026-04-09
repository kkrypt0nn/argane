package restricted

import (
	"slices"

	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type CapabilitiesRule struct{}

func (r CapabilitiesRule) ID() string {
	return "pss:restricted:capabilities"
}

func (r CapabilitiesRule) MarkdownDescription() string {
	return `Ensures that containers drop all capabilities except for the explicitly allowed capability.

Allowed values:

- ` + "`drop: ALL`" + `
- ` + "`add: NET_BIND_SERVICE`" + ` or undefined/nil

The rule checks the following fields:

- ` + "`spec.containers[*].securityContext.capabilities.drop`" + `
- ` + "`spec.containers[*].securityContext.capabilities.add`" + `
- ` + "`spec.initContainers[*].securityContext.capabilities.drop`" + `
- ` + "`spec.initContainers[*].securityContext.capabilities.add`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.capabilities.drop`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.capabilities.add`"
}

func (r CapabilitiesRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	if util.IsWindows(podSpec.OS) {
		return nil, nil
	}

	var violations []rule.Violation

	r.checkContainers(&violations, podSpec.Containers, "spec.containers")
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers")
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers")

	return violations, nil
}

func (r CapabilitiesRule) check(base string, caps *corev1.Capabilities) []rule.Violation {
	var violations []rule.Violation

	if caps == nil {
		violations = append(violations, rule.Violation{
			RuleID:  r.ID(),
			Message: "All capabilities must be dropped",
			Field:   base + ".drop",
		})
		return violations
	}

	if !slices.Contains(caps.Drop, "ALL") {
		violations = append(violations, rule.Violation{
			RuleID:  r.ID(),
			Message: "All capabilities must be dropped",
			Field:   base + ".drop",
		})
	}

	for _, cap := range caps.Add {
		if cap != "NET_BIND_SERVICE" {
			violations = append(violations, rule.Violation{
				RuleID:  r.ID(),
				Message: "Only NET_BIND_SERVICE capability may be added",
				Field:   base + ".add",
			})
		}
	}

	return violations
}

func (r CapabilitiesRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
) {
	for i, c := range containers {
		path := util.FieldPath(base, i, "securityContext.capabilities")

		if c.SecurityContext == nil {
			util.AppendViolations(violations, []rule.Violation{
				{
					RuleID:  r.ID(),
					Message: "Containers must drop ALL capabilities",
					Field:   path + ".drop",
				},
			})
			continue
		}

		util.AppendViolations(
			violations,
			r.check(
				path,
				c.SecurityContext.Capabilities,
			),
		)
	}
}

func (r CapabilitiesRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
) {
	for i, c := range containers {
		path := util.FieldPath(base, i, "securityContext.capabilities")

		if c.SecurityContext == nil {
			util.AppendViolations(violations, []rule.Violation{
				{
					RuleID:  r.ID(),
					Message: "Containers must drop ALL capabilities",
					Field:   path + ".drop",
				},
			})
			continue
		}

		util.AppendViolations(
			violations,
			r.check(
				path,
				c.SecurityContext.Capabilities,
			),
		)
	}
}
