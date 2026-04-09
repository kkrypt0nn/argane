package baseline

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type HostPortsRule struct{}

func (r HostPortsRule) ID() string {
	return "pss:baseline:host_ports"
}

func (r HostPortsRule) MarkdownDescription() string {
	return `Ensures that containers do not bind ports directly on the host.

Allowed values:

- undefined/nil
- ` + "`0`" + `

The rule checks the following fields:

- ` + "`spec.containers[*].ports[*].hostPort`" + `
- ` + "`spec.initContainers[*].ports[*].hostPort`" + `
- ` + "`spec.ephemeralContainers[*].ports[*].hostPort`"
}

func (r HostPortsRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	r.checkContainers(&violations, podSpec.Containers, "spec.containers")
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers")
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers")

	return violations, nil
}

func (r HostPortsRule) check(fieldPrefix string, ports []corev1.ContainerPort) *rule.Violation {
	for i, p := range ports {
		if p.HostPort != 0 {
			return &rule.Violation{
				RuleID:  r.ID(),
				Message: "hostPort must be unset or 0",
				Field:   util.FieldPath(fieldPrefix, i, "hostPort"),
			}
		}
	}

	return nil
}

func (r HostPortsRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
) {
	for i, c := range containers {
		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "ports"),
				c.Ports,
			),
		)
	}
}

func (r HostPortsRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
) {
	for i, c := range containers {
		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "ports"),
				c.Ports,
			),
		)
	}
}
