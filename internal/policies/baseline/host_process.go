package baseline

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type HostProcessRule struct{}

func (r HostProcessRule) ID() string {
	return "pss:baseline:host_process"
}

func (r HostProcessRule) MarkdownDescription() string {
	return `Ensures that Windows containers do not enable HostProcess.

Allowed values:

- undefined/nil
- ` + "`false`" + `

The rule checks the following fields:

- ` + "`spec.securityContext.windowsOptions.hostProcess`" + `
- ` + "`spec.containers[*].securityContext.windowsOptions.hostProcess`" + `
- ` + "`spec.initContainers[*].securityContext.windowsOptions.hostProcess`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.windowsOptions.hostProcess`"
}

func (r HostProcessRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	if podSpec.SecurityContext != nil && podSpec.SecurityContext.WindowsOptions != nil {
		util.AppendIfViolation(
			&violations,
			r.check(
				"spec.securityContext.windowsOptions.hostProcess",
				podSpec.SecurityContext.WindowsOptions.HostProcess,
			),
		)
	}

	r.checkContainers(&violations, podSpec.Containers, "spec.containers")
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers")
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers")

	return violations, nil
}

func (r HostProcessRule) check(field string, hostProcess *bool) *rule.Violation {
	if hostProcess == nil || !*hostProcess {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: "hostProcess must be unset or false",
		Field:   field,
	}
}

func (r HostProcessRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.WindowsOptions == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.windowsOptions.hostProcess"),
				c.SecurityContext.WindowsOptions.HostProcess,
			),
		)
	}
}

func (r HostProcessRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.WindowsOptions == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.windowsOptions.hostProcess"),
				c.SecurityContext.WindowsOptions.HostProcess,
			),
		)
	}
}
