package restricted

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type RunningAsNonRootRule struct{}

func (r RunningAsNonRootRule) ID() string {
	return "pss:restricted:running_as_non_root"
}

func (r RunningAsNonRootRule) MarkdownDescription() string {
	return `Ensures that containers run as a non-root user.

Allowed values:

- ` + "`true`" + `
- undefined/nil (inherits from Pod securityContext)

The rule checks the following fields:

- ` + "`spec.securityContext.runAsNonRoot`" + `
- ` + "`spec.containers[*].securityContext.runAsNonRoot`" + `
- ` + "`spec.initContainers[*].securityContext.runAsNonRoot`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.runAsNonRoot`"
}

func (r RunningAsNonRootRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	var podRunAsNonRoot *bool
	if sc := podSpec.SecurityContext; sc != nil {
		podRunAsNonRoot = sc.RunAsNonRoot
	}

	r.checkContainers(&violations, podSpec.Containers, "spec.containers", podRunAsNonRoot)
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers", podRunAsNonRoot)
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers", podRunAsNonRoot)

	return violations, nil
}

func (r RunningAsNonRootRule) check(field string, runAsNonRoot *bool, podDefault *bool) *rule.Violation {
	if runAsNonRoot == nil {
		if podDefault != nil && *podDefault {
			return nil
		}
		return &rule.Violation{
			RuleID:  r.ID(),
			Message: "runAsNonRoot must be true",
			Field:   field,
		}
	}

	if *runAsNonRoot {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: "runAsNonRoot must be true",
		Field:   field,
	}
}

func (r RunningAsNonRootRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
	podDefault *bool,
) {
	for i, c := range containers {
		var runAsNonRoot *bool
		if sc := c.SecurityContext; sc != nil {
			runAsNonRoot = sc.RunAsNonRoot
		}
		util.AppendIfViolation(
			violations,
			r.check(util.FieldPath(base, i, "securityContext.runAsNonRoot"), runAsNonRoot, podDefault),
		)
	}
}

func (r RunningAsNonRootRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
	podDefault *bool,
) {
	for i, c := range containers {
		var runAsNonRoot *bool
		if sc := c.SecurityContext; sc != nil {
			runAsNonRoot = sc.RunAsNonRoot
		}
		util.AppendIfViolation(
			violations,
			r.check(util.FieldPath(base, i, "securityContext.runAsNonRoot"), runAsNonRoot, podDefault),
		)
	}
}
