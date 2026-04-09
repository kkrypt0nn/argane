package baseline

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type HostProbesRule struct{}

func (r HostProbesRule) ID() string {
	return "pss:baseline:host_probes"
}

func (r HostProbesRule) MarkdownDescription() string {
	return `Ensures that container probes and lifecycle hooks do not target the host network directly.

Allowed values:

- undefined/nil
- ` + "`\"\"`" + `

The rule checks the following fields:

- ` + "`spec.containers[*].livenessProbe.httpGet.host`" + `
- ` + "`spec.containers[*].readinessProbe.httpGet.host`" + `
- ` + "`spec.containers[*].startupProbe.httpGet.host`" + `
- ` + "`spec.containers[*].livenessProbe.tcpSocket.host`" + `
- ` + "`spec.containers[*].readinessProbe.tcpSocket.host`" + `
- ` + "`spec.containers[*].startupProbe.tcpSocket.host`" + `
- ` + "`spec.containers[*].lifecycle.postStart.httpGet.host`" + `
- ` + "`spec.containers[*].lifecycle.preStop.httpGet.host`" + `
- ` + "`spec.containers[*].lifecycle.postStart.tcpSocket.host`" + `
- ` + "`spec.containers[*].lifecycle.preStop.tcpSocket.host`"
}

func (r HostProbesRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	r.checkContainers(&violations, podSpec.Containers, "spec.containers")
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers")

	return violations, nil
}

func (r HostProbesRule) check(field string, host string) *rule.Violation {
	if host == "" {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: "host must be unset or empty",
		Field:   field,
	}
}

func (r HostProbesRule) checkLifecycleHandler(
	violations *[]rule.Violation,
	handler *corev1.LifecycleHandler,
	basePath string,
) {
	if handler == nil {
		return
	}

	if handler.HTTPGet != nil {
		util.AppendIfViolation(
			violations,
			r.check(
				basePath+".httpGet.host",
				handler.HTTPGet.Host,
			),
		)
	}
	if handler.TCPSocket != nil {
		util.AppendIfViolation(
			violations,
			r.check(
				basePath+".tcpSocket.host",
				handler.TCPSocket.Host,
			),
		)
	}
}

func (r HostProbesRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	basePath string,
) {
	for i, c := range containers {
		r.checkContainer(violations, c, basePath, i)
	}
}

func (r HostProbesRule) checkContainer(
	violations *[]rule.Violation,
	c corev1.Container,
	basePath string,
	index int,
) {
	path := func(field string) string {
		return util.FieldPath(basePath, index, field)
	}

	probesCheck := map[string]*corev1.Probe{
		"livenessProbe":  c.LivenessProbe,
		"readinessProbe": c.ReadinessProbe,
		"startupProbe":   c.StartupProbe,
	}

	for base, probe := range probesCheck {
		if probe == nil {
			continue
		}

		if probe.HTTPGet != nil {
			util.AppendIfViolation(
				violations,
				r.check(
					path(base+".httpGet.host"),
					probe.HTTPGet.Host,
				),
			)
		}
		if probe.TCPSocket != nil {
			util.AppendIfViolation(
				violations,
				r.check(
					path(base+".tcpSocket.host"),
					probe.TCPSocket.Host,
				),
			)
		}
	}

	if c.Lifecycle != nil {
		r.checkLifecycleHandler(
			violations,
			c.Lifecycle.PostStart,
			path("lifecycle.postStart"),
		)
		r.checkLifecycleHandler(
			violations,
			c.Lifecycle.PreStop,
			path("lifecycle.preStop"),
		)
	}
}
