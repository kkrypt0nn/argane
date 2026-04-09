package baseline

import (
	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type HostNamespacesRule struct{}

func (r HostNamespacesRule) ID() string {
	return "pss:baseline:host_namespaces"
}

func (r HostNamespacesRule) MarkdownDescription() string {
	return `Ensures that pods do not share the host's network, PID, or IPC namespaces.

Allowed values:

- undefined/nil
- ` + "`false`" + `

The rule checks the following fields:

- ` + "`spec.hostNetwork`" + `
- ` + "`spec.hostPID`" + `
- ` + "`spec.hostIPC`"
}

func (r HostNamespacesRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	util.AppendIfViolation(
		&violations,
		r.check(
			"spec.hostNetwork",
			podSpec.HostNetwork,
			"hostNetwork must be unset or false",
		),
	)

	util.AppendIfViolation(
		&violations,
		r.check(
			"spec.hostPID",
			podSpec.HostPID,
			"hostPID must be unset or false",
		),
	)

	util.AppendIfViolation(
		&violations,
		r.check(
			"spec.hostIPC",
			podSpec.HostIPC,
			"hostIPC must be unset or false",
		),
	)

	return violations, nil
}

func (r HostNamespacesRule) check(field string, enabled bool, message string) *rule.Violation {
	if !enabled {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: message,
		Field:   field,
	}
}
