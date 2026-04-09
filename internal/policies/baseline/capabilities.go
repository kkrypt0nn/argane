package baseline

import (
	"sort"
	"strings"

	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

var allowedCapabilities = map[corev1.Capability]struct{}{
	"AUDIT_WRITE":      {},
	"CHOWN":            {},
	"DAC_OVERRIDE":     {},
	"FOWNER":           {},
	"FSETID":           {},
	"KILL":             {},
	"MKNOD":            {},
	"NET_BIND_SERVICE": {},
	"SETFCAP":          {},
	"SETGID":           {},
	"SETPCAP":          {},
	"SETUID":           {},
	"SYS_CHROOT":       {},
}

func allowedCapabilitiesMessage() string {
	values := make([]string, 0, len(allowedCapabilities))
	for cap := range allowedCapabilities {
		values = append(values, string(cap))
	}

	sort.Strings(values)

	return "Capabilities may only be added from the following list: " +
		strings.Join(values, ", ")
}

type CapabilitiesRule struct{}

func (r CapabilitiesRule) ID() string {
	return "pss:baseline:capabilities"
}

func (r CapabilitiesRule) MarkdownDescription() string {
	return `Ensures that containers only add Linux capabilities from a pre-defined list of allowed capabilities.

Allowed values:

- undefined/nil
- ` + "`AUDIT_WRITE`" + `
- ` + "`CHOWN`" + `
- ` + "`DAC_OVERRIDE`" + `
- ` + "`FOWNER`" + `
- ` + "`FSETID`" + `
- ` + "`KILL`" + `
- ` + "`MKNOD`" + `
- ` + "`NET_BIND_SERVICE`" + `
- ` + "`SETFCAP`" + `
- ` + "`SETGID`" + `
- ` + "`SETPCAP`" + `
- ` + "`SETUID`" + `
- ` + "`SYS_CHROOT`" + `

The rule checks the following fields:

- ` + "`spec.containers[*].securityContext.capabilities.add`" + `
- ` + "`spec.initContainers[*].securityContext.capabilities.add`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.capabilities.add`"
}

func (r CapabilitiesRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation
	message := allowedCapabilitiesMessage()

	r.checkContainers(&violations, podSpec.Containers, "spec.containers", message)
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers", message)
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers", message)

	return violations, nil
}

func (r CapabilitiesRule) check(field string, caps *corev1.Capabilities, message string) *rule.Violation {
	if caps == nil || len(caps.Add) == 0 {
		return nil
	}

	for _, cap := range caps.Add {
		if _, ok := allowedCapabilities[cap]; !ok {
			return &rule.Violation{
				RuleID:  r.ID(),
				Message: message,
				Field:   field,
			}
		}
	}

	return nil
}

func (r CapabilitiesRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
	message string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.capabilities.add"),
				c.SecurityContext.Capabilities,
				message,
			),
		)
	}
}

func (r CapabilitiesRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
	message string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.check(
				util.FieldPath(base, i, "securityContext.capabilities.add"),
				c.SecurityContext.Capabilities,
				message,
			),
		)
	}
}
