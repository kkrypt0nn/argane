package baseline

import (
	"sort"
	"strings"

	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

var allowedSysctlsTypes = map[string]bool{
	"kernel.shm_rmid_forced":              true,
	"net.ipv4.ip_local_port_range":        true,
	"net.ipv4.ip_unprivileged_port_start": true,
	"net.ipv4.tcp_syncookies":             true,
	"net.ipv4.ping_group_range":           true,
	"net.ipv4.ip_local_reserved_ports":    true,
	"net.ipv4.tcp_keepalive_time":         true,
	"net.ipv4.tcp_fin_timeout":            true,
	"net.ipv4.tcp_keepalive_intvl":        true,
	"net.ipv4.tcp_keepalive_probes":       true,
}

func allowedSysctlsMessage() string {
	values := make([]string, 0, len(allowedSysctlsTypes))
	for k := range allowedSysctlsTypes {
		values = append(values, k)
	}

	sort.Strings(values)

	return "Sysctls name must be one of: " +
		strings.Join(values, ", ") +
		" or unset"
}

type SysctlsRule struct{}

func (r SysctlsRule) ID() string {
	return "pss:baseline:sysctls"
}

func (r SysctlsRule) MarkdownDescription() string {
	return `Ensures that containers only use allowed sysctls.

Allowed values:

- undefined/nil
- ` + "`kernel.shm_rmid_forced`" + `
- ` + "`net.ipv4.ip_local_port_range`" + `
- ` + "`net.ipv4.ip_unprivileged_port_start`" + `
- ` + "`net.ipv4.tcp_syncookies`" + `
- ` + "`net.ipv4.ping_group_range`" + `
- ` + "`net.ipv4.ip_local_reserved_ports`" + `
- ` + "`net.ipv4.tcp_keepalive_time`" + `
- ` + "`net.ipv4.tcp_fin_timeout`" + `
- ` + "`net.ipv4.tcp_keepalive_intvl`" + `
- ` + "`net.ipv4.tcp_keepalive_probes`" + `

The rule checks the following fields:

- ` + "`spec.securityContext.sysctls[*].name`"
}

func (r SysctlsRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	if podSpec.SecurityContext != nil && len(podSpec.SecurityContext.Sysctls) != 0 {
		for i, s := range podSpec.SecurityContext.Sysctls {
			util.AppendIfViolation(
				&violations,
				r.check(
					util.FieldPath("spec.securityContext.sysctls", i, "name"),
					s.Name,
				),
			)
		}
	}

	return violations, nil
}

func (r SysctlsRule) check(field, sysctlName string) *rule.Violation {
	if allowedSysctlsTypes[sysctlName] {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: allowedSysctlsMessage(),
		Field:   field,
	}
}
