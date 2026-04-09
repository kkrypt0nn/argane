package baseline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

var allowedSELinuxTypes = map[string]bool{
	"":                   true,
	"container_t":        true,
	"container_init_t":   true,
	"container_kvm_t":    true,
	"container_engine_t": true,
}

func allowedSELinuxMessage() string {
	values := make([]string, 0, len(allowedSELinuxTypes))
	for k := range allowedSELinuxTypes {
		if k == "" {
			continue
		}
		values = append(values, k)
	}

	sort.Strings(values)

	return "SELinux type must be one of: " +
		strings.Join(values, ", ") +
		" or unset"
}

type SELinuxRule struct{}

func (r SELinuxRule) ID() string {
	return "pss:baseline:selinux"
}

func (r SELinuxRule) MarkdownDescription() string {
	return `Ensures that containers use allowed SELinux types and that user/role fields are unset.

Allowed values:

- type:
  - undefined/nil
  - ` + "`container_t`" + `
  - ` + "`container_init_t`" + `
  - ` + "`container_kvm_t`" + `
  - ` + "`container_engine_t`" + `
- user: undefined/nil
- role: undefined/nil

The rule checks the following fields:

- ` + "`spec.securityContext.seLinuxOptions.type`" + `
- ` + "`spec.securityContext.seLinuxOptions.user`" + `
- ` + "`spec.securityContext.seLinuxOptions.role`" + `
- ` + "`spec.containers[*].securityContext.seLinuxOptions.type`" + `
- ` + "`spec.containers[*].securityContext.seLinuxOptions.user`" + `
- ` + "`spec.containers[*].securityContext.seLinuxOptions.role`" + `
- ` + "`spec.initContainers[*].securityContext.seLinuxOptions.type`" + `
- ` + "`spec.initContainers[*].securityContext.seLinuxOptions.user`" + `
- ` + "`spec.initContainers[*].securityContext.seLinuxOptions.role`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.seLinuxOptions.type`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.seLinuxOptions.user`" + `
- ` + "`spec.ephemeralContainers[*].securityContext.seLinuxOptions.role`"
}

func (r SELinuxRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	if podSpec.SecurityContext != nil && podSpec.SecurityContext.SELinuxOptions != nil {
		util.AppendIfViolation(
			&violations,
			r.checkType(
				"spec.securityContext.seLinuxOptions.type",
				podSpec.SecurityContext.SELinuxOptions.Type,
			),
		)
		util.AppendIfViolation(
			&violations,
			r.checkUserRole(
				"spec.securityContext.seLinuxOptions.user",
				podSpec.SecurityContext.SELinuxOptions.User,
				"user",
			),
		)
		util.AppendIfViolation(
			&violations,
			r.checkUserRole(
				"spec.securityContext.seLinuxOptions.role",
				podSpec.SecurityContext.SELinuxOptions.Role,
				"role",
			),
		)
	}

	r.checkContainers(&violations, podSpec.Containers, "spec.containers")
	r.checkContainers(&violations, podSpec.InitContainers, "spec.initContainers")
	r.checkEphemeralContainers(&violations, podSpec.EphemeralContainers, "spec.ephemeralContainers")

	return violations, nil
}

func (r SELinuxRule) checkType(field, selinuxType string) *rule.Violation {
	if allowedSELinuxTypes[selinuxType] {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: allowedSELinuxMessage(),
		Field:   field,
	}
}

func (r SELinuxRule) checkUserRole(field, value, option string) *rule.Violation {
	if value == "" {
		return nil
	}

	return &rule.Violation{
		RuleID:  r.ID(),
		Message: fmt.Sprintf("SELinux %s must be empty or unset", option),
		Field:   field,
	}
}

func (r SELinuxRule) checkContainers(
	violations *[]rule.Violation,
	containers []corev1.Container,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.SELinuxOptions == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.checkType(
				util.FieldPath(base, i, "securityContext.seLinuxOptions.type"),
				c.SecurityContext.SELinuxOptions.Type,
			),
		)
		util.AppendIfViolation(
			violations,
			r.checkUserRole(
				util.FieldPath(base, i, "securityContext.seLinuxOptions.user"),
				c.SecurityContext.SELinuxOptions.User,
				"user",
			),
		)
		util.AppendIfViolation(
			violations,
			r.checkUserRole(
				util.FieldPath(base, i, "securityContext.seLinuxOptions.role"),
				c.SecurityContext.SELinuxOptions.Role,
				"role",
			),
		)
	}
}

func (r SELinuxRule) checkEphemeralContainers(
	violations *[]rule.Violation,
	containers []corev1.EphemeralContainer,
	base string,
) {
	for i, c := range containers {
		if c.SecurityContext == nil || c.SecurityContext.SELinuxOptions == nil {
			continue
		}

		util.AppendIfViolation(
			violations,
			r.checkType(
				util.FieldPath(base, i, "securityContext.seLinuxOptions.type"),
				c.SecurityContext.SELinuxOptions.Type,
			),
		)
		util.AppendIfViolation(
			violations,
			r.checkUserRole(
				util.FieldPath(base, i, "securityContext.seLinuxOptions.user"),
				c.SecurityContext.SELinuxOptions.User,
				"user",
			),
		)
		util.AppendIfViolation(
			violations,
			r.checkUserRole(
				util.FieldPath(base, i, "securityContext.seLinuxOptions.role"),
				c.SecurityContext.SELinuxOptions.Role,
				"role",
			),
		)
	}
}
