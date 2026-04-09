package restricted

import (
	"reflect"
	"strings"

	"github.com/kkrypt0nn/argane/internal/rule"
	"github.com/kkrypt0nn/argane/internal/util"
	corev1 "k8s.io/api/core/v1"
)

type VolumeTypesRule struct{}

func (r VolumeTypesRule) ID() string {
	return "pss:restricted:volume_types"
}

func (r VolumeTypesRule) MarkdownDescription() string {
	return `Ensures that only allowed volume types are used in pods and containers.

Allowed values:

- ` + "`configMap`" + `
- ` + "`csi`" + `
- ` + "`downwardAPI`" + `
- ` + "`emptyDir`" + `
- ` + "`ephemeral`" + `
- ` + "`persistentVolumeClaim`" + `
- ` + "`projected`" + `
- ` + "`secret`" + `

The rule checks the following fields:

- ` + "`spec.volumes[*].<volume-type>`"
}

func (r VolumeTypesRule) Evaluate(podSpec *corev1.PodSpec) ([]rule.Violation, error) {
	var violations []rule.Violation

	for i, v := range podSpec.Volumes {
		util.AppendIfViolation(
			&violations,
			r.check(util.FieldPath("spec.volumes", i, volumeType(v)), v),
		)
	}

	return violations, nil
}

func (r VolumeTypesRule) check(field string, v corev1.Volume) *rule.Violation {
	allowed :=
		v.ConfigMap != nil ||
			v.CSI != nil ||
			v.DownwardAPI != nil ||
			v.EmptyDir != nil ||
			v.Ephemeral != nil ||
			v.PersistentVolumeClaim != nil ||
			v.Projected != nil ||
			v.Secret != nil

	if !allowed {
		return &rule.Violation{
			RuleID:  r.ID(),
			Message: "Volume source must be one of: configMap, csi, downwardAPI, emptyDir, ephemeral, persistentVolumeClaim, projected, secret",
			Field:   field,
		}
	}

	return nil
}

func volumeType(v corev1.Volume) string {
	vs := v.VolumeSource
	rv := reflect.ValueOf(vs)
	rt := reflect.TypeOf(vs)

	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		if field.Kind() == reflect.Pointer && !field.IsNil() {
			jsonTag := rt.Field(i).Tag.Get("json")
			if jsonTag == "" {
				return rt.Field(i).Name
			}

			return strings.Split(jsonTag, ",")[0]
		}
	}

	return "unknown"
}
