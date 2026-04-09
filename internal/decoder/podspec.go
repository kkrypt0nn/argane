package decoder

import (
	"bytes"
	"io"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

var scheme = runtime.NewScheme()

func init() {
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
}

type PodSpecWithMetadata struct {
	Kind string
	Name string
	Spec *corev1.PodSpec
}

func DecodePodSpecs(yamlBytes []byte) ([]*PodSpecWithMetadata, error) {
	deserializer := serializer.NewCodecFactory(scheme).UniversalDeserializer()
	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(yamlBytes), 4096)

	var specs []*PodSpecWithMetadata
	for {
		var raw runtime.RawExtension
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if len(raw.Raw) == 0 {
			continue
		}

		spec, err := decodePodSpecWithMetadata(raw.Raw, deserializer)
		if err != nil {
			return nil, err
		}
		if spec != nil {
			specs = append(specs, spec)
		}
	}

	return specs, nil
}

func decodePodSpecWithMetadata(raw []byte, deserializer runtime.Decoder) (*PodSpecWithMetadata, error) {
	obj, _, err := deserializer.Decode(raw, nil, nil)
	if err != nil {
		if runtime.IsNotRegisteredError(err) || meta.IsNoMatchError(err) {
			return nil, nil
		}
		return nil, err
	}

	if pod, ok := obj.(*corev1.Pod); ok {
		return &PodSpecWithMetadata{Kind: "pod", Name: pod.Name, Spec: &pod.Spec}, nil
	}

	if spec := PodSpecWithMetadataFromWorkload(obj); spec != nil {
		return spec, nil
	}

	return nil, nil
}

func PodSpecWithMetadataFromWorkload(obj runtime.Object) *PodSpecWithMetadata {
	switch o := obj.(type) {
	case *appsv1.DaemonSet:
		return &PodSpecWithMetadata{Kind: "daemonset", Name: o.Name, Spec: &o.Spec.Template.Spec}
	case *appsv1.Deployment:
		return &PodSpecWithMetadata{Kind: "deployment", Name: o.Name, Spec: &o.Spec.Template.Spec}
	case *appsv1.StatefulSet:
		return &PodSpecWithMetadata{Kind: "statefulset", Name: o.Name, Spec: &o.Spec.Template.Spec}
	case *batchv1.Job:
		return &PodSpecWithMetadata{Kind: "job", Name: o.Name, Spec: &o.Spec.Template.Spec}
	case *batchv1.CronJob:
		return &PodSpecWithMetadata{Kind: "cronjob", Name: o.Name, Spec: &o.Spec.JobTemplate.Spec.Template.Spec}
	}
	return nil
}
