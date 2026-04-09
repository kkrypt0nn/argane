package util

import corev1 "k8s.io/api/core/v1"

func IsWindows(podSpecOS *corev1.PodOS) bool {
	return podSpecOS != nil && podSpecOS.Name == corev1.Windows
}
