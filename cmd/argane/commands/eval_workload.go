package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kkrypt0nn/argane/internal/decoder"
	"github.com/kkrypt0nn/argane/internal/engine"
	"github.com/kkrypt0nn/argane/internal/policies"
	"github.com/kkrypt0nn/argane/internal/reporters"
	"github.com/kkrypt0nn/argane/internal/util"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// https://github.com/kubernetes/client-go/blob/master/examples/out-of-cluster-client-configuration/main.go

var (
	evalWorkloadOptNamespace   string
	evalWorkloadOptContextName string
	evalWorkloadOptKubeconfig  string
)

func init() {
	evalCmd.AddCommand(evalWorkloadCmd)

	evalWorkloadCmd.PersistentFlags().StringVarP(
		&evalWorkloadOptNamespace,
		"namespace",
		"n",
		"default",
		"Namespace of the resource",
	)

	evalWorkloadCmd.PersistentFlags().StringVarP(
		&evalWorkloadOptContextName,
		"context",
		"c",
		"",
		"The context of the kubeconfig file to use, default is the currently active one",
	)

	var kubeconfigPath string
	if home := homedir.HomeDir(); home != "" {
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}
	evalWorkloadCmd.PersistentFlags().StringVarP(
		&evalWorkloadOptKubeconfig,
		"kubeconfig",
		"k",
		kubeconfigPath,
		"Absolute path to the kubeconfig file",
	)
	flag := evalWorkloadCmd.PersistentFlags().Lookup("kubeconfig")
	flag.DefValue = "$HOME/.kube/config"
}

var evalWorkloadCmd = &cobra.Command{
	Use:   "workload <resource>/<name>",
	Short: "Evaluate a pod-compatible running workload or the whole cluster from the current kubeconfig against the Kubernetes Pod Security Standards.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		parts := strings.SplitN(args[0], "/", 2)
		if len(parts) != 2 {
			util.LogError("Invalid input, expected format <resource>/<name>")
			os.Exit(1)
		}
		resource, name := parts[0], parts[1]

		overrides := &clientcmd.ConfigOverrides{}
		if evalWorkloadOptContextName != "" {
			overrides.CurrentContext = evalWorkloadOptContextName
		}
		configLoadingRules := &clientcmd.ClientConfigLoadingRules{
			ExplicitPath: evalWorkloadOptKubeconfig,
		}
		clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			configLoadingRules,
			overrides,
		)

		config, err := clientConfig.ClientConfig()
		if err != nil {
			util.LogError(fmt.Sprintf("Failed to use the kubeconfig context: %v", err))
			os.Exit(1)
		}
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			util.LogError(fmt.Sprintf("Failed to create the clientset: %v", err))
			os.Exit(1)
		}

		rawConfig, err := clientConfig.RawConfig()
		if err != nil {
			util.LogError(fmt.Sprintf("Failed to get raw kubeconfig: %v", err))
			os.Exit(1)
		}

		selectedPolicy := policies.GetPolicyFromChoice(evalOptPolicy, evalOptDisabledRules)
		if selectedPolicy == nil {
			util.LogError("Invalid policy. Must be 'baseline', 'restricted' or a Y(A)ML file")
			os.Exit(1)
		}

		e := engine.New(selectedPolicy)
		reporter := reporters.NewReporter(evalOptOutput, selectedPolicy, evalOptViolationsOnly)

		var spec *corev1.PodSpec
		switch resource {
		case "cronjob":
			cronjob, err := clientset.BatchV1().CronJobs(evalWorkloadOptNamespace).Get(cmd.Context(), name, metav1.GetOptions{})
			if err != nil {
				util.LogError(fmt.Sprintf("Failed to get CronJob %s/%s: %v", evalWorkloadOptNamespace, name, err))
				os.Exit(1)
			}
			spec = &cronjob.Spec.JobTemplate.Spec.Template.Spec
		case "daemonset":
			daemonset, err := clientset.AppsV1().DaemonSets(evalWorkloadOptNamespace).Get(cmd.Context(), name, metav1.GetOptions{})
			if err != nil {
				util.LogError(fmt.Sprintf("Failed to get DaemonSet %s/%s: %v", evalWorkloadOptNamespace, name, err))
				os.Exit(1)
			}
			spec = &daemonset.Spec.Template.Spec
		case "deployment":
			deployment, err := clientset.AppsV1().Deployments(evalWorkloadOptNamespace).Get(cmd.Context(), name, metav1.GetOptions{})
			if err != nil {
				util.LogError(fmt.Sprintf("Failed to get Deployment %s/%s: %v", evalWorkloadOptNamespace, name, err))
				os.Exit(1)
			}
			spec = &deployment.Spec.Template.Spec
		case "job":
			job, err := clientset.BatchV1().Jobs(evalWorkloadOptNamespace).Get(cmd.Context(), name, metav1.GetOptions{})
			if err != nil {
				util.LogError(fmt.Sprintf("Failed to get Job %s/%s: %v", evalWorkloadOptNamespace, name, err))
				os.Exit(1)
			}
			spec = &job.Spec.Template.Spec
		case "pod":
			pod, err := clientset.CoreV1().Pods(evalWorkloadOptNamespace).Get(cmd.Context(), name, metav1.GetOptions{})
			if err != nil {
				util.LogError(fmt.Sprintf("Failed to get Pod %s/%s: %v", evalWorkloadOptNamespace, name, err))
				os.Exit(1)
			}
			spec = &pod.Spec
		case "statefulset":
			statefulset, err := clientset.AppsV1().StatefulSets(evalWorkloadOptNamespace).Get(cmd.Context(), name, metav1.GetOptions{})
			if err != nil {
				util.LogError(fmt.Sprintf("Failed to get StatefulSet %s/%s: %v", evalWorkloadOptNamespace, name, err))
				os.Exit(1)
			}
			spec = &statefulset.Spec.Template.Spec
		default:
			util.LogError("Invalid resource type. Must be 'cronjob', 'daemonset', 'deployment', 'job', 'pod' or 'statefulset'")
			os.Exit(1)
		}

		result := e.Evaluate(
			&decoder.PodSpecWithMetadata{
				Kind: resource,
				Name: name,
				Spec: spec,
			},
			fmt.Sprintf("%s/%s", rawConfig.CurrentContext, evalWorkloadOptNamespace),
		)

		reporter.Print([]*engine.Result{result})
		if !result.IsClean() {
			os.Exit(1)
		}
		os.Exit(0)
	},
}
