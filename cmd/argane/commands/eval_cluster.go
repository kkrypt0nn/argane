package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kkrypt0nn/argane/internal/decoder"
	"github.com/kkrypt0nn/argane/internal/engine"
	"github.com/kkrypt0nn/argane/internal/policies"
	"github.com/kkrypt0nn/argane/internal/reporters"
	"github.com/kkrypt0nn/argane/internal/util"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// https://github.com/kubernetes/client-go/blob/master/examples/out-of-cluster-client-configuration/main.go

var (
	evalClusterOptNamespace             string
	evalClusterOptAllNamespaces         bool
	evalClusterOptContextName           string
	evalClusterOptContextNameKubeconfig string
)

func init() {
	evalCmd.AddCommand(evalClusterCmd)

	evalClusterCmd.PersistentFlags().StringVarP(
		&evalClusterOptNamespace,
		"namespace",
		"n",
		"default",
		"The namespace to evaluate",
	)

	evalClusterCmd.PersistentFlags().BoolVarP(
		&evalClusterOptAllNamespaces,
		"all-namespaces",
		"A",
		false,
		"Evaluate across all namespaces",
	)

	evalClusterCmd.PersistentFlags().StringVarP(
		&evalClusterOptContextName,
		"context",
		"c",
		"",
		"The context of the kubeconfig file to use, default is the currently active one",
	)

	var kubeconfigPath string
	if home := homedir.HomeDir(); home != "" {
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}
	evalClusterCmd.PersistentFlags().StringVarP(
		&evalClusterOptContextNameKubeconfig,
		"kubeconfig",
		"k",
		kubeconfigPath,
		"Absolute path to the kubeconfig file",
	)
	flag := evalClusterCmd.PersistentFlags().Lookup("kubeconfig")
	flag.DefValue = "$HOME/.kube/config"
}

var evalClusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Evaluate a cluster and all its pod-compatible running workload from the current kubeconfig against the Kubernetes Pod Security Standards.",
	Run: func(cmd *cobra.Command, args []string) {
		overrides := &clientcmd.ConfigOverrides{}
		if evalClusterOptContextName != "" {
			overrides.CurrentContext = evalClusterOptContextName
		}
		configLoadingRules := &clientcmd.ClientConfigLoadingRules{
			ExplicitPath: evalClusterOptContextNameKubeconfig,
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

		ns := evalClusterOptNamespace
		originNs := ns
		if evalClusterOptAllNamespaces {
			ns = ""
			originNs = "<all>"
		}

		results := []*engine.Result{}
		origin := fmt.Sprintf("%s/%s", rawConfig.CurrentContext, originNs)

		// TODO(kkrypt0nn): Maybe some generic function later
		if daemonsets, err := clientset.AppsV1().DaemonSets(ns).List(cmd.Context(), metav1.ListOptions{}); err == nil {
			for _, ds := range daemonsets.Items {
				spec := &decoder.PodSpecWithMetadata{
					Kind: "daemonset",
					Name: ds.Name,
					Spec: &ds.Spec.Template.Spec,
				}
				results = append(results, e.Evaluate(spec, origin))
			}
		}

		if deployments, err := clientset.AppsV1().Deployments(ns).List(cmd.Context(), metav1.ListOptions{}); err == nil {
			for _, dep := range deployments.Items {
				spec := &decoder.PodSpecWithMetadata{
					Kind: "deployment",
					Name: dep.Name,
					Spec: &dep.Spec.Template.Spec,
				}
				results = append(results, e.Evaluate(spec, origin))
			}
		}

		if statefulsets, err := clientset.AppsV1().StatefulSets(ns).List(cmd.Context(), metav1.ListOptions{}); err == nil {
			for _, sts := range statefulsets.Items {
				spec := &decoder.PodSpecWithMetadata{
					Kind: "statefulset",
					Name: sts.Name,
					Spec: &sts.Spec.Template.Spec,
				}
				results = append(results, e.Evaluate(spec, origin))
			}
		}

		if jobs, err := clientset.BatchV1().Jobs(ns).List(cmd.Context(), metav1.ListOptions{}); err == nil {
			for _, job := range jobs.Items {
				spec := &decoder.PodSpecWithMetadata{
					Kind: "job",
					Name: job.Name,
					Spec: &job.Spec.Template.Spec,
				}
				results = append(results, e.Evaluate(spec, origin))
			}
		}

		if cronjobs, err := clientset.BatchV1().CronJobs(ns).List(cmd.Context(), metav1.ListOptions{}); err == nil {
			for _, cj := range cronjobs.Items {
				spec := &decoder.PodSpecWithMetadata{
					Kind: "cronjob",
					Name: cj.Name,
					Spec: &cj.Spec.JobTemplate.Spec.Template.Spec,
				}
				results = append(results, e.Evaluate(spec, origin))
			}
		}

		reporter.Print(results)
		for _, r := range results {
			if !r.IsClean() {
				os.Exit(1)
			}
		}

		os.Exit(0)
	},
}
