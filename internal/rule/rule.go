package rule

import corev1 "k8s.io/api/core/v1"

type Rule interface {
	ID() string
	MarkdownDescription() string
	Evaluate(podSpec *corev1.PodSpec) ([]Violation, error)
}

type RuleResult struct {
	RuleID  string   `json:"rule_id"`
	Passed  bool     `json:"passed"`
	Details []string `json:"details,omitempty"`
}
