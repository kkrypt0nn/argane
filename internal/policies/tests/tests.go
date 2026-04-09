package tests

import (
	"os"
	"strings"
	"testing"

	"github.com/kkrypt0nn/argane/internal/decoder"
)

func loadPodSpecs(t *testing.T, path string) []*decoder.PodSpecWithMetadata {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}

	specs, err := decoder.DecodePodSpecs(data)
	if err != nil {
		t.Fatalf("failed to decode %s: %v", path, err)
	}

	return specs
}

func ruleIDToFilename(ruleID string) (string, string) {
	parts := strings.Split(ruleID, ":")
	if len(parts) != 3 || parts[0] != "pss" {
		panic("unexpected rule ID: " + ruleID)
	}
	return parts[1], parts[2] + ".yaml"
}
