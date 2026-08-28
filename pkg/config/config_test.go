package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		shouldError bool
	}{
		{"low", SeverityLow, false},
		{"MEDIUM", SeverityMedium, false},
		{"high", SeverityHigh, false},
		{"critical", SeverityCritical, false},
		{"crit", SeverityCritical, false},
		{"none", SeverityNone, false},
		{"off", SeverityNone, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		got, err := NormalizeSeverity(tt.input)
		if (err != nil) != tt.shouldError {
			t.Errorf("NormalizeSeverity(%q) unexpected error status: %v", tt.input, err)
		}
		if got != tt.expected {
			t.Errorf("NormalizeSeverity(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityRank(SeverityCritical) <= SeverityRank(SeverityHigh) {
		t.Errorf("Expected Critical rank > High rank")
	}
	if SeverityRank(SeverityHigh) <= SeverityRank(SeverityMedium) {
		t.Errorf("Expected High rank > Medium rank")
	}
	if SeverityRank(SeverityMedium) <= SeverityRank(SeverityLow) {
		t.Errorf("Expected Medium rank > Low rank")
	}
	if SeverityRank(SeverityLow) <= SeverityRank(SeverityNone) {
		t.Errorf("Expected Low rank > None rank")
	}
}

func TestLoadPolicyFile(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, ".aegisci.yml")

	content := `version: "1.0"
settings:
  fail_on_unpatched_cves: true
ignore:
  - id: "G401"
    path: "pkg/legacy/hash.go"
    reason: "Legacy non-cryptographic usage"
`
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write temp policy file: %v", err)
	}

	policy, err := LoadPolicyFile(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicyFile failed: %v", err)
	}
	if policy == nil {
		t.Fatalf("Expected policy, got nil")
	}
	if !policy.Settings.FailOnUnpatchedCVEs {
		t.Errorf("Expected FailOnUnpatchedCVEs to be true")
	}
	if len(policy.Ignore) != 1 || policy.Ignore[0].ID != "G401" {
		t.Errorf("Expected 1 ignore rule with ID G401, got %+v", policy.Ignore)
	}
}
