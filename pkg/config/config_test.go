package config

import (
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

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.EnableSAST || !cfg.EnableSecrets || !cfg.EnableSCA || !cfg.EnableIaC {
		t.Errorf("Expected default v2.0 config to enable SAST, Secrets, SCA, and IaC")
	}
	if cfg.FailOnSeverity != SeverityHigh {
		t.Errorf("Expected default FailOnSeverity to be HIGH, got %s", cfg.FailOnSeverity)
	}
	if cfg.SBOMFormat != SBOMFormatCycloneDX {
		t.Errorf("Expected default SBOM format to be cyclonedx-json, got %s", cfg.SBOMFormat)
	}
}
