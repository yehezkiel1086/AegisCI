package config

import (
	"fmt"
	"strings"
)

// Severity levels
const (
	SeverityNone     = "NONE"
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

// Mode types
const (
	ModeAuto     = "auto"
	ModePRCheck  = "pr-check"
	ModeDeepScan = "deep-scan"
)

// SBOM Formats
const (
	SBOMFormatCycloneDX = "cyclonedx-json"
	SBOMFormatSPDX      = "spdx-json"
)

// Config holds runtime configuration options for the AegisCI orchestrator.
type Config struct {
	TargetDir      string `yaml:"target_dir"`
	OutputFile     string `yaml:"output_file"`
	Mode           string `yaml:"mode"`
	FailOnSeverity string `yaml:"fail_on_severity"`
	EnableSAST     bool   `yaml:"sast"`
	EnableSecrets  bool   `yaml:"secrets"`
	EnableSCA      bool   `yaml:"sca"`
	EnableIaC      bool   `yaml:"iac"`
	EnableDAST     bool   `yaml:"dast"`
	DASTTargetURL  string `yaml:"dast_target_url"`
	GenerateSBOM   bool   `yaml:"sbom"`
	SBOMFormat     string `yaml:"sbom_format"`
	SBOMOutput     string `yaml:"sbom_output"`
	PolicyFile     string `yaml:"policy_file"`
	Verbose        bool   `yaml:"verbose"`
}

// DefaultConfig returns default configuration values for v2.0.
func DefaultConfig() *Config {
	return &Config{
		TargetDir:      ".",
		OutputFile:     "results.sarif",
		Mode:           ModeAuto,
		FailOnSeverity: SeverityHigh,
		EnableSAST:     true,
		EnableSecrets:  true,
		EnableSCA:      true, // Enabled by default in v2.0
		EnableIaC:      true, // Enabled by default in v2.0
		EnableDAST:     false,
		DASTTargetURL:  "",
		GenerateSBOM:   false,
		SBOMFormat:     SBOMFormatCycloneDX,
		SBOMOutput:     "sbom.cdx.json",
		PolicyFile:     ".aegisci.yml",
		Verbose:        false,
	}
}

// NormalizeSeverity standardizes severity strings to uppercase and validates them.
func NormalizeSeverity(sev string) (string, error) {
	upper := strings.ToUpper(strings.TrimSpace(sev))
	switch upper {
	case SeverityNone, "OFF":
		return SeverityNone, nil
	case SeverityLow:
		return SeverityLow, nil
	case SeverityMedium, "MED":
		return SeverityMedium, nil
	case SeverityHigh:
		return SeverityHigh, nil
	case SeverityCritical, "CRIT":
		return SeverityCritical, nil
	default:
		return "", fmt.Errorf("invalid severity '%s', allowed values: NONE, LOW, MEDIUM, HIGH, CRITICAL", sev)
	}
}

// SeverityRank converts a severity level string into an integer rank for comparison.
func SeverityRank(sev string) int {
	norm, err := NormalizeSeverity(sev)
	if err != nil {
		return 0
	}
	switch norm {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// MapSARIFLevelToSeverity converts SARIF result levels ("error", "warning", "note", "none") to AegisCI severity strings.
func MapSARIFLevelToSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	case "note":
		return SeverityLow
	default:
		return SeverityLow
	}
}
