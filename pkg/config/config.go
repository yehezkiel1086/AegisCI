package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
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
	PolicyFile     string `yaml:"policy_file"`
	Verbose        bool   `yaml:"verbose"`
}

// PolicyConfig represents the structure of .aegisci.yml policy file.
type PolicyConfig struct {
	Version    string         `yaml:"version"`
	Settings   PolicySettings `yaml:"settings"`
	Ignore     []PolicyIgnore `yaml:"ignore"`
	Exceptions []PolicyIgnore `yaml:"exceptions"` // Alias/support for exceptions
}

// PolicySettings defines general policy settings.
type PolicySettings struct {
	FailOnUnpatchedCVEs bool `yaml:"fail_on_unpatched_cves"`
}

// PolicyIgnore defines an exception or suppression rule.
type PolicyIgnore struct {
	ID      string `yaml:"id"`
	Path    string `yaml:"path"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"`
}

// DefaultConfig returns default configuration values.
func DefaultConfig() *Config {
	return &Config{
		TargetDir:      ".",
		OutputFile:     "results.sarif",
		Mode:           ModeAuto,
		FailOnSeverity: SeverityHigh,
		EnableSAST:     true,
		EnableSecrets:  true,
		EnableSCA:      false,
		EnableIaC:      false,
		EnableDAST:     false,
		DASTTargetURL:  "",
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
		return SeverityHigh // Standard SARIF error maps to HIGH (or CRITICAL)
	case "warning":
		return SeverityMedium
	case "note":
		return SeverityLow
	default:
		return SeverityLow
	}
}

// LoadPolicyFile attempts to load policy configuration from the given file path.
func LoadPolicyFile(path string) (*PolicyConfig, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil // Not an error if optional policy file doesn't exist
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", path, err)
	}

	var policy PolicyConfig
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy file %s: %w", path, err)
	}

	// Merge exceptions into Ignore for backward/forward compatibility
	if len(policy.Exceptions) > 0 {
		policy.Ignore = append(policy.Ignore, policy.Exceptions...)
	}

	return &policy, nil
}
