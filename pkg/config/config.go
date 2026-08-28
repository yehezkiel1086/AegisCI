package config

import (
	"fmt"
	"strings"
)

const (
	SeverityNone     = "NONE"
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

const (
	ModeAuto     = "auto"
	ModePRCheck  = "pr-check"
	ModeDeepScan = "deep-scan"
)

const (
	SBOMFormatCycloneDX = "cyclonedx-json"
	SBOMFormatSPDX      = "spdx-json"
)

const (
	DASTModeBaseline = "baseline"
	DASTModeAPI      = "api"
	DASTModeFull     = "full"
)

const (
	AIProviderGemini = "gemini"
	AIProviderOpenAI = "openai"
	AIProviderCustom = "custom"
)

type Config struct {
	TargetDir           string `yaml:"target_dir"`
	OutputFile          string `yaml:"output_file"`
	Mode                string `yaml:"mode"`
	FailOnSeverity      string `yaml:"fail_on_severity"`
	EnableSAST          bool   `yaml:"sast"`
	EnableSecrets       bool   `yaml:"secrets"`
	EnableSCA           bool   `yaml:"sca"`
	EnableIaC           bool   `yaml:"iac"`
	EnableDAST          bool   `yaml:"dast"`
	DASTTargetURL       string `yaml:"dast_target_url"`
	DASTMode            string `yaml:"dast_mode"`
	EnableWorkflowAudit bool   `yaml:"workflow_audit"`
	EnableAnnotations   bool   `yaml:"annotations"`
	EnableVortex        bool   `yaml:"vortex"`
	VortexAPIURL        string `yaml:"vortex_api_url"`
	VortexAPIKey        string `yaml:"vortex_api_key"`
	GenerateSBOM        bool   `yaml:"sbom"`
	SBOMFormat          string `yaml:"sbom_format"`
	SBOMOutput          string `yaml:"sbom_output"`
	EnableAIRemediation bool   `yaml:"ai_remediation"`
	AIProvider          string `yaml:"ai_provider"`
	AIAPIKey            string `yaml:"ai_api_key"`
	AIModel             string `yaml:"ai_model"`
	AIBaseURL           string `yaml:"ai_base_url"`
	PatchesDir          string `yaml:"patches_dir"`
	PluginsDir          string `yaml:"plugins_dir"`
	DashboardURL        string `yaml:"dashboard_url"`
	DashboardToken      string `yaml:"dashboard_token"`
	ExportMetrics       bool   `yaml:"export_metrics"`
	PolicyFile          string `yaml:"policy_file"`
	Verbose             bool   `yaml:"verbose"`
}

func DefaultConfig() *Config {
	return &Config{
		TargetDir:           ".",
		OutputFile:          "results.sarif",
		Mode:                ModeAuto,
		FailOnSeverity:      SeverityHigh,
		EnableSAST:          true,
		EnableSecrets:       true,
		EnableSCA:           true,
		EnableIaC:           true,
		EnableDAST:          false,
		DASTTargetURL:       "",
		DASTMode:            DASTModeBaseline,
		EnableWorkflowAudit: true,
		EnableAnnotations:   true,
		EnableVortex:        false,
		VortexAPIURL:        "https://api.vortex-threatintel.io/v1",
		VortexAPIKey:        "",
		GenerateSBOM:        false,
		SBOMFormat:          SBOMFormatCycloneDX,
		SBOMOutput:          "sbom.cdx.json",
		EnableAIRemediation: false,
		AIProvider:          AIProviderGemini,
		AIAPIKey:            "",
		AIModel:             "gemini-1.5-pro",
		AIBaseURL:           "",
		PatchesDir:          "patches",
		PluginsDir:          ".aegisci/plugins",
		DashboardURL:        "",
		DashboardToken:      "",
		ExportMetrics:       false,
		PolicyFile:          ".aegisci.yml",
		Verbose:             false,
	}
}

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
