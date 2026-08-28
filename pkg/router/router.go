package router

import (
	"os"
	"strings"

	"github.com/yehezkiel1086/AegisCI/pkg/config"
)

// Plan encapsulates the resolved execution mode, decision reasoning, and engine profile.
type Plan struct {
	RequestedMode       string
	EffectiveMode       string
	Reason              string
	EnableSecrets       bool
	EnableSAST          bool
	EnableSCA           bool
	EnableIaC           bool
	EnableDAST          bool
	DASTTargetURL       string
	DASTMode            string
	EnableWorkflowAudit bool
	GenerateSBOM        bool
	FastTimeoutSec      int
}

// ResolvePlan determines the optimal scanner profile and execution mode.
func ResolvePlan(cfg *config.Config) *Plan {
	plan := &Plan{
		RequestedMode:       cfg.Mode,
		EnableSecrets:       cfg.EnableSecrets,
		EnableSAST:          cfg.EnableSAST,
		EnableSCA:           cfg.EnableSCA,
		EnableIaC:           cfg.EnableIaC,
		EnableDAST:          cfg.EnableDAST,
		DASTTargetURL:       cfg.DASTTargetURL,
		DASTMode:            cfg.DASTMode,
		EnableWorkflowAudit: cfg.EnableWorkflowAudit,
		GenerateSBOM:        cfg.GenerateSBOM,
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" || mode == config.ModeAuto {
		// Auto-detect based on CI environment
		if isPullRequestEvent() {
			plan.EffectiveMode = config.ModePRCheck
			plan.Reason = "Pull Request event detected; applying fast PR-Check pipeline (< 3 mins)."
		} else {
			plan.EffectiveMode = config.ModeDeepScan
			plan.Reason = "Push / Release branch event detected; applying full Deep-Scan suite."
		}
	} else if mode == config.ModePRCheck {
		plan.EffectiveMode = config.ModePRCheck
		plan.Reason = "Explicit PR-Check mode requested."
	} else if mode == config.ModeDeepScan {
		plan.EffectiveMode = config.ModeDeepScan
		plan.Reason = "Explicit Deep-Scan mode requested."
	} else {
		plan.EffectiveMode = config.ModePRCheck
		plan.Reason = "Unknown mode provided; defaulting to safe PR-Check pipeline."
	}

	// Apply mode-specific optimizations
	if plan.EffectiveMode == config.ModePRCheck {
		// PR-Check focuses on fast feedback (< 3 mins): Secrets + SAST + SCA + Workflow linter
		if !cfg.EnableIaC {
			plan.EnableIaC = false
		}
		// If DAST is requested in PR-check, limit to baseline scan
		if plan.EnableDAST && plan.DASTMode == config.DASTModeFull {
			plan.DASTMode = config.DASTModeBaseline
		}
		plan.FastTimeoutSec = 180 // 3 minutes timeout
	} else {
		// Deep-Scan enables full capabilities
		plan.FastTimeoutSec = 600 // 10 minutes timeout
	}

	return plan
}

func isPullRequestEvent() bool {
	// GitHub Actions
	if os.Getenv("GITHUB_EVENT_NAME") == "pull_request" {
		return true
	}
	// GitLab CI
	if os.Getenv("CI_MERGE_REQUEST_IID") != "" {
		return true
	}
	// Bitbucket Pipelines / Generic PR indicator
	if os.Getenv("BITBUCKET_PR_ID") != "" || os.Getenv("CHANGE_ID") != "" {
		return true
	}
	return false
}
