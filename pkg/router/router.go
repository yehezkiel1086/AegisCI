package router

import (
	"os"
	"strings"

	"github.com/yehezkiel1086/AegisCI/pkg/config"
)

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

	if plan.EffectiveMode == config.ModePRCheck {
		if !cfg.EnableIaC {
			plan.EnableIaC = false
		}
		if plan.EnableDAST && plan.DASTMode == config.DASTModeFull {
			plan.DASTMode = config.DASTModeBaseline
		}
		plan.FastTimeoutSec = 180
	} else {
		plan.FastTimeoutSec = 600
	}

	return plan
}

func isPullRequestEvent() bool {
	if os.Getenv("GITHUB_EVENT_NAME") == "pull_request" {
		return true
	}
	if os.Getenv("CI_MERGE_REQUEST_IID") != "" {
		return true
	}
	if os.Getenv("BITBUCKET_PR_ID") != "" || os.Getenv("CHANGE_ID") != "" {
		return true
	}
	return false
}
