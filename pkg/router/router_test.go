package router

import (
	"os"
	"testing"

	"github.com/yehezkiel1086/AegisCI/pkg/config"
)

func TestResolvePlan(t *testing.T) {
	t.Run("Explicit PRCheck mode", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Mode = config.ModePRCheck
		plan := ResolvePlan(cfg)

		if plan.EffectiveMode != config.ModePRCheck {
			t.Errorf("Expected effective mode to be pr-check, got %s", plan.EffectiveMode)
		}
	})

	t.Run("Explicit DeepScan mode", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Mode = config.ModeDeepScan
		plan := ResolvePlan(cfg)

		if plan.EffectiveMode != config.ModeDeepScan {
			t.Errorf("Expected effective mode to be deep-scan, got %s", plan.EffectiveMode)
		}
	})

	t.Run("Auto mode with Pull Request CI env", func(t *testing.T) {
		os.Setenv("GITHUB_EVENT_NAME", "pull_request")
		defer os.Unsetenv("GITHUB_EVENT_NAME")

		cfg := config.DefaultConfig()
		cfg.Mode = config.ModeAuto
		plan := ResolvePlan(cfg)

		if plan.EffectiveMode != config.ModePRCheck {
			t.Errorf("Expected auto mode during PR event to resolve to pr-check, got %s", plan.EffectiveMode)
		}
	})

	t.Run("Auto mode with Push/Merge CI env", func(t *testing.T) {
		os.Setenv("GITHUB_EVENT_NAME", "push")
		defer os.Unsetenv("GITHUB_EVENT_NAME")

		cfg := config.DefaultConfig()
		cfg.Mode = config.ModeAuto
		plan := ResolvePlan(cfg)

		if plan.EffectiveMode != config.ModeDeepScan {
			t.Errorf("Expected auto mode during Push event to resolve to deep-scan, got %s", plan.EffectiveMode)
		}
	})
}
