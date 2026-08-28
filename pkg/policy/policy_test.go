package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPolicy_ShouldIgnore(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	p := &Policy{
		Ignore: []RuleIgnore{
			{
				ID:      "G401",
				Path:    "pkg/legacy/hash.go",
				Reason:  "Non-cryptographic hash",
				Expires: "2026-12-31", // Not expired
			},
			{
				ID:      "CVE-2022-1234",
				Path:    "",
				Reason:  "Old expired exemption",
				Expires: "2025-01-01", // Expired
			},
			{
				ID:     "generic-api-key",
				Path:   "test/fixtures/**",
				Reason: "Synthetic test data",
			},
			{
				ID:     "CKV_DOCKER_2",
				Path:   "Dockerfile*",
				Reason: "Healthcheck not required on ephemeral workers",
			},
		},
	}

	tests := []struct {
		name       string
		ruleID     string
		path       string
		wantIgnore bool
	}{
		{
			name:       "Active unexpired rule matching ID and path",
			ruleID:     "G401",
			path:       "pkg/legacy/hash.go",
			wantIgnore: true,
		},
		{
			name:       "Active rule matching ID but different path",
			ruleID:     "G401",
			path:       "pkg/auth/hash.go",
			wantIgnore: false,
		},
		{
			name:       "Expired exemption should not ignore",
			ruleID:     "CVE-2022-1234",
			path:       "package.json",
			wantIgnore: false,
		},
		{
			name:       "Glob recursive match in test fixtures",
			ruleID:     "generic-api-key",
			path:       "test/fixtures/tokens/secret.env",
			wantIgnore: true,
		},
		{
			name:       "Glob wildcard for Dockerfile",
			ruleID:     "CKV_DOCKER_2",
			path:       "Dockerfile.worker",
			wantIgnore: true,
		},
		{
			name:       "Unrelated finding",
			ruleID:     "sql-injection",
			path:       "main.go",
			wantIgnore: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ignored, reason := p.ShouldIgnore(tt.ruleID, tt.path, now)
			if ignored != tt.wantIgnore {
				t.Errorf("ShouldIgnore(%q, %q) = %v (reason: %q), want %v", tt.ruleID, tt.path, ignored, reason, tt.wantIgnore)
			}
		})
	}
}

func TestPolicy_LicenseCheck(t *testing.T) {
	p := &Policy{
		LicensePolicy: LicensePolicy{
			Banned:  []string{"GPL-3.0", "AGPL-3.0"},
			Allowed: []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		},
	}

	// Banned
	if allowed, _ := p.IsLicenseAllowed("GPL-3.0"); allowed {
		t.Errorf("Expected GPL-3.0 to be banned")
	}

	// Allowed
	if allowed, _ := p.IsLicenseAllowed("MIT"); !allowed {
		t.Errorf("Expected MIT to be allowed")
	}

	// Not in allowed whitelist
	if allowed, _ := p.IsLicenseAllowed("CC-BY-4.0"); allowed {
		t.Errorf("Expected CC-BY-4.0 to be rejected because not in whitelist")
	}
}

func TestLoadPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, ".aegisci.yml")

	content := `version: "2.0"
settings:
  fail_on_unpatched_cves: false
  max_critical: 0
  max_high: 2
ignore:
  - id: "CKV_AWS_18"
    path: "terraform/s3.tf"
    reason: "Public assets bucket"
    expires: "2027-01-01"
license_policy:
  banned:
    - "GPL-3.0"
`
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	p, err := LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}
	if p == nil {
		t.Fatal("Expected policy, got nil")
	}
	if p.Settings.MaxHigh != 2 {
		t.Errorf("Expected MaxHigh = 2, got %d", p.Settings.MaxHigh)
	}
	if len(p.Ignore) != 1 || p.Ignore[0].ID != "CKV_AWS_18" {
		t.Errorf("Expected 1 ignore rule with ID CKV_AWS_18")
	}
}
