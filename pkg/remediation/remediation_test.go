package remediation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yehezkiel1086/AegisCI/pkg/aggregator"
)

func TestEngine_GenerateRemediationsHeuristic(t *testing.T) {
	engine := NewEngine("openai", "", "gpt-4o", "")

	findings := []aggregator.Finding{
		{
			Engine:   "Semgrep",
			RuleID:   "sql-injection",
			Severity: "HIGH",
			Message:  "Unsanitized parameter passed to db.Query",
			FilePath: "pkg/db/query.go",
			Line:     42,
		},
	}

	suggestions, err := engine.GenerateRemediations(context.Background(), findings, ".")
	if err != nil {
		t.Fatalf("GenerateRemediations failed: %v", err)
	}

	if len(suggestions) != 1 {
		t.Fatalf("Expected 1 suggestion, got %d", len(suggestions))
	}

	s := suggestions[0]
	if s.RuleID != "sql-injection" {
		t.Errorf("Expected RuleID sql-injection, got %s", s.RuleID)
	}
	if !strings.Contains(s.PatchDiff, "diff --git") {
		t.Errorf("Expected patch diff to contain 'diff --git', got:\n%s", s.PatchDiff)
	}
}

func TestSavePatches(t *testing.T) {
	tmpDir := t.TempDir()

	suggestions := []RemediationSuggestion{
		{
			RuleID:        "G401",
			Engine:        "Semgrep",
			FilePath:      "pkg/hash.go",
			Line:          10,
			Severity:      "MEDIUM",
			Vulnerability: "MD5 weak hash",
			Explanation:   "Use SHA-256 instead of MD5",
			PatchDiff:     "diff --git a/pkg/hash.go b/pkg/hash.go\n- md5.New()\n+ sha256.New()\n",
		},
	}

	if err := SavePatches(suggestions, tmpDir); err != nil {
		t.Fatalf("SavePatches failed: %v", err)
	}

	patchFile := filepath.Join(tmpDir, "patch-01-G401.patch")
	if _, err := os.Stat(patchFile); os.IsNotExist(err) {
		t.Errorf("Expected patch file %s to be created", patchFile)
	}

	summaryFile := filepath.Join(tmpDir, "remediations.md")
	if _, err := os.Stat(summaryFile); os.IsNotExist(err) {
		t.Errorf("Expected remediations.md to be created")
	}
}
