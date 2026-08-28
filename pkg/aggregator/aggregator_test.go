package aggregator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/yehezkiel1086/AegisCI/pkg/config"
	"github.com/yehezkiel1086/AegisCI/pkg/policy"
)

func createSampleReport(toolName, ruleID, uri string, line int, level string) *sarif.Report {
	report, _ := sarif.New(sarif.Version210)
	run := sarif.NewRunWithInformationURI(toolName, "https://example.com")

	result := sarif.NewRuleResult(ruleID).
		WithMessage(sarif.NewTextMessage("Test security vulnerability")).
		WithLevel(level)

	location := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(uri)).
		WithRegion(sarif.NewRegion().WithStartLine(line))

	result.WithLocations([]*sarif.Location{sarif.NewLocationWithPhysicalLocation(location)})
	run.AddResult(result)
	report.AddRun(run)
	return report
}

func TestAggregator_MultiEngineDeduplicate(t *testing.T) {
	agg, err := New()
	if err != nil {
		t.Fatalf("Failed to initialize aggregator: %v", err)
	}

	repSAST := createSampleReport("Semgrep", "sql-injection", "pkg/db/query.go", 42, "error")
	repSecrets := createSampleReport("Gitleaks", "generic-api-key", "config/creds.env", 10, "error")
	repSCA := createSampleReport("Trivy", "CVE-2023-44487", "go.mod", 1, "error")
	repIaC := createSampleReport("Checkov", "CKV_AWS_18", "terraform/s3.tf", 5, "warning")
	// Duplicate finding
	repDup := createSampleReport("Semgrep", "sql-injection", "pkg/db/query.go", 42, "error")

	agg.AddReport(repSAST)
	agg.AddReport(repSecrets)
	agg.AddReport(repSCA)
	agg.AddReport(repIaC)
	agg.AddReport(repDup)

	summaryBefore := agg.ComputeSummary()
	if summaryBefore.Total != 5 {
		t.Errorf("Expected 5 findings before deduplication, got %d", summaryBefore.Total)
	}

	agg.Deduplicate()

	summaryAfter := agg.ComputeSummary()
	if summaryAfter.Total != 4 {
		t.Errorf("Expected 4 findings after deduplication, got %d", summaryAfter.Total)
	}
	if summaryAfter.ByEngine["Semgrep"] != 1 {
		t.Errorf("Expected 1 Semgrep finding, got %d", summaryAfter.ByEngine["Semgrep"])
	}
	if summaryAfter.ByEngine["Trivy"] != 1 {
		t.Errorf("Expected 1 Trivy finding, got %d", summaryAfter.ByEngine["Trivy"])
	}
	if summaryAfter.ByEngine["Checkov"] != 1 {
		t.Errorf("Expected 1 Checkov finding, got %d", summaryAfter.ByEngine["Checkov"])
	}
}

func TestAggregator_ApplyPolicyWithExpiration(t *testing.T) {
	agg, err := New()
	if err != nil {
		t.Fatalf("Failed to initialize aggregator: %v", err)
	}

	rep1 := createSampleReport("Semgrep", "G401", "pkg/legacy/hash.go", 15, "warning")
	rep2 := createSampleReport("Gitleaks", "aws-access-token", "deploy/main.tf", 8, "error")
	agg.AddReport(rep1)
	agg.AddReport(rep2)

	p := &policy.Policy{
		Ignore: []policy.RuleIgnore{
			{
				ID:      "G401",
				Path:    "pkg/legacy/hash.go",
				Expires: "2099-01-01",
			},
		},
	}

	agg.ApplyPolicy(p)
	summary := agg.ComputeSummary()

	if summary.Total != 1 {
		t.Fatalf("Expected 1 finding after policy application, got %d", summary.Total)
	}
	if summary.Suppressed != 1 {
		t.Errorf("Expected 1 suppressed finding, got %d", summary.Suppressed)
	}
	if summary.Findings[0].RuleID != "aws-access-token" {
		t.Errorf("Expected remaining finding to be aws-access-token, got %s", summary.Findings[0].RuleID)
	}
}

func TestAggregator_EvaluateGate(t *testing.T) {
	agg, err := New()
	if err != nil {
		t.Fatalf("Failed to initialize aggregator: %v", err)
	}

	rep := createSampleReport("Semgrep", "cors-misconfig", "server.go", 12, "warning") // maps to MEDIUM
	agg.AddReport(rep)

	p := &policy.Policy{}

	// Should not fail on HIGH threshold
	shouldFail, _ := agg.EvaluateGate(p, config.SeverityHigh)
	if shouldFail {
		t.Errorf("Warning finding should not fail on HIGH threshold")
	}

	// Should fail on MEDIUM threshold
	shouldFail, reason := agg.EvaluateGate(p, config.SeverityMedium)
	if !shouldFail {
		t.Errorf("Warning finding should fail on MEDIUM threshold")
	}
	if reason == "" {
		t.Errorf("Expected failure reason, got empty")
	}
}

func TestAggregator_SaveAndLoad(t *testing.T) {
	agg, err := New()
	if err != nil {
		t.Fatalf("Failed to initialize aggregator: %v", err)
	}

	rep := createSampleReport("Trivy", "CVE-2023-1234", "go.mod", 1, "error")
	agg.AddReport(rep)

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "results.sarif")

	if err := agg.SaveCombined(outputPath); err != nil {
		t.Fatalf("SaveCombined failed: %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatalf("Output file was not created at %s", outputPath)
	}

	newAgg, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := newAgg.MergeReportFile(outputPath); err != nil {
		t.Fatalf("MergeReportFile failed: %v", err)
	}
	summary := newAgg.ComputeSummary()
	if summary.Total != 1 {
		t.Errorf("Expected 1 finding in reloaded report, got %d", summary.Total)
	}
}
