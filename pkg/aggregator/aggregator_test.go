package aggregator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/yehezkiel1086/AegisCI/pkg/config"
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

func TestAggregator_AddReportAndDeduplicate(t *testing.T) {
	agg, err := New()
	if err != nil {
		t.Fatalf("Failed to initialize aggregator: %v", err)
	}

	rep1 := createSampleReport("Semgrep", "sql-injection", "pkg/db/query.go", 42, "error")
	rep2 := createSampleReport("Gitleaks", "generic-api-key", "config/creds.env", 10, "error")
	// Duplicate finding
	rep3 := createSampleReport("Semgrep", "sql-injection", "pkg/db/query.go", 42, "error")

	agg.AddReport(rep1)
	agg.AddReport(rep2)
	agg.AddReport(rep3)

	summaryBefore := agg.ComputeSummary()
	if summaryBefore.Total != 3 {
		t.Errorf("Expected 3 findings before deduplication, got %d", summaryBefore.Total)
	}

	agg.Deduplicate()

	summaryAfter := agg.ComputeSummary()
	if summaryAfter.Total != 2 {
		t.Errorf("Expected 2 findings after deduplication, got %d", summaryAfter.Total)
	}

	if summaryAfter.High != 2 {
		t.Errorf("Expected 2 High findings, got %d", summaryAfter.High)
	}
}

func TestAggregator_ApplyPolicy(t *testing.T) {
	agg, err := New()
	if err != nil {
		t.Fatalf("Failed to initialize aggregator: %v", err)
	}

	rep1 := createSampleReport("Semgrep", "G401", "pkg/legacy/hash.go", 15, "warning")
	rep2 := createSampleReport("Gitleaks", "aws-access-token", "deploy/main.tf", 8, "error")
	agg.AddReport(rep1)
	agg.AddReport(rep2)

	policy := &config.PolicyConfig{
		Ignore: []config.PolicyIgnore{
			{
				ID:   "G401",
				Path: "pkg/legacy/hash.go",
			},
		},
	}

	agg.ApplyPolicy(policy)
	summary := agg.ComputeSummary()

	if summary.Total != 1 {
		t.Fatalf("Expected 1 finding after policy application, got %d", summary.Total)
	}
	if summary.Findings[0].RuleID != "aws-access-token" {
		t.Errorf("Expected remaining finding to be aws-access-token, got %s", summary.Findings[0].RuleID)
	}
}

func TestAggregator_ShouldFail(t *testing.T) {
	agg, err := New()
	if err != nil {
		t.Fatalf("Failed to initialize aggregator: %v", err)
	}

	rep := createSampleReport("Semgrep", "cors-misconfig", "server.go", 12, "warning") // maps to MEDIUM
	agg.AddReport(rep)

	if agg.ShouldFail(config.SeverityHigh) {
		t.Errorf("Warning finding should not fail on HIGH threshold")
	}

	if !agg.ShouldFail(config.SeverityMedium) {
		t.Errorf("Warning finding should fail on MEDIUM threshold")
	}

	if !agg.ShouldFail(config.SeverityLow) {
		t.Errorf("Warning finding should fail on LOW threshold")
	}

	if agg.ShouldFail(config.SeverityNone) {
		t.Errorf("Should never fail when threshold is NONE")
	}
}

func TestAggregator_SaveAndLoad(t *testing.T) {
	agg, err := New()
	if err != nil {
		t.Fatalf("Failed to initialize aggregator: %v", err)
	}

	rep := createSampleReport("Gitleaks", "jwt-secret", "auth.go", 55, "error")
	agg.AddReport(rep)

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "results.sarif")

	if err := agg.SaveCombined(outputPath); err != nil {
		t.Fatalf("SaveCombined failed: %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatalf("Output file was not created at %s", outputPath)
	}

	// Verify reading it back
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
