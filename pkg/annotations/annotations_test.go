package annotations

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yehezkiel1086/AegisCI/pkg/aggregator"
)

func TestEmitter_Emit(t *testing.T) {
	var buf bytes.Buffer
	emitter := NewEmitter(&buf)

	summary := &aggregator.Summary{
		Findings: []aggregator.Finding{
			{
				Engine:   "Semgrep",
				RuleID:   "sql-injection",
				Severity: "HIGH",
				Message:  "User input directly concatenated into SQL query",
				FilePath: "pkg/db/query.go",
				Line:     42,
			},
			{
				Engine:   "Checkov",
				RuleID:   "CKV_AWS_18",
				Severity: "MEDIUM",
				Message:  "S3 Bucket access logging not enabled",
				FilePath: "terraform/s3.tf",
				Line:     15,
			},
			{
				Engine:   "Gitleaks",
				RuleID:   "generic-api-key",
				Severity: "LOW",
				Message:  "Dummy test secret",
				FilePath: "config.env",
				Line:     1,
			},
		},
	}

	emitter.Emit(summary)
	output := buf.String()

	// Verify error annotation
	if !strings.Contains(output, "::error file=pkg/db/query.go,line=42,title=[Semgrep] sql-injection (HIGH)::User input directly concatenated into SQL query") {
		t.Errorf("Expected error annotation for SQL injection, got:\n%s", output)
	}

	// Verify warning annotation
	if !strings.Contains(output, "::warning file=terraform/s3.tf,line=15,title=[Checkov] CKV_AWS_18 (MEDIUM)::S3 Bucket access logging not enabled") {
		t.Errorf("Expected warning annotation for Checkov finding, got:\n%s", output)
	}

	// Verify notice annotation
	if !strings.Contains(output, "::notice file=config.env,line=1,title=[Gitleaks] generic-api-key (LOW)::Dummy test secret") {
		t.Errorf("Expected notice annotation for low severity finding, got:\n%s", output)
	}
}
