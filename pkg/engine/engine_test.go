package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// MockScanner implements Scanner and SBOMGenerator for unit testing.
type MockScanner struct {
	name       string
	category   string
	available  bool
	report     *sarif.Report
	err        error
	delay      time.Duration
	sbomErr    error
	sbomCalled bool
}

func (m *MockScanner) Name() string     { return m.name }
func (m *MockScanner) Category() string { return m.category }
func (m *MockScanner) IsAvailable() bool { return m.available }
func (m *MockScanner) Scan(ctx context.Context, targetDir string) (*sarif.Report, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.report, m.err
}

func (m *MockScanner) GenerateSBOM(ctx context.Context, targetDir, format, outputPath string) error {
	m.sbomCalled = true
	return m.sbomErr
}

func TestOrchestrator_Run(t *testing.T) {
	rep1, _ := sarif.New(sarif.Version210)
	rep1.AddRun(sarif.NewRunWithInformationURI("mock1", "https://example.com"))

	rep2, _ := sarif.New(sarif.Version210)
	rep2.AddRun(sarif.NewRunWithInformationURI("mock2", "https://example.com"))

	scanner1 := &MockScanner{name: "Gitleaks", category: "Secrets", available: true, report: rep1}
	scanner2 := &MockScanner{name: "Semgrep", category: "SAST", available: true, report: rep2}
	scanner3 := &MockScanner{name: "Trivy", category: "SCA", available: true, report: rep1}
	scanner4 := &MockScanner{name: "Checkov", category: "IaC", available: true, report: rep2}
	scanner5 := &MockScanner{name: "Zizmor", category: "CI Workflow", available: true, report: rep1}
	scanner6 := &MockScanner{name: "OWASP ZAP", category: "DAST", available: false}
	scanner7 := &MockScanner{name: "FailedScanner", category: "Other", available: true, err: errors.New("scan error")}

	orchestrator := NewOrchestrator(scanner1, scanner2, scanner3, scanner4, scanner5, scanner6, scanner7)
	results := orchestrator.Run(context.Background(), ".")

	if len(results) != 7 {
		t.Fatalf("Expected 7 results, got %d", len(results))
	}

	if results[0].Error != nil || results[0].Report == nil {
		t.Errorf("Expected Gitleaks to succeed, got error: %v", results[0].Error)
	}
	if results[1].Error != nil || results[1].Report == nil {
		t.Errorf("Expected Semgrep to succeed, got error: %v", results[1].Error)
	}
	if results[2].Error != nil || results[2].Report == nil {
		t.Errorf("Expected Trivy to succeed, got error: %v", results[2].Error)
	}
	if results[3].Error != nil || results[3].Report == nil {
		t.Errorf("Expected Checkov to succeed, got error: %v", results[3].Error)
	}
	if results[4].Error != nil || results[4].Report == nil {
		t.Errorf("Expected Zizmor to succeed, got error: %v", results[4].Error)
	}
	if results[5].Error == nil {
		t.Errorf("Expected OWASP ZAP (unavailable) to have error")
	}
	if results[6].Error == nil {
		t.Errorf("Expected FailedScanner to have error")
	}
}

func TestSBOMGenerator_Mock(t *testing.T) {
	mock := &MockScanner{
		name:      "Trivy",
		category:  "SCA",
		available: true,
	}

	var gen SBOMGenerator = mock
	err := gen.GenerateSBOM(context.Background(), ".", "cyclonedx-json", "sbom.json")
	if err != nil {
		t.Errorf("GenerateSBOM failed: %v", err)
	}
	if !mock.sbomCalled {
		t.Errorf("Expected GenerateSBOM to be called")
	}
}
