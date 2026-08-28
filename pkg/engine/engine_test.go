package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// MockScanner implements the Scanner interface for unit testing.
type MockScanner struct {
	name      string
	category  string
	available bool
	report    *sarif.Report
	err       error
	delay     time.Duration
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

func TestOrchestrator_Run(t *testing.T) {
	rep1, _ := sarif.New(sarif.Version210)
	rep1.AddRun(sarif.NewRunWithInformationURI("mock1", "https://example.com"))

	rep2, _ := sarif.New(sarif.Version210)
	rep2.AddRun(sarif.NewRunWithInformationURI("mock2", "https://example.com"))

	scanner1 := &MockScanner{name: "Scanner1", category: "Secrets", available: true, report: rep1}
	scanner2 := &MockScanner{name: "Scanner2", category: "SAST", available: true, report: rep2}
	scanner3 := &MockScanner{name: "Scanner3", category: "SCA", available: false}
	scanner4 := &MockScanner{name: "Scanner4", category: "DAST", available: true, err: errors.New("scan error")}

	orchestrator := NewOrchestrator(scanner1, scanner2, scanner3, scanner4)
	results := orchestrator.Run(context.Background(), ".")

	if len(results) != 4 {
		t.Fatalf("Expected 4 results, got %d", len(results))
	}

	if results[0].Error != nil || results[0].Report == nil {
		t.Errorf("Expected scanner 1 to succeed, got error: %v", results[0].Error)
	}

	if results[1].Error != nil || results[1].Report == nil {
		t.Errorf("Expected scanner 2 to succeed, got error: %v", results[1].Error)
	}

	if results[2].Error == nil {
		t.Errorf("Expected scanner 3 (unavailable) to have error")
	}

	if results[3].Error == nil {
		t.Errorf("Expected scanner 4 to have error: scan error")
	}
}

func TestOrchestrator_Timeout(t *testing.T) {
	scannerSlow := &MockScanner{
		name:      "SlowScanner",
		category:  "SAST",
		available: true,
		delay:     500 * time.Millisecond,
	}

	orchestrator := NewOrchestrator(scannerSlow)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	results := orchestrator.Run(ctx, ".")
	if len(results) != 1 {
		t.Fatalf("Expected 1 result")
	}

	if results[0].Error == nil {
		t.Fatalf("Expected timeout error for slow scanner")
	}
}
