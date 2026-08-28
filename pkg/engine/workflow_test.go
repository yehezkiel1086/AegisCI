package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestZizmorScanner_NoWorkflowsDir(t *testing.T) {
	tmpDir := t.TempDir()
	scanner := &ZizmorScanner{
		BinaryPath: "zizmor", // Mock path
	}

	// When no .github/workflows exists, Scan should return empty report cleanly
	report, err := scanner.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Expected no error when .github/workflows doesn't exist, got: %v", err)
	}
	if report == nil || len(report.Runs) != 1 {
		t.Fatalf("Expected empty SARIF report with 1 run, got: %+v", report)
	}
}

func TestZizmorScanner_NotAvailable(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(tmpDir, ".github", "workflows"), 0755)

	scanner := &ZizmorScanner{
		BinaryPath: "",
	}

	if scanner.IsAvailable() {
		t.Errorf("Expected scanner to be unavailable when BinaryPath is empty")
	}

	_, err := scanner.Scan(context.Background(), tmpDir)
	if err == nil {
		t.Errorf("Expected error when zizmor is not available")
	}
}
