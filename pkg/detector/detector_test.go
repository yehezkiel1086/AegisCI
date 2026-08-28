package detector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetect(t *testing.T) {
	tmpDir := t.TempDir()

	// Create dummy files
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte("FROM alpine"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, ".github", "workflows"), 0755); err != nil {
		t.Fatal(err)
	}

	info, err := Detect(tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	hasGo := false
	for _, l := range info.Languages {
		if l == "Go" {
			hasGo = true
			break
		}
	}
	if !hasGo {
		t.Errorf("Expected Go to be detected in languages, got %+v", info.Languages)
	}

	hasDocker := false
	for _, i := range info.Infrastructure {
		if i == "Docker/Containers" {
			hasDocker = true
			break
		}
	}
	if !hasDocker {
		t.Errorf("Expected Docker/Containers in infrastructure, got %+v", info.Infrastructure)
	}

	if !info.HasWorkflows {
		t.Errorf("Expected HasWorkflows to be true")
	}
}
