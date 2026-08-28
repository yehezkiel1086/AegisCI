package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

type MockPlugin struct {
	name string
	ver  string
	cat  string
	rep  *sarif.Report
	err  error
}

func (m *MockPlugin) Name() string     { return m.name }
func (m *MockPlugin) Version() string  { return m.ver }
func (m *MockPlugin) Category() string { return m.cat }
func (m *MockPlugin) Execute(ctx context.Context, targetDir string) (*sarif.Report, error) {
	return m.rep, m.err
}

func TestPluginAdapter(t *testing.T) {
	rep, _ := sarif.New(sarif.Version210)
	rep.AddRun(sarif.NewRunWithInformationURI("CustomOrgRule", "https://internal.corp"))

	p := &MockPlugin{
		name: "CustomCompliancePlugin",
		ver:  "2.1.0",
		cat:  "Enterprise Compliance",
		rep:  rep,
	}

	scanner := AsScanner(p)
	if scanner.Name() != "CustomCompliancePlugin" {
		t.Errorf("Expected scanner name CustomCompliancePlugin, got %s", scanner.Name())
	}
	if scanner.Category() != "Enterprise Compliance" {
		t.Errorf("Expected category Enterprise Compliance, got %s", scanner.Category())
	}
	if !scanner.IsAvailable() {
		t.Errorf("Expected scanner to be available")
	}

	report, err := scanner.Scan(context.Background(), ".")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(report.Runs) != 1 {
		t.Errorf("Expected 1 run, got %d", len(report.Runs))
	}
}

func TestDiscoverPlugins(t *testing.T) {
	tmpDir := t.TempDir()

	// Create dummy plugin files
	_ = os.WriteFile(filepath.Join(tmpDir, "pci-dss-check.sh"), []byte("#!/bin/sh\n"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, "hipaa-audit.py"), []byte("#!/usr/bin/env python3\n"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, "README.txt"), []byte("Not a plugin"), 0644) // Should be ignored

	plugins, err := DiscoverPlugins(tmpDir)
	if err != nil {
		t.Fatalf("DiscoverPlugins failed: %v", err)
	}

	if len(plugins) != 2 {
		t.Fatalf("Expected 2 discovered plugins, got %d", len(plugins))
	}

	names := make(map[string]bool)
	for _, p := range plugins {
		names[p.Name()] = true
	}

	if !names["pci-dss-check"] || !names["hipaa-audit"] {
		t.Errorf("Expected pci-dss-check and hipaa-audit plugins, got %+v", names)
	}
}
