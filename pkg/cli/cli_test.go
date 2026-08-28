package cli

import (
	"bytes"
	"testing"
)

func TestRootCommand(t *testing.T) {
	rootCmd.SetArgs([]string{"--help"})
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Root help command failed: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Errorf("Expected help output, got empty")
	}
}

func TestVersionCommand(t *testing.T) {
	Version = "4.0.0"
	Commit = "abcdef123"
	Date = "2026-08-28"
	BuiltBy = "test-builder"

	buf := new(bytes.Buffer)
	versionCmd.SetOut(buf)
	versionCmd.SetArgs([]string{})

	err := versionCmd.Execute()
	if err != nil {
		t.Fatalf("Version command failed: %v", err)
	}
}

func TestScanFlags(t *testing.T) {
	flags := scanCmd.Flags()

	if flags.Lookup("target") == nil {
		t.Errorf("Expected --target flag to be defined")
	}
	if flags.Lookup("mode") == nil {
		t.Errorf("Expected --mode flag to be defined")
	}
	if flags.Lookup("fail-on") == nil {
		t.Errorf("Expected --fail-on flag to be defined")
	}
	if flags.Lookup("config") == nil {
		t.Errorf("Expected --config flag to be defined")
	}
	if flags.Lookup("ai-remediation") == nil {
		t.Errorf("Expected --ai-remediation flag to be defined")
	}
	if flags.Lookup("dashboard-url") == nil {
		t.Errorf("Expected --dashboard-url flag to be defined")
	}
}
