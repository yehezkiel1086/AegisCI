package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// GitleaksScanner implements the Scanner interface for Gitleaks secret detection.
type GitleaksScanner struct {
	BinaryPath string
	CustomArgs []string
}

// NewGitleaksScanner creates a new Gitleaks scanner.
func NewGitleaksScanner() *GitleaksScanner {
	path, _ := exec.LookPath("gitleaks")
	return &GitleaksScanner{
		BinaryPath: path,
	}
}

// Name returns the name of the scanner.
func (g *GitleaksScanner) Name() string {
	return "Gitleaks"
}

// Category returns the security pillar category.
func (g *GitleaksScanner) Category() string {
	return "Secrets Detection"
}

// IsAvailable checks whether the gitleaks executable exists.
func (g *GitleaksScanner) IsAvailable() bool {
	return g.BinaryPath != ""
}

// Scan executes gitleaks against the target directory and returns a SARIF report.
func (g *GitleaksScanner) Scan(ctx context.Context, targetDir string) (*sarif.Report, error) {
	if !g.IsAvailable() {
		return nil, fmt.Errorf("gitleaks binary not found in PATH")
	}

	tmpFile, err := os.CreateTemp("", "gitleaks-sarif-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file for gitleaks output: %w", err)
	}
	tmpFilePath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpFilePath)

	// Build arguments
	args := []string{
		"detect",
		"--source", targetDir,
		"--report-format", "sarif",
		"--report-path", tmpFilePath,
		"--no-banner",
		"--exit-code", "0", // Always return 0 so we can parse findings from SARIF
	}

	if len(g.CustomArgs) > 0 {
		args = append(args, g.CustomArgs...)
	}

	cmd := exec.CommandContext(ctx, g.BinaryPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gitleaks execution failed: %w (stderr: %s)", err, stderr.String())
	}

	// Read generated SARIF report
	if _, err := os.Stat(tmpFilePath); os.IsNotExist(err) {
		// No report was written, return empty report
		report, _ := sarif.New(sarif.Version210)
		run := sarif.NewRunWithInformationURI("gitleaks", "https://github.com/gitleaks/gitleaks")
		report.AddRun(run)
		return report, nil
	}

	data, err := os.ReadFile(tmpFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read gitleaks SARIF output: %w", err)
	}

	if len(bytes.TrimSpace(data)) == 0 {
		report, _ := sarif.New(sarif.Version210)
		run := sarif.NewRunWithInformationURI("gitleaks", "https://github.com/gitleaks/gitleaks")
		report.AddRun(run)
		return report, nil
	}

	report, err := sarif.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks SARIF report: %w", err)
	}

	// Standardize relative paths if needed
	absTarget, _ := filepath.Abs(targetDir)
	for _, run := range report.Runs {
		for _, res := range run.Results {
			for _, loc := range res.Locations {
				if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation != nil && loc.PhysicalLocation.ArtifactLocation.URI != nil {
					uri := *loc.PhysicalLocation.ArtifactLocation.URI
					if rel, err := filepath.Rel(absTarget, uri); err == nil && !filepath.IsAbs(rel) {
						normalized := filepath.ToSlash(rel)
						loc.PhysicalLocation.ArtifactLocation.URI = &normalized
					}
				}
			}
		}
	}

	return report, nil
}
