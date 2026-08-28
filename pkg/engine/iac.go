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

// CheckovScanner implements the Scanner interface for Infrastructure-as-Code (IaC) analysis.
type CheckovScanner struct {
	BinaryPath string
	CustomArgs []string
}

// NewCheckovScanner creates a new Checkov IaC scanner.
func NewCheckovScanner() *CheckovScanner {
	path, _ := exec.LookPath("checkov")
	return &CheckovScanner{
		BinaryPath: path,
	}
}

// Name returns the scanner engine name.
func (c *CheckovScanner) Name() string {
	return "Checkov"
}

// Category returns the security pillar category.
func (c *CheckovScanner) Category() string {
	return "IaC & Containers"
}

// IsAvailable checks whether the checkov executable exists in PATH.
func (c *CheckovScanner) IsAvailable() bool {
	return c.BinaryPath != ""
}

// Scan executes Checkov against the target directory and parses SARIF findings.
func (c *CheckovScanner) Scan(ctx context.Context, targetDir string) (*sarif.Report, error) {
	if !c.IsAvailable() {
		return nil, fmt.Errorf("checkov binary not found in PATH")
	}

	tmpDir, err := os.MkdirTemp("", "checkov-sarif-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for checkov output: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	args := []string{
		"-d", targetDir,
		"--output", "sarif",
		"--output-file-path", tmpDir,
		"--soft-fail",
		"--quiet",
		"--compact",
	}

	if len(c.CustomArgs) > 0 {
		args = append(args, c.CustomArgs...)
	}

	cmd := exec.CommandContext(ctx, c.BinaryPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	_ = cmd.Run()

	// Checkov creates results_sarif.sarif inside tmpDir
	sarifPath := filepath.Join(tmpDir, "results_sarif.sarif")
	if _, err := os.Stat(sarifPath); os.IsNotExist(err) {
		// If no findings, checkov might not generate results_sarif.sarif
		report, _ := sarif.New(sarif.Version210)
		run := sarif.NewRunWithInformationURI("checkov", "https://github.com/bridgecrewio/checkov")
		report.AddRun(run)
		return report, nil
	}

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkov SARIF output: %w", err)
	}

	if len(bytes.TrimSpace(data)) == 0 {
		report, _ := sarif.New(sarif.Version210)
		run := sarif.NewRunWithInformationURI("checkov", "https://github.com/bridgecrewio/checkov")
		report.AddRun(run)
		return report, nil
	}

	report, err := sarif.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse checkov SARIF report: %w", err)
	}

	// Normalize relative artifact locations
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
