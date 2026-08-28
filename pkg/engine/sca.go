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

type TrivyScanner struct {
	BinaryPath string
	CustomArgs []string
}

func NewTrivyScanner() *TrivyScanner {
	path, _ := exec.LookPath("trivy")
	return &TrivyScanner{
		BinaryPath: path,
	}
}

func (t *TrivyScanner) Name() string {
	return "Trivy"
}

func (t *TrivyScanner) Category() string {
	return "SCA & Supply Chain"
}

func (t *TrivyScanner) IsAvailable() bool {
	return t.BinaryPath != ""
}

func (t *TrivyScanner) Scan(ctx context.Context, targetDir string) (*sarif.Report, error) {
	if !t.IsAvailable() {
		return nil, fmt.Errorf("trivy binary not found in PATH")
	}

	tmpFile, err := os.CreateTemp("", "trivy-sarif-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file for trivy output: %w", err)
	}
	tmpFilePath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpFilePath)

	args := []string{
		"fs",
		"--scanners", "vuln",
		"--format", "sarif",
		"--output", tmpFilePath,
		"--quiet",
		targetDir,
	}

	if len(t.CustomArgs) > 0 {
		args = append(args, t.CustomArgs...)
	}

	cmd := exec.CommandContext(ctx, t.BinaryPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	_ = cmd.Run()

	fileInfo, statErr := os.Stat(tmpFilePath)
	if statErr != nil || fileInfo.Size() == 0 {
		return nil, fmt.Errorf("trivy did not produce a SARIF output file (stderr: %s)", stderr.String())
	}

	data, err := os.ReadFile(tmpFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read trivy SARIF output: %w", err)
	}

	report, err := sarif.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trivy SARIF report: %w", err)
	}

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

func (t *TrivyScanner) GenerateSBOM(ctx context.Context, targetDir, format, outputPath string) error {
	if !t.IsAvailable() {
		return fmt.Errorf("trivy binary not found in PATH")
	}

	// map format argument to trivy format flags
	trivyFormat := "cyclonedx"
	if format == "spdx-json" || format == "spdx" {
		trivyFormat = "spdx-json"
	} else if format == "cyclonedx-json" || format == "cyclonedx" {
		trivyFormat = "cyclonedx"
	}

	if dir := filepath.Dir(outputPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory for SBOM output: %w", err)
		}
	}

	args := []string{
		"fs",
		"--format", trivyFormat,
		"--output", outputPath,
		"--quiet",
		targetDir,
	}

	cmd := exec.CommandContext(ctx, t.BinaryPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to generate SBOM with trivy: %w (stderr: %s)", err, stderr.String())
	}

	return nil
}
