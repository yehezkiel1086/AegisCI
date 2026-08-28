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

type SemgrepScanner struct {
	BinaryPath string
	Ruleset    string
	CustomArgs []string
}

func NewSemgrepScanner() *SemgrepScanner {
	path, _ := exec.LookPath("semgrep")
	return &SemgrepScanner{
		BinaryPath: path,
		Ruleset:    "auto",
	}
}

func (s *SemgrepScanner) Name() string {
	return "Semgrep"
}

func (s *SemgrepScanner) Category() string {
	return "SAST"
}

func (s *SemgrepScanner) IsAvailable() bool {
	return s.BinaryPath != ""
}

func (s *SemgrepScanner) Scan(ctx context.Context, targetDir string) (*sarif.Report, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("semgrep binary not found in PATH")
	}

	tmpFile, err := os.CreateTemp("", "semgrep-sarif-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file for semgrep output: %w", err)
	}
	tmpFilePath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpFilePath)

	ruleset := s.Ruleset
	if ruleset == "" {
		ruleset = "auto"
	}

	args := []string{
		"scan",
		"--config=" + ruleset,
		"--sarif",
		"--output=" + tmpFilePath,
		"--quiet",
		targetDir,
	}

	if len(s.CustomArgs) > 0 {
		args = append(args, s.CustomArgs...)
	}

	cmd := exec.CommandContext(ctx, s.BinaryPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// semgrep returns non-zero exit codes when findings exist
	_ = cmd.Run()

	fileInfo, statErr := os.Stat(tmpFilePath)
	if statErr != nil || fileInfo.Size() == 0 {
		return nil, fmt.Errorf("semgrep did not produce a SARIF output file (stderr: %s)", stderr.String())
	}

	data, err := os.ReadFile(tmpFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read semgrep SARIF output: %w", err)
	}

	report, err := sarif.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semgrep SARIF report: %w", err)
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
