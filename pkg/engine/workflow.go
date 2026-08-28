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

// ZizmorScanner implements the Scanner interface for auditing GitHub Actions CI workflows.
type ZizmorScanner struct {
	BinaryPath string
	CustomArgs []string
}

// NewZizmorScanner creates a new Zizmor CI workflow security scanner.
func NewZizmorScanner() *ZizmorScanner {
	path, _ := exec.LookPath("zizmor")
	return &ZizmorScanner{
		BinaryPath: path,
	}
}

// Name returns the scanner engine name.
func (z *ZizmorScanner) Name() string {
	return "Zizmor"
}

// Category returns the security pillar category.
func (z *ZizmorScanner) Category() string {
	return "CI Workflow Hardening"
}

// IsAvailable checks whether the zizmor executable exists in PATH.
func (z *ZizmorScanner) IsAvailable() bool {
	return z.BinaryPath != ""
}

// Scan executes Zizmor across .github/workflows/ and returns a SARIF report.
func (z *ZizmorScanner) Scan(ctx context.Context, targetDir string) (*sarif.Report, error) {
	if !z.IsAvailable() {
		return nil, fmt.Errorf("zizmor binary not found in PATH")
	}

	// Check if .github/workflows exists
	workflowsDir := filepath.Join(targetDir, ".github", "workflows")
	if _, err := os.Stat(workflowsDir); os.IsNotExist(err) {
		report, _ := sarif.New(sarif.Version210)
		run := sarif.NewRunWithInformationURI("zizmor", "https://woodruffw.github.io/zizmor/")
		report.AddRun(run)
		return report, nil
	}

	args := []string{
		targetDir,
		"--format", "sarif",
		"--quiet",
	}

	if len(z.CustomArgs) > 0 {
		args = append(args, z.CustomArgs...)
	}

	cmd := exec.CommandContext(ctx, z.BinaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run()

	data := stdout.Bytes()
	if len(bytes.TrimSpace(data)) == 0 {
		report, _ := sarif.New(sarif.Version210)
		run := sarif.NewRunWithInformationURI("zizmor", "https://woodruffw.github.io/zizmor/")
		report.AddRun(run)
		return report, nil
	}

	report, err := sarif.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse zizmor SARIF report: %w (stderr: %s)", err, stderr.String())
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
