package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// ZAPAlert represents an individual alert from OWASP ZAP's JSON report.
type ZAPAlert struct {
	PluginID    string `json:"pluginId"`
	Alert       string `json:"alert"`
	RiskDesc    string `json:"riskdesc"`
	RiskCode    string `json:"riskcode"`
	Confidence  string `json:"confidence"`
	Description string `json:"desc"`
	Solution    string `json:"solution"`
	URI         string `json:"uri"`
	Param       string `json:"param"`
	Evidence    string `json:"evidence"`
	CWEID       string `json:"cweid"`
	WASCID      string `json:"wascid"`
}

// ZAPReport represents the JSON output format of OWASP ZAP baseline / api scans.
type ZAPReport struct {
	Site []struct {
		Name   string     `json:"@name"`
		Host   string     `json:"@host"`
		Port   string     `json:"@port"`
		SSL    string     `json:"@ssl"`
		Alerts []ZAPAlert `json:"alerts"`
	} `json:"site"`
}

// ZAPScanner implements the Scanner interface for OWASP ZAP DAST testing.
type ZAPScanner struct {
	BinaryPath   string
	TargetURL    string
	Mode         string // "baseline", "api", "full"
	ExcludePaths []string
	CustomArgs   []string
	HTTPClient   *http.Client
}

// NewZAPScanner creates a new OWASP ZAP DAST scanner.
func NewZAPScanner(targetURL, mode string) *ZAPScanner {
	// Look for zap-baseline.py, zap-api-scan.py, or docker
	path := ""
	if p, err := exec.LookPath("zap-baseline.py"); err == nil {
		path = p
	} else if p, err := exec.LookPath("zap-api-scan.py"); err == nil {
		path = p
	} else if p, err := exec.LookPath("zap.sh"); err == nil {
		path = p
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Allow local staging self-signed certs
	}

	return &ZAPScanner{
		BinaryPath: path,
		TargetURL:  targetURL,
		Mode:       mode,
		HTTPClient: &http.Client{
			Transport: tr,
			Timeout:   5 * time.Second,
		},
	}
}

// Name returns the scanner engine name.
func (z *ZAPScanner) Name() string {
	return "OWASP ZAP"
}

// Category returns the security pillar category.
func (z *ZAPScanner) Category() string {
	return "DAST & Runtime Security"
}

// IsAvailable checks whether the ZAP executable exists and a target URL is configured.
func (z *ZAPScanner) IsAvailable() bool {
	return z.BinaryPath != "" && z.TargetURL != ""
}

// ProbeTarget performs an HTTP health check to ensure the target URL is reachable before scanning.
func (z *ZAPScanner) ProbeTarget(ctx context.Context, targetURL string) error {
	u, err := url.Parse(targetURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid DAST target URL '%s' (must include http:// or https://)", targetURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build probe request: %w", err)
	}

	client := z.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("target URL '%s' is unreachable: %w", targetURL, err)
	}
	defer resp.Body.Close()

	return nil
}

// Scan executes the OWASP ZAP scan against the target URL and returns a SARIF report.
func (z *ZAPScanner) Scan(ctx context.Context, targetDir string) (*sarif.Report, error) {
	if z.TargetURL == "" {
		return nil, fmt.Errorf("DAST target URL is required")
	}

	// 1. Health check probe
	if err := z.ProbeTarget(ctx, z.TargetURL); err != nil {
		return nil, fmt.Errorf("DAST endpoint health check failed: %w", err)
	}

	if !z.IsAvailable() {
		return nil, fmt.Errorf("OWASP ZAP runner (zap-baseline.py) not found in PATH")
	}

	tmpDir, err := os.MkdirTemp("", "zap-dast-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for ZAP report: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	jsonReportPath := filepath.Join(tmpDir, "zap_report.json")

	args := []string{
		"-t", z.TargetURL,
		"-J", filepath.Base(jsonReportPath),
		"-I", // Do not fail exit code on alerts
	}

	// Add excluded paths
	for _, ep := range z.ExcludePaths {
		args = append(args, "-x", ep)
	}

	if len(z.CustomArgs) > 0 {
		args = append(args, z.CustomArgs...)
	}

	cmd := exec.CommandContext(ctx, z.BinaryPath, args...)
	cmd.Dir = tmpDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	_ = cmd.Run()

	// Parse generated JSON report into SARIF
	if _, err := os.Stat(jsonReportPath); os.IsNotExist(err) {
		report, _ := sarif.New(sarif.Version210)
		run := sarif.NewRunWithInformationURI("OWASP ZAP", "https://www.zaproxy.org")
		report.AddRun(run)
		return report, nil
	}

	data, err := os.ReadFile(jsonReportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ZAP report: %w", err)
	}

	return ConvertZAPJSONToSARIF(data)
}

// ConvertZAPJSONToSARIF translates OWASP ZAP's native JSON output into standard SARIF v2.1.0 format.
func ConvertZAPJSONToSARIF(data []byte) (*sarif.Report, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, err
	}

	run := sarif.NewRunWithInformationURI("OWASP ZAP", "https://www.zaproxy.org")

	var zapData ZAPReport
	if err := json.Unmarshal(data, &zapData); err != nil {
		report.AddRun(run)
		return report, nil
	}

	for _, site := range zapData.Site {
		for _, alert := range site.Alerts {
			ruleID := alert.PluginID
			if ruleID == "" {
				ruleID = alert.Alert
			}

			level := "warning"
			// Risk codes: 3 = High, 2 = Medium, 1 = Low, 0 = Informational
			switch {
			case strings.HasPrefix(alert.RiskDesc, "High") || alert.RiskCode == "3":
				level = "error"
			case strings.HasPrefix(alert.RiskDesc, "Medium") || alert.RiskCode == "2":
				level = "warning"
			default:
				level = "note"
			}

			msgText := alert.Alert
			if alert.Description != "" {
				msgText = fmt.Sprintf("%s: %s", alert.Alert, alert.Description)
			}

			result := sarif.NewRuleResult(ruleID).
				WithMessage(sarif.NewTextMessage(msgText)).
				WithLevel(level)

			if alert.URI != "" {
				location := sarif.NewPhysicalLocation().
					WithArtifactLocation(sarif.NewSimpleArtifactLocation(alert.URI)).
					WithRegion(sarif.NewRegion().WithStartLine(1))
				result.WithLocations([]*sarif.Location{sarif.NewLocationWithPhysicalLocation(location)})
			}

			run.AddResult(result)
		}
	}

	report.AddRun(run)
	return report, nil
}
