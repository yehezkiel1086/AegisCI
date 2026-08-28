package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/yehezkiel1086/AegisCI/pkg/aggregator"
)

// Payload represents the structured telemetry metrics sent to the enterprise dashboard.
type Payload struct {
	Repository    string              `json:"repository"`
	CommitSHA     string              `json:"commit_sha"`
	Branch        string              `json:"branch"`
	PRNumber      string              `json:"pr_number,omitempty"`
	TriggerEvent  string              `json:"trigger_event"`
	Timestamp     time.Time           `json:"timestamp"`
	DurationMs    int64               `json:"duration_ms"`
	Mode          string              `json:"mode"`
	GatePassed    bool                `json:"gate_passed"`
	FailThreshold string              `json:"fail_threshold"`
	Summary       *aggregator.Summary `json:"summary"`
	Engines       []string            `json:"active_engines"`
}

// Exporter manages dispatching scan telemetry and metrics to enterprise endpoints.
type Exporter struct {
	EndpointURL string
	AuthToken   string
	HTTPClient  *http.Client
}

// NewExporter creates a new enterprise dashboard telemetry exporter.
func NewExporter(endpointURL, authToken string) *Exporter {
	return &Exporter{
		EndpointURL: endpointURL,
		AuthToken:   authToken,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IsConfigured checks if an enterprise dashboard endpoint is set.
func (e *Exporter) IsConfigured() bool {
	return e.EndpointURL != ""
}

// BuildPayload constructs the telemetry payload from environment variables and scan statistics.
func BuildPayload(summary *aggregator.Summary, duration time.Duration, mode, failThreshold string, gatePassed bool, engines []string) *Payload {
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		repo = "local/repository"
	}

	commit := os.Getenv("GITHUB_SHA")
	if commit == "" {
		commit = "head"
	}

	branch := os.Getenv("GITHUB_REF_NAME")
	if branch == "" {
		branch = "main"
	}

	prNum := os.Getenv("GITHUB_PR_NUMBER")
	event := os.Getenv("GITHUB_EVENT_NAME")
	if event == "" {
		event = "cli-invocation"
	}

	return &Payload{
		Repository:    repo,
		CommitSHA:     commit,
		Branch:        branch,
		PRNumber:      prNum,
		TriggerEvent:  event,
		Timestamp:     time.Now().UTC(),
		DurationMs:    duration.Milliseconds(),
		Mode:          mode,
		GatePassed:    gatePassed,
		FailThreshold: failThreshold,
		Summary:       summary,
		Engines:       engines,
	}
}

// Export sends the telemetry metrics payload to the enterprise dashboard webhook.
func (e *Exporter) Export(ctx context.Context, payload *Payload) error {
	if !e.IsConfigured() {
		return nil
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal telemetry payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.EndpointURL, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create telemetry request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AegisCI-Exporter/4.0")
	if e.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+e.AuthToken)
	}

	resp, err := e.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to dispatch telemetry to dashboard: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("dashboard webhook returned error status %d", resp.StatusCode)
	}

	return nil
}
