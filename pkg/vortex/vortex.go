package vortex

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ThreatLevel defines threat risk tiers.
type ThreatLevel string

const (
	ThreatLevelNone     ThreatLevel = "NONE"
	ThreatLevelLow      ThreatLevel = "LOW"
	ThreatLevelMedium   ThreatLevel = "MEDIUM"
	ThreatLevelHigh     ThreatLevel = "HIGH"
	ThreatLevelCritical ThreatLevel = "CRITICAL"
)

// ThreatIntelReport represents threat intelligence information from the Vortex API.
type ThreatIntelReport struct {
	Indicator      string      `json:"indicator"`
	Type           string      `json:"type"` // "package", "ip", "domain", "cve"
	ThreatLevel    ThreatLevel `json:"threat_level"`
	Reputation     int         `json:"reputation_score"` // 0-100 (0 = malicious, 100 = safe)
	Malicious      bool        `json:"malicious"`
	BreachFlag     bool        `json:"breach_flag"`
	Advisories     []string    `json:"advisories"`
	KnownAttacks   []string    `json:"known_attacks"`
	LastSeenAt     string      `json:"last_seen_at"`
}

// PackageRiskReport represents supply chain threat intelligence for a software dependency.
type PackageRiskReport struct {
	Ecosystem          string      `json:"ecosystem"` // "npm", "pypi", "golang", etc.
	PackageName        string      `json:"package_name"`
	Version            string      `json:"version"`
	ThreatLevel        ThreatLevel `json:"threat_level"`
	Typosquatting      bool        `json:"is_typosquatting"`
	CompromisedAccount bool        `json:"compromised_maintainer"`
	MaliciousRelease   bool        `json:"malicious_release"`
	Advisories         []string    `json:"advisories"`
}

// Client provides an interface for interacting with the Vortex Threat Intelligence service.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NewClient creates a new Vortex threat intelligence API client.
func NewClient(baseURL, apiKey string) *Client {
	if baseURL == "" {
		baseURL = "https://api.vortex-threatintel.io/v1"
	}
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// IsConfigured returns true if the Vortex API URL and key are provided.
func (c *Client) IsConfigured() bool {
	return c.BaseURL != "" && c.APIKey != ""
}

// QueryPackage queries Vortex for supply chain security intelligence regarding a package.
func (c *Client) QueryPackage(ctx context.Context, ecosystem, name, version string) (*PackageRiskReport, error) {
	endpoint := fmt.Sprintf("%s/packages/%s/%s", c.BaseURL, url.PathEscape(ecosystem), url.PathEscape(name))
	if version != "" {
		endpoint = fmt.Sprintf("%s?version=%s", endpoint, url.QueryEscape(version))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vortex query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &PackageRiskReport{
			Ecosystem:   ecosystem,
			PackageName: name,
			Version:     version,
			ThreatLevel: ThreatLevelNone,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vortex api returned status %d", resp.StatusCode)
	}

	var report PackageRiskReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &report, nil
}

// CheckIndicator checks threat intelligence records for a general indicator (domain, IP, CVE).
func (c *Client) CheckIndicator(ctx context.Context, indicatorType, value string) (*ThreatIntelReport, error) {
	endpoint := fmt.Sprintf("%s/indicators/%s/%s", c.BaseURL, url.PathEscape(indicatorType), url.PathEscape(value))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vortex indicator query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vortex api returned status %d", resp.StatusCode)
	}

	var report ThreatIntelReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &report, nil
}
