package vortex

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_QueryPackage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		resp := PackageRiskReport{
			Ecosystem:        "npm",
			PackageName:      "malicious-lib",
			Version:          "1.0.0",
			ThreatLevel:      ThreatLevelCritical,
			Typosquatting:    true,
			MaliciousRelease: true,
			Advisories:       []string{"VTX-2026-0042"},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "test-key")
	if !client.IsConfigured() {
		t.Errorf("Expected client to be configured")
	}

	report, err := client.QueryPackage(context.Background(), "npm", "malicious-lib", "1.0.0")
	if err != nil {
		t.Fatalf("QueryPackage failed: %v", err)
	}

	if report.ThreatLevel != ThreatLevelCritical {
		t.Errorf("Expected Critical threat level, got %s", report.ThreatLevel)
	}
	if !report.Typosquatting {
		t.Errorf("Expected Typosquatting to be true")
	}
}

func TestClient_CheckIndicator(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ThreatIntelReport{
			Indicator:   "198.51.100.1",
			Type:        "ip",
			ThreatLevel: ThreatLevelHigh,
			Reputation:  15,
			Malicious:   true,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "")
	report, err := client.CheckIndicator(context.Background(), "ip", "198.51.100.1")
	if err != nil {
		t.Fatalf("CheckIndicator failed: %v", err)
	}

	if report.ThreatLevel != ThreatLevelHigh {
		t.Errorf("Expected High threat level, got %s", report.ThreatLevel)
	}
	if !report.Malicious {
		t.Errorf("Expected Malicious to be true")
	}
}
