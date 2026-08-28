package exporter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yehezkiel1086/AegisCI/pkg/aggregator"
)

func TestExporter_Export(t *testing.T) {
	receivedPayload := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-dashboard-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		receivedPayload = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	exporter := NewExporter(ts.URL, "test-dashboard-token")
	if !exporter.IsConfigured() {
		t.Errorf("Expected exporter to be configured")
	}

	summary := &aggregator.Summary{
		Total:    2,
		Critical: 1,
		High:     1,
	}

	payload := BuildPayload(summary, 500*time.Millisecond, "deep-scan", "HIGH", false, []string{"Semgrep", "Gitleaks"})
	if err := exporter.Export(context.Background(), payload); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	if !receivedPayload {
		t.Errorf("Expected dashboard server to receive payload")
	}
}
