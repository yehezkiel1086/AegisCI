package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestZAPScanner_ProbeTarget(t *testing.T) {
	// Create mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	scanner := NewZAPScanner(ts.URL, "baseline")

	// Test reachable URL
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := scanner.ProbeTarget(ctx, ts.URL); err != nil {
		t.Fatalf("ProbeTarget failed on valid server: %v", err)
	}

	// Test invalid URL scheme
	if err := scanner.ProbeTarget(ctx, "ftp://invalid-scheme"); err == nil {
		t.Errorf("Expected error on invalid scheme")
	}

	// Test unreachable URL
	if err := scanner.ProbeTarget(ctx, "http://127.0.0.1:59999"); err == nil {
		t.Errorf("Expected error on unreachable URL")
	}
}

func TestConvertZAPJSONToSARIF(t *testing.T) {
	zapJSON := `{
		"site": [
			{
				"@name": "http://localhost:8080",
				"alerts": [
					{
						"pluginId": "10021",
						"alert": "X-Content-Type-Options Header Missing",
						"riskdesc": "Low (Medium)",
						"riskcode": "1",
						"desc": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'.",
						"uri": "http://localhost:8080/index.html"
					},
					{
						"pluginId": "40018",
						"alert": "SQL Injection",
						"riskdesc": "High (High)",
						"riskcode": "3",
						"desc": "SQL injection vulnerability detected in parameter 'id'.",
						"uri": "http://localhost:8080/api/users"
					}
				]
			}
		]
	}`

	report, err := ConvertZAPJSONToSARIF([]byte(zapJSON))
	if err != nil {
		t.Fatalf("ConvertZAPJSONToSARIF failed: %v", err)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(report.Runs))
	}

	results := report.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	// Check SQL injection is mapped to error (High risk)
	if *results[1].RuleID != "40018" || *results[1].Level != "error" {
		t.Errorf("Expected SQL Injection with error level, got ruleID: %s, level: %s", *results[1].RuleID, *results[1].Level)
	}

	// Check header missing is mapped to note (Low risk)
	if *results[0].RuleID != "10021" || *results[0].Level != "note" {
		t.Errorf("Expected Header Missing with note level, got ruleID: %s, level: %s", *results[0].RuleID, *results[0].Level)
	}
}
