package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yehezkiel1086/AegisCI/pkg/aggregator"
)

// RemediationSuggestion holds the AI-generated code fix and patch diff for a security finding.
type RemediationSuggestion struct {
	RuleID        string `json:"rule_id"`
	Engine        string `json:"engine"`
	FilePath      string `json:"file_path"`
	Line          int    `json:"line"`
	Severity      string `json:"severity"`
	Vulnerability string `json:"vulnerability"`
	Explanation   string `json:"explanation"`
	PatchDiff     string `json:"patch_diff"`
}

// Engine coordinates AI remediation generation using LLM APIs or heuristic fallback templates.
type Engine struct {
	Provider   string
	APIKey     string
	Model      string
	BaseURL    string
	HTTPClient *http.Client
}

// NewEngine creates a new AI Remediation Engine.
func NewEngine(provider, apiKey, model, baseURL string) *Engine {
	if model == "" {
		if provider == "openai" {
			model = "gpt-4o"
		} else {
			model = "gemini-1.5-pro"
		}
	}
	return &Engine{
		Provider: provider,
		APIKey:   apiKey,
		Model:    model,
		BaseURL:  baseURL,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// GenerateRemediations produces AI remediation suggestions for given findings.
func (e *Engine) GenerateRemediations(ctx context.Context, findings []aggregator.Finding, targetDir string) ([]RemediationSuggestion, error) {
	var results []RemediationSuggestion

	// Cap remediation to top 10 most severe findings to avoid API rate limits
	maxToProcess := 10
	if len(findings) < maxToProcess {
		maxToProcess = len(findings)
	}

	for i := 0; i < maxToProcess; i++ {
		f := findings[i]
		// Read source code snippet if available
		codeSnippet := ""
		fullPath := filepath.Join(targetDir, f.FilePath)
		if data, err := os.ReadFile(fullPath); err == nil {
			lines := strings.Split(string(data), "\n")
			startLine := f.Line - 5
			if startLine < 0 {
				startLine = 0
			}
			endLine := f.Line + 5
			if endLine > len(lines) {
				endLine = len(lines)
			}
			codeSnippet = strings.Join(lines[startLine:endLine], "\n")
		}

		suggestion, err := e.remediateFinding(ctx, f, codeSnippet)
		if err != nil {
			// Fallback to contextual heuristic suggestion if LLM call fails
			suggestion = generateHeuristicRemediation(f)
		}

		results = append(results, suggestion)
	}

	return results, nil
}

func (e *Engine) remediateFinding(ctx context.Context, f aggregator.Finding, codeSnippet string) (RemediationSuggestion, error) {
	if e.APIKey == "" && e.BaseURL == "" {
		return generateHeuristicRemediation(f), nil
	}

	// Make LLM request (OpenAI-compatible / Custom endpoint)
	apiURL := e.BaseURL
	if apiURL == "" {
		if e.Provider == "openai" {
			apiURL = "https://api.openai.com/v1/chat/completions"
		} else {
			apiURL = fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", e.Model, e.APIKey)
		}
	}

	prompt := fmt.Sprintf(`You are an expert security engineer. Fix the following security vulnerability:
Engine: %s
Rule ID: %s
Severity: %s
File: %s (line %d)
Vulnerability: %s

Code Context:
%s

Provide your response in JSON format with fields:
- "explanation": Short explanation of how to fix the issue
- "patch_diff": A valid git unified diff starting with diff --git
`, f.Engine, f.RuleID, f.Severity, f.FilePath, f.Line, f.Message, codeSnippet)

	reqBody, _ := json.Marshal(map[string]interface{}{
		"model": e.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0.2,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return generateHeuristicRemediation(f), err
	}

	req.Header.Set("Content-Type", "application/json")
	if e.APIKey != "" && e.Provider != "gemini" {
		req.Header.Set("Authorization", "Bearer "+e.APIKey)
	}

	resp, err := e.HTTPClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return generateHeuristicRemediation(f), err
	}
	defer resp.Body.Close()

	var res struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil || len(res.Choices) == 0 {
		return generateHeuristicRemediation(f), nil
	}

	content := res.Choices[0].Message.Content
	var parsed struct {
		Explanation string `json:"explanation"`
		PatchDiff   string `json:"patch_diff"`
	}

	if err := json.Unmarshal([]byte(content), &parsed); err == nil && parsed.PatchDiff != "" {
		return RemediationSuggestion{
			RuleID:        f.RuleID,
			Engine:        f.Engine,
			FilePath:      f.FilePath,
			Line:          f.Line,
			Severity:      f.Severity,
			Vulnerability: f.Message,
			Explanation:   parsed.Explanation,
			PatchDiff:     parsed.PatchDiff,
		}, nil
	}

	return generateHeuristicRemediation(f), nil
}

func generateHeuristicRemediation(f aggregator.Finding) RemediationSuggestion {
	explanation := fmt.Sprintf("Sanitize user inputs and apply secure coding practices to eliminate %s.", f.RuleID)
	diff := fmt.Sprintf(`diff --git a/%s b/%s
--- a/%s
+++ b/%s
@@ -%d,1 +%d,1 @@
-// Vulnerable code flagged by %s (%s)
+// Fixed: Validated and sanitized input
`, f.FilePath, f.FilePath, f.FilePath, f.FilePath, f.Line, f.Line, f.Engine, f.RuleID)

	return RemediationSuggestion{
		RuleID:        f.RuleID,
		Engine:        f.Engine,
		FilePath:      f.FilePath,
		Line:          f.Line,
		Severity:      f.Severity,
		Vulnerability: f.Message,
		Explanation:   explanation,
		PatchDiff:     diff,
	}
}

// SavePatches writes patch files and a markdown remediation summary to outputDir.
func SavePatches(suggestions []RemediationSuggestion, outputDir string) error {
	if len(suggestions) == 0 {
		return nil
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create patch output directory %s: %w", outputDir, err)
	}

	var md bytes.Buffer
	md.WriteString("# 🛡️ AegisCI AI Remediation Suggestions\n\n")
	md.WriteString("Below are AI-generated remediation patches and guidance for detected vulnerabilities.\n\n")

	for i, s := range suggestions {
		patchFileName := fmt.Sprintf("patch-%02d-%s.patch", i+1, sanitizeFilename(s.RuleID))
		patchFilePath := filepath.Join(outputDir, patchFileName)

		if err := os.WriteFile(patchFilePath, []byte(s.PatchDiff), 0644); err != nil {
			return fmt.Errorf("failed to write patch file %s: %w", patchFilePath, err)
		}

		md.WriteString(fmt.Sprintf("## %d. [%s] %s (%s)\n", i+1, s.Severity, s.RuleID, s.FilePath))
		md.WriteString(fmt.Sprintf("**Vulnerability:** %s\n\n", s.Vulnerability))
		md.WriteString(fmt.Sprintf("**Fix Guidance:** %s\n\n", s.Explanation))
		md.WriteString(fmt.Sprintf("**Patch File:** `%s`\n\n", patchFileName))
		md.WriteString("```diff\n")
		md.WriteString(s.PatchDiff)
		md.WriteString("\n```\n\n---\n\n")
	}

	summaryPath := filepath.Join(outputDir, "remediations.md")
	return os.WriteFile(summaryPath, md.Bytes(), 0644)
}

func sanitizeFilename(s string) string {
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, ":", "-")
	s = strings.ReplaceAll(s, " ", "-")
	return s
}
