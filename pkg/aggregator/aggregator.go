package aggregator

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/yehezkiel1086/AegisCI/pkg/config"
	"github.com/yehezkiel1086/AegisCI/pkg/policy"
)

// Summary contains aggregate statistics of scan findings.
type Summary struct {
	Total      int            `json:"total"`
	Critical   int            `json:"critical"`
	High       int            `json:"high"`
	Medium     int            `json:"medium"`
	Low        int            `json:"low"`
	Note       int            `json:"note"`
	Suppressed int            `json:"suppressed"`
	ByEngine   map[string]int `json:"by_engine"`
	Findings   []Finding      `json:"findings"`
}

// Finding represents a single unified finding.
type Finding struct {
	Engine   string `json:"engine"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	FilePath string `json:"file_path"`
	Line     int    `json:"line"`
}

// Aggregator merges and processes SARIF reports from multiple scanner engines.
type Aggregator struct {
	masterReport    *sarif.Report
	suppressedCount int
}

// New creates a new Aggregator initialized with an empty SARIF v2.1.0 document.
func New() (*Aggregator, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize master SARIF report: %w", err)
	}
	return &Aggregator{masterReport: report}, nil
}

// MasterReport returns the underlying unified SARIF report.
func (a *Aggregator) MasterReport() *sarif.Report {
	return a.masterReport
}

// AddReport appends runs from another SARIF report into the master report.
func (a *Aggregator) AddReport(subReport *sarif.Report) {
	if subReport == nil {
		return
	}
	for _, run := range subReport.Runs {
		if run.Results == nil {
			run.Results = make([]*sarif.Result, 0)
		}
		a.masterReport.AddRun(run)
	}
}

// MergeReportFile reads and parses a SARIF file from disk and merges it.
func (a *Aggregator) MergeReportFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read SARIF file %s: %w", filePath, err)
	}

	subReport, err := sarif.FromBytes(data)
	if err != nil {
		return fmt.Errorf("failed to parse SARIF file %s: %w", filePath, err)
	}

	a.AddReport(subReport)
	return nil
}

// Deduplicate removes duplicate findings across results within each run or across runs.
func (a *Aggregator) Deduplicate() {
	seenKeys := make(map[string]bool)

	for _, run := range a.masterReport.Runs {
		uniqueResults := make([]*sarif.Result, 0)
		for _, result := range run.Results {
			key := generateResultDeduplicationKey(result)
			if !seenKeys[key] {
				seenKeys[key] = true
				uniqueResults = append(uniqueResults, result)
			}
		}
		run.Results = uniqueResults
	}
}

// generateResultDeduplicationKey creates a unique string for a SARIF result.
func generateResultDeduplicationKey(res *sarif.Result) string {
	ruleID := ""
	if res.RuleID != nil {
		ruleID = *res.RuleID
	}

	fileURI := ""
	startLine := 0
	if len(res.Locations) > 0 && res.Locations[0].PhysicalLocation != nil {
		phys := res.Locations[0].PhysicalLocation
		if phys.ArtifactLocation != nil && phys.ArtifactLocation.URI != nil {
			fileURI = *phys.ArtifactLocation.URI
		}
		if phys.Region != nil && phys.Region.StartLine != nil {
			startLine = *phys.Region.StartLine
		}
	}

	return fmt.Sprintf("%s:%s:%d", ruleID, fileURI, startLine)
}

// ApplyPolicy filters out findings according to policy exceptions / ignore rules.
func (a *Aggregator) ApplyPolicy(p *policy.Policy) {
	if p == nil || len(p.Ignore) == 0 {
		return
	}

	now := time.Now()
	for _, run := range a.masterReport.Runs {
		filteredResults := make([]*sarif.Result, 0)
		for _, result := range run.Results {
			ruleID := ""
			if result.RuleID != nil {
				ruleID = *result.RuleID
			}

			fileURI := ""
			if len(result.Locations) > 0 && result.Locations[0].PhysicalLocation != nil {
				phys := result.Locations[0].PhysicalLocation
				if phys.ArtifactLocation != nil && phys.ArtifactLocation.URI != nil {
					fileURI = *phys.ArtifactLocation.URI
				}
			}

			if ignored, _ := p.ShouldIgnore(ruleID, fileURI, now); ignored {
				a.suppressedCount++
			} else {
				filteredResults = append(filteredResults, result)
			}
		}
		run.Results = filteredResults
	}
}

// ComputeSummary calculates statistics across all runs and findings.
func (a *Aggregator) ComputeSummary() *Summary {
	summary := &Summary{
		Suppressed: a.suppressedCount,
		ByEngine:   make(map[string]int),
		Findings:   make([]Finding, 0),
	}

	for _, run := range a.masterReport.Runs {
		engineName := "Unknown"
		if run.Tool.Driver != nil && run.Tool.Driver.Name != "" {
			engineName = run.Tool.Driver.Name
		}

		for _, res := range run.Results {
			summary.Total++
			summary.ByEngine[engineName]++

			ruleID := "unknown"
			if res.RuleID != nil {
				ruleID = *res.RuleID
			}

			message := ""
			if res.Message.Text != nil {
				message = *res.Message.Text
			}

			fileURI := "unknown"
			line := 0
			if len(res.Locations) > 0 && res.Locations[0].PhysicalLocation != nil {
				phys := res.Locations[0].PhysicalLocation
				if phys.ArtifactLocation != nil && phys.ArtifactLocation.URI != nil {
					fileURI = *phys.ArtifactLocation.URI
				}
				if phys.Region != nil && phys.Region.StartLine != nil {
					line = *phys.Region.StartLine
				}
			}

			level := "warning"
			if res.Level != nil {
				level = *res.Level
			}

			sev := config.MapSARIFLevelToSeverity(level)
			if res.Properties != nil {
				if propSev, ok := res.Properties["security-severity"].(string); ok && propSev != "" {
					sev = propSev
				}
			}

			switch strings.ToUpper(sev) {
			case config.SeverityCritical:
				summary.Critical++
			case config.SeverityHigh:
				summary.High++
			case config.SeverityMedium:
				summary.Medium++
			case config.SeverityLow:
				summary.Low++
			default:
				summary.Note++
			}

			summary.Findings = append(summary.Findings, Finding{
				Engine:   engineName,
				RuleID:   ruleID,
				Severity: sev,
				Message:  message,
				FilePath: fileURI,
				Line:     line,
			})
		}
	}

	return summary
}

// EvaluateGate determines whether the build should fail based on severity threshold and policy settings.
func (a *Aggregator) EvaluateGate(p *policy.Policy, failOnSeverity string) (bool, string) {
	thresholdRank := config.SeverityRank(failOnSeverity)
	summary := a.ComputeSummary()

	// 1. Check max tolerances from policy settings if defined
	if p != nil {
		if p.Settings.MaxCritical > 0 && summary.Critical > p.Settings.MaxCritical {
			return true, fmt.Sprintf("Critical findings (%d) exceeded policy max tolerance of %d", summary.Critical, p.Settings.MaxCritical)
		}
		if p.Settings.MaxHigh > 0 && summary.High > p.Settings.MaxHigh {
			return true, fmt.Sprintf("High findings (%d) exceeded policy max tolerance of %d", summary.High, p.Settings.MaxHigh)
		}
		if p.Settings.MaxMedium > 0 && summary.Medium > p.Settings.MaxMedium {
			return true, fmt.Sprintf("Medium findings (%d) exceeded policy max tolerance of %d", summary.Medium, p.Settings.MaxMedium)
		}
	}

	// 2. Check general fail-on-severity threshold
	if thresholdRank > 0 {
		for _, f := range summary.Findings {
			if config.SeverityRank(f.Severity) >= thresholdRank {
				return true, fmt.Sprintf("Finding '%s' (%s) meets or exceeds fail-on-severity threshold '%s'", f.RuleID, f.Severity, failOnSeverity)
			}
		}
	}

	return false, ""
}

// sanitizeRulesArray normalizes rules in a tool driver or extension object.
func sanitizeRulesArray(rules interface{}) []interface{} {
	rulesList, ok := rules.([]interface{})
	if !ok {
		return nil
	}

	sanitizedRules := make([]interface{}, 0, len(rulesList))
	for _, r := range rulesList {
		ruleMap, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		ruleID := "unknown"
		if idVal, ok := ruleMap["id"].(string); ok && idVal != "" {
			ruleID = idVal
		}

		// Ensure shortDescription is a valid object with required "text" string
		if shortDesc, exists := ruleMap["shortDescription"]; exists {
			switch sd := shortDesc.(type) {
			case string:
				ruleMap["shortDescription"] = map[string]interface{}{"text": sd}
			case map[string]interface{}:
				if textVal, hasText := sd["text"].(string); !hasText || textVal == "" {
					sd["text"] = ruleID
				}
			default:
				ruleMap["shortDescription"] = map[string]interface{}{"text": ruleID}
			}
		} else {
			ruleMap["shortDescription"] = map[string]interface{}{"text": ruleID}
		}

		// Ensure fullDescription is valid object or removed
		if fullDesc, exists := ruleMap["fullDescription"]; exists {
			switch fd := fullDesc.(type) {
			case string:
				ruleMap["fullDescription"] = map[string]interface{}{"text": fd}
			case map[string]interface{}:
				if textVal, hasText := fd["text"].(string); !hasText || textVal == "" {
					delete(ruleMap, "fullDescription")
				}
			default:
				delete(ruleMap, "fullDescription")
			}
		}

		// Ensure help is valid object or removed
		if help, exists := ruleMap["help"]; exists {
			switch h := help.(type) {
			case string:
				ruleMap["help"] = map[string]interface{}{"text": h}
			case map[string]interface{}:
				if textVal, hasText := h["text"].(string); !hasText || textVal == "" {
					delete(ruleMap, "help")
				}
			default:
				delete(ruleMap, "help")
			}
		}

		sanitizedRules = append(sanitizedRules, ruleMap)
	}

	return sanitizedRules
}

// sanitizeJSONTree walks and sanitizes raw JSON structure to guarantee 100% schema compliance with GitHub Code Scanning.
func sanitizeJSONTree(root map[string]interface{}) {
	runsVal, ok := root["runs"].([]interface{})
	if !ok {
		root["runs"] = []interface{}{}
		return
	}

	for _, r := range runsVal {
		runMap, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		// 1. results MUST be an array `[]`, NEVER null
		if resVal, exists := runMap["results"]; !exists || resVal == nil {
			runMap["results"] = []interface{}{}
		} else if resList, ok := resVal.([]interface{}); ok {
			for _, res := range resList {
				if resMap, ok := res.(map[string]interface{}); ok {
					// Clean up invalid or overflow sentinel ruleIndex values
					if ri, hasRI := resMap["ruleIndex"]; hasRI {
						if num, isNum := ri.(float64); isNum && (num >= 1000000 || num < 0) {
							delete(resMap, "ruleIndex")
						}
					}
				}
			}
		}

		// 2. tool driver validation
		if toolVal, exists := runMap["tool"].(map[string]interface{}); exists {
			if driverVal, exists := toolVal["driver"].(map[string]interface{}); exists {
				if nameVal, ok := driverVal["name"].(string); !ok || nameVal == "" {
					driverVal["name"] = "AegisCI"
				}

				if rulesVal, exists := driverVal["rules"]; exists && rulesVal != nil {
					driverVal["rules"] = sanitizeRulesArray(rulesVal)
				}
			} else {
				toolVal["driver"] = map[string]interface{}{"name": "AegisCI"}
			}

			// Extensions validation
			if extVal, exists := toolVal["extensions"].([]interface{}); exists {
				for _, ext := range extVal {
					if extMap, ok := ext.(map[string]interface{}); ok {
						if extRules, exists := extMap["rules"]; exists && extRules != nil {
							extMap["rules"] = sanitizeRulesArray(extRules)
						}
					}
				}
			}
		}
	}
}

// SaveCombined writes the sanitized merged SARIF report to the target destination.
func (a *Aggregator) SaveCombined(outputPath string) error {
	rawBytes, err := json.Marshal(a.masterReport)
	if err != nil {
		return fmt.Errorf("failed to marshal master SARIF report: %w", err)
	}

	var root map[string]interface{}
	if err := json.Unmarshal(rawBytes, &root); err != nil {
		return fmt.Errorf("failed to unmarshal SARIF for sanitization: %w", err)
	}

	sanitizeJSONTree(root)

	finalBytes, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to re-marshal sanitized SARIF: %w", err)
	}

	return os.WriteFile(outputPath, finalBytes, 0644)
}
