package aggregator

import (
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

// SanitizeReport ensures the SARIF report strictly satisfies GitHub Code Scanning's schema validator.
func (a *Aggregator) SanitizeReport() {
	if a.masterReport == nil {
		return
	}

	for _, run := range a.masterReport.Runs {
		// 1. GitHub Code Scanning requires results to be an array `[]`, NEVER null
		if run.Results == nil {
			run.Results = make([]*sarif.Result, 0)
		}

		// 2. Ensure Tool.Driver is valid
		if run.Tool.Driver == nil {
			run.Tool.Driver = sarif.NewDriver("AegisCI")
		}
		if run.Tool.Driver.Name == "" {
			run.Tool.Driver.Name = "AegisCI"
		}

		// 3. Sanitize driver rules
		if run.Tool.Driver.Rules != nil {
			for _, rule := range run.Tool.Driver.Rules {
				if rule == nil {
					continue
				}

				// Ensure ShortDescription is a valid MultiformatMessageString object
				if rule.ShortDescription != nil && (rule.ShortDescription.Text == nil || *rule.ShortDescription.Text == "") {
					rule.ShortDescription = sarif.NewMultiformatMessageString(rule.ID)
				}

				// Ensure FullDescription is valid or nil
				if rule.FullDescription != nil && (rule.FullDescription.Text == nil || *rule.FullDescription.Text == "") {
					rule.FullDescription = nil
				}

				// Ensure Help is valid or nil
				if rule.Help != nil && (rule.Help.Text == nil || *rule.Help.Text == "") {
					rule.Help = nil
				}
			}
		}

		// 4. Sanitize results
		for _, res := range run.Results {
			if res == nil {
				continue
			}

			// Ensure rule ID is present
			if res.RuleID == nil || *res.RuleID == "" {
				defaultRuleID := "security-finding"
				res.RuleID = &defaultRuleID
			}

			// Ensure message text is present
			if res.Message.Text == nil || *res.Message.Text == "" {
				defaultMsg := "Security vulnerability detected"
				res.Message.Text = &defaultMsg
			}

			// Ensure level is valid
			if res.Level == nil || *res.Level == "" {
				defaultLevel := "warning"
				res.Level = &defaultLevel
			}
		}
	}
}

// SaveCombined writes the sanitized merged SARIF report to the target destination.
func (a *Aggregator) SaveCombined(outputPath string) error {
	a.SanitizeReport()
	return a.masterReport.WriteFile(outputPath)
}
