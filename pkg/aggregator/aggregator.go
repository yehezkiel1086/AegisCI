package aggregator

import (
	"fmt"
	"os"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/yehezkiel1086/AegisCI/pkg/config"
)

// Summary contains aggregate statistics of scan findings.
type Summary struct {
	Total    int            `json:"total"`
	Critical int            `json:"critical"`
	High     int            `json:"high"`
	Medium   int            `json:"medium"`
	Low      int            `json:"low"`
	Note     int            `json:"note"`
	ByEngine map[string]int `json:"by_engine"`
	Findings []Finding      `json:"findings"`
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
	masterReport *sarif.Report
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
		var uniqueResults []*sarif.Result
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
func (a *Aggregator) ApplyPolicy(policy *config.PolicyConfig) {
	if policy == nil || len(policy.Ignore) == 0 {
		return
	}

	for _, run := range a.masterReport.Runs {
		var filteredResults []*sarif.Result
		for _, result := range run.Results {
			if !isIgnored(result, policy.Ignore) {
				filteredResults = append(filteredResults, result)
			}
		}
		run.Results = filteredResults
	}
}

func isIgnored(res *sarif.Result, ignores []config.PolicyIgnore) bool {
	ruleID := ""
	if res.RuleID != nil {
		ruleID = *res.RuleID
	}

	fileURI := ""
	if len(res.Locations) > 0 && res.Locations[0].PhysicalLocation != nil {
		phys := res.Locations[0].PhysicalLocation
		if phys.ArtifactLocation != nil && phys.ArtifactLocation.URI != nil {
			fileURI = *phys.ArtifactLocation.URI
		}
	}

	for _, ig := range ignores {
		if ig.ID != "" && ig.ID != ruleID {
			continue
		}
		if ig.Path != "" && !strings.Contains(fileURI, ig.Path) {
			continue
		}
		return true
	}
	return false
}

// ComputeSummary calculates statistics across all runs and findings.
func (a *Aggregator) ComputeSummary() *Summary {
	summary := &Summary{
		ByEngine: make(map[string]int),
		Findings: make([]Finding, 0),
	}

	for _, run := range a.masterReport.Runs {
		engineName := "Unknown"
		if run.Tool.Driver != nil {
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

			// Map SARIF level or properties to severity
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

// ShouldFail determines if any finding in the summary exceeds or meets the threshold.
func (a *Aggregator) ShouldFail(failOnSeverity string) bool {
	thresholdRank := config.SeverityRank(failOnSeverity)
	if thresholdRank == 0 {
		return false // NONE or OFF never fails
	}

	summary := a.ComputeSummary()
	for _, f := range summary.Findings {
		if config.SeverityRank(f.Severity) >= thresholdRank {
			return true
		}
	}
	return false
}

// SaveCombined writes the merged SARIF report to the target destination.
func (a *Aggregator) SaveCombined(outputPath string) error {
	return a.masterReport.WriteFile(outputPath)
}
