package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy represents the comprehensive .aegisci.yml policy-as-code configuration.
type Policy struct {
	Version       string         `yaml:"version"`
	Settings      Settings       `yaml:"settings"`
	Ignore        []RuleIgnore   `yaml:"ignore"`
	Exceptions    []RuleIgnore   `yaml:"exceptions"` // Alias for ignore
	LicensePolicy LicensePolicy  `yaml:"license_policy"`
	SCA           SCAPolicy      `yaml:"sca"`
	IaC           IaCPolicy      `yaml:"iac"`
}

// Settings defines global policy settings and tolerances.
type Settings struct {
	FailOnUnpatchedCVEs bool `yaml:"fail_on_unpatched_cves"`
	MaxCritical         int  `yaml:"max_critical"`
	MaxHigh             int  `yaml:"max_high"`
	MaxMedium           int  `yaml:"max_medium"`
}

// RuleIgnore defines a specific exception / suppression rule.
type RuleIgnore struct {
	ID      string `yaml:"id"`
	Path    string `yaml:"path"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"` // YYYY-MM-DD format
}

// LicensePolicy defines allowed and banned open-source licenses.
type LicensePolicy struct {
	Banned  []string `yaml:"banned"`
	Allowed []string `yaml:"allowed"`
}

// SCAPolicy defines specific supply-chain policy configurations.
type SCAPolicy struct {
	IgnoreDevDependencies bool     `yaml:"ignore_dev_dependencies"`
	ExcludePackages       []string `yaml:"exclude_packages"`
}

// IaCPolicy defines Infrastructure-as-Code policies.
type IaCPolicy struct {
	ExcludedFrameworks []string `yaml:"excluded_frameworks"`
}

// LoadPolicy parses a YAML policy file from the given file path.
func LoadPolicy(path string) (*Policy, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil // Policy is optional
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", path, err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse policy file %s: %w", path, err)
	}

	// Merge exceptions into Ignore for backward compatibility
	if len(p.Exceptions) > 0 {
		p.Ignore = append(p.Ignore, p.Exceptions...)
	}

	return &p, nil
}

// ShouldIgnore determines whether a finding should be suppressed based on active ignore rules.
// Returns (ignored bool, reason string).
func (p *Policy) ShouldIgnore(ruleID, filePath string, now time.Time) (bool, string) {
	if p == nil || len(p.Ignore) == 0 {
		return false, ""
	}

	for _, rule := range p.Ignore {
		// 1. Check expiration date if specified
		if rule.Expires != "" {
			expDate, err := time.Parse("2006-01-02", strings.TrimSpace(rule.Expires))
			if err == nil {
				// Expired at the end of the specified date
				expDate = expDate.Add(24 * time.Hour)
				if now.After(expDate) {
					// Rule is expired, do not suppress
					continue
				}
			}
		}

		// 2. Match Rule ID
		if rule.ID != "" && !strings.EqualFold(rule.ID, ruleID) {
			continue
		}

		// 3. Match File Path (supports exact match, substring, and glob)
		if rule.Path != "" {
			if !matchPath(rule.Path, filePath) {
				continue
			}
		}

		reason := rule.Reason
		if reason == "" {
			reason = fmt.Sprintf("Suppressed by policy rule '%s'", rule.ID)
		}
		return true, reason
	}

	return false, ""
}

// matchPath compares a policy pattern against a file path using substring or glob matching.
func matchPath(pattern, filePath string) bool {
	normPattern := filepath.ToSlash(pattern)
	normPath := filepath.ToSlash(filePath)

	// Direct match or substring match
	if normPattern == normPath || strings.Contains(normPath, normPattern) {
		return true
	}

	// Glob matching
	matched, err := filepath.Match(normPattern, normPath)
	if err == nil && matched {
		return true
	}

	// Handle recursive wildcard "**/"
	if strings.Contains(normPattern, "**/") {
		prefix := strings.Split(normPattern, "**/")[0]
		suffix := strings.Split(normPattern, "**/")[1]
		if (prefix == "" || strings.HasPrefix(normPath, prefix)) &&
			(suffix == "" || strings.HasSuffix(normPath, suffix) || matchGlobSuffix(normPath, suffix)) {
			return true
		}
	}

	return false
}

func matchGlobSuffix(path, suffix string) bool {
	matched, err := filepath.Match(suffix, filepath.Base(path))
	return err == nil && matched
}

// IsLicenseAllowed verifies whether an identified license is permissible under the license policy.
func (p *Policy) IsLicenseAllowed(license string) (bool, string) {
	if p == nil {
		return true, ""
	}

	normLic := strings.ToUpper(strings.TrimSpace(license))

	// Check banned licenses first
	for _, banned := range p.LicensePolicy.Banned {
		if strings.EqualFold(strings.TrimSpace(banned), normLic) {
			return false, fmt.Sprintf("License '%s' is explicitly banned by policy", license)
		}
	}

	// If an allowed whitelist is defined, license must be in the whitelist
	if len(p.LicensePolicy.Allowed) > 0 {
		for _, allowed := range p.LicensePolicy.Allowed {
			if strings.EqualFold(strings.TrimSpace(allowed), normLic) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("License '%s' is not in the approved licenses whitelist", license)
	}

	return true, ""
}
