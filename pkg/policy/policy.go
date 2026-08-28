package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version       string        `yaml:"version"`
	Settings      Settings      `yaml:"settings"`
	Ignore        []RuleIgnore  `yaml:"ignore"`
	Exceptions    []RuleIgnore  `yaml:"exceptions"`
	LicensePolicy LicensePolicy `yaml:"license_policy"`
	SCA           SCAPolicy     `yaml:"sca"`
	IaC           IaCPolicy     `yaml:"iac"`
}

type Settings struct {
	FailOnUnpatchedCVEs bool `yaml:"fail_on_unpatched_cves"`
	MaxCritical         int  `yaml:"max_critical"`
	MaxHigh             int  `yaml:"max_high"`
	MaxMedium           int  `yaml:"max_medium"`
}

type RuleIgnore struct {
	ID      string `yaml:"id"`
	Path    string `yaml:"path"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"`
}

type LicensePolicy struct {
	Banned  []string `yaml:"banned"`
	Allowed []string `yaml:"allowed"`
}

type SCAPolicy struct {
	IgnoreDevDependencies bool     `yaml:"ignore_dev_dependencies"`
	ExcludePackages       []string `yaml:"exclude_packages"`
}

type IaCPolicy struct {
	ExcludedFrameworks []string `yaml:"excluded_frameworks"`
}

func LoadPolicy(path string) (*Policy, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", path, err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse policy file %s: %w", path, err)
	}

	if len(p.Exceptions) > 0 {
		p.Ignore = append(p.Ignore, p.Exceptions...)
	}

	return &p, nil
}

func (p *Policy) ShouldIgnore(ruleID, filePath string, now time.Time) (bool, string) {
	if p == nil || len(p.Ignore) == 0 {
		return false, ""
	}

	for _, rule := range p.Ignore {
		if rule.Expires != "" {
			expDate, err := time.Parse("2006-01-02", strings.TrimSpace(rule.Expires))
			if err == nil {
				expDate = expDate.Add(24 * time.Hour)
				if now.After(expDate) {
					continue
				}
			}
		}

		if rule.ID != "" && !strings.EqualFold(rule.ID, ruleID) {
			continue
		}

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

func matchPath(pattern, filePath string) bool {
	normPattern := strings.TrimPrefix(filepath.ToSlash(pattern), "./")
	normPath := strings.TrimPrefix(filepath.ToSlash(filePath), "./")

	if normPattern == normPath || normPattern == "**" || normPattern == "*" {
		return true
	}

	if !strings.Contains(normPattern, "*") && strings.Contains(normPath, normPattern) {
		return true
	}

	matched, err := filepath.Match(normPattern, normPath)
	if err == nil && matched {
		return true
	}
	matchedBase, err := filepath.Match(normPattern, filepath.Base(normPath))
	if err == nil && matchedBase {
		return true
	}

	if strings.Contains(normPattern, "**") {
		if strings.HasSuffix(normPattern, "/**") {
			prefix := strings.TrimSuffix(normPattern, "/**")
			if normPath == prefix || strings.HasPrefix(normPath, prefix+"/") || strings.Contains(normPath, prefix+"/") {
				return true
			}
		}

		if strings.HasPrefix(normPattern, "**/") {
			suffix := strings.TrimPrefix(normPattern, "**/")
			if strings.HasSuffix(normPath, suffix) || matchGlobSuffix(normPath, suffix) {
				return true
			}
		}

		parts := strings.Split(normPattern, "**")
		if len(parts) == 2 {
			prefix := strings.TrimSuffix(parts[0], "/")
			suffix := strings.TrimPrefix(parts[1], "/")
			prefixMatches := prefix == "" || normPath == prefix || strings.HasPrefix(normPath, prefix+"/") || strings.Contains(normPath, prefix+"/")
			suffixMatches := suffix == "" || strings.HasSuffix(normPath, suffix) || matchGlobSuffix(normPath, suffix)
			if prefixMatches && suffixMatches {
				return true
			}
		}
	}

	return false
}

func matchGlobSuffix(path, suffix string) bool {
	matched, err := filepath.Match(suffix, filepath.Base(path))
	return err == nil && matched
}

func (p *Policy) IsLicenseAllowed(license string) (bool, string) {
	if p == nil {
		return true, ""
	}

	normLic := strings.ToUpper(strings.TrimSpace(license))

	for _, banned := range p.LicensePolicy.Banned {
		if strings.EqualFold(strings.TrimSpace(banned), normLic) {
			return false, fmt.Sprintf("License '%s' is explicitly banned by policy", license)
		}
	}

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
