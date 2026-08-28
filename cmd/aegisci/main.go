package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/yehezkiel1086/AegisCI/pkg/aggregator"
	"github.com/yehezkiel1086/AegisCI/pkg/config"
	"github.com/yehezkiel1086/AegisCI/pkg/detector"
	"github.com/yehezkiel1086/AegisCI/pkg/engine"
)

const version = "1.0.0"

var (
	banner = `
    _              _       ____ ___ 
   / \   ___  __ _(_)___  / ___|_ _|
  / _ \ / _ \/ _` + "`" + ` | / __|| |    | | 
 / ___ \  __/ (_| | \__ \| |___ | | 
/_/   \_\___|\__, |_|___(_)____|___|
             |___/                  
`
	cyanBold   = color.New(color.FgCyan, color.Bold)
	greenBold  = color.New(color.FgGreen, color.Bold)
	redBold    = color.New(color.FgRed, color.Bold)
	yellowBold = color.New(color.FgYellow, color.Bold)
	whiteBold  = color.New(color.FgWhite, color.Bold)
	magenta    = color.New(color.FgMagenta)
	gray       = color.New(color.FgHiBlack)
)

func main() {
	cfg := config.DefaultConfig()

	rootCmd := &cobra.Command{
		Use:   "aegisci",
		Short: "AegisCI - All-in-One DevSecOps Scanner Orchestrator",
		Long:  "AegisCI orchestrates SAST, Secret Detection, SCA, and IaC tools into a unified SARIF output for GitHub Code Scanning.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cfg)
		},
	}

	// Flags
	rootCmd.Flags().StringVarP(&cfg.TargetDir, "target", "t", cfg.TargetDir, "Target directory to scan")
	rootCmd.Flags().StringVarP(&cfg.OutputFile, "output", "o", cfg.OutputFile, "Output SARIF report destination")
	rootCmd.Flags().StringVarP(&cfg.Mode, "mode", "m", cfg.Mode, "Pipeline mode (auto, pr-check, deep-scan)")
	rootCmd.Flags().StringVarP(&cfg.FailOnSeverity, "fail-on-severity", "f", cfg.FailOnSeverity, "Fail pipeline on severity (NONE, LOW, MEDIUM, HIGH, CRITICAL)")
	rootCmd.Flags().BoolVar(&cfg.EnableSAST, "sast", cfg.EnableSAST, "Enable SAST engine (Semgrep)")
	rootCmd.Flags().BoolVar(&cfg.EnableSecrets, "secrets", cfg.EnableSecrets, "Enable Secrets engine (Gitleaks)")
	rootCmd.Flags().StringVar(&cfg.PolicyFile, "policy-file", cfg.PolicyFile, "Path to .aegisci.yml policy configuration")
	rootCmd.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", cfg.Verbose, "Enable verbose output")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(cfg *config.Config) error {
	// Print Banner
	cyanBold.Print(banner)
	whiteBold.Printf(" AegisCI Security Orchestrator v%s\n", version)
	gray.Println(" ==========================================================")
	fmt.Println()

	// Normalize and validate fail-on-severity
	normSev, err := config.NormalizeSeverity(cfg.FailOnSeverity)
	if err != nil {
		return err
	}
	cfg.FailOnSeverity = normSev

	// Handle graceful termination
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startTime := time.Now()

	// 1. Stack Detection
	whiteBold.Println("🔍 [1/4] Detecting Repository Stack...")
	stack, err := detector.Detect(cfg.TargetDir)
	if err != nil {
		gray.Printf("  Warning: could not inspect stack: %v\n", err)
	} else {
		if len(stack.Languages) > 0 {
			fmt.Printf("  • Languages:      %s\n", color.GreenString(strings.Join(stack.Languages, ", ")))
		} else {
			fmt.Printf("  • Languages:      %s\n", gray.Sprint("None detected / Generic"))
		}
		if len(stack.Infrastructure) > 0 {
			fmt.Printf("  • Infrastructure: %s\n", color.BlueString(strings.Join(stack.Infrastructure, ", ")))
		}
		if stack.HasWorkflows {
			fmt.Printf("  • CI Workflows:   %s\n", color.YellowString("GitHub Actions detected"))
		}
	}
	fmt.Println()

	// 2. Scanner Orchestration
	whiteBold.Println("⚡ [2/4] Initializing Security Engines...")
	var activeScanners []engine.Scanner

	if cfg.EnableSecrets {
		gitleaks := engine.NewGitleaksScanner()
		if gitleaks.IsAvailable() {
			greenBold.Printf("  [✓] Gitleaks (Secrets)  -> READY\n")
		} else {
			yellowBold.Printf("  [!] Gitleaks (Secrets)  -> NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, gitleaks)
	}

	if cfg.EnableSAST {
		semgrep := engine.NewSemgrepScanner()
		if semgrep.IsAvailable() {
			greenBold.Printf("  [✓] Semgrep (SAST)      -> READY\n")
		} else {
			yellowBold.Printf("  [!] Semgrep (SAST)      -> NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, semgrep)
	}

	if len(activeScanners) == 0 {
		return fmt.Errorf("no scanners enabled or available")
	}
	fmt.Println()

	// 3. Execution
	whiteBold.Printf("🚀 [3/4] Running Security Audits (Mode: %s)...\n", color.CyanString(cfg.Mode))
	orchestrator := engine.NewOrchestrator(activeScanners...)
	results := orchestrator.Run(ctx, cfg.TargetDir)

	agg, err := aggregator.New()
	if err != nil {
		return fmt.Errorf("failed to create SARIF aggregator: %w", err)
	}

	for _, res := range results {
		if res.Error != nil {
			redBold.Printf("  ✗ %s (%s): failed (%s) - %v\n", res.ScannerName, res.Category, res.Duration.Round(time.Millisecond), res.Error)
		} else {
			findingCount := 0
			if res.Report != nil {
				for _, r := range res.Report.Runs {
					findingCount += len(r.Results)
				}
				agg.AddReport(res.Report)
			}
			greenBold.Printf("  ✓ %s (%s): completed in %s (findings: %d)\n",
				res.ScannerName, res.Category, res.Duration.Round(time.Millisecond), findingCount)
		}
	}
	fmt.Println()

	// 4. Aggregation & Policy Application
	whiteBold.Println("🛡️  [4/4] Aggregating & Deduplicating SARIF Findings...")
	agg.Deduplicate()

	policy, polErr := config.LoadPolicyFile(cfg.PolicyFile)
	if polErr != nil {
		gray.Printf("  Warning: could not load policy file: %v\n", polErr)
	} else if policy != nil {
		gray.Printf("  Loaded policy from %s (%d ignore rules)\n", cfg.PolicyFile, len(policy.Ignore))
		agg.ApplyPolicy(policy)
	}

	if err := agg.SaveCombined(cfg.OutputFile); err != nil {
		return fmt.Errorf("failed to write unified SARIF file: %w", err)
	}
	greenBold.Printf("  Unified SARIF report written to: %s\n", color.WhiteString(cfg.OutputFile))
	fmt.Println()

	// Summary Table
	summary := agg.ComputeSummary()
	printSummaryTable(summary, time.Since(startTime), cfg.FailOnSeverity)

	// Evaluate Exit Code
	if agg.ShouldFail(cfg.FailOnSeverity) {
		redBold.Printf("\n❌ Build Failed: Security findings exceed fail-on-severity threshold (%s)\n", cfg.FailOnSeverity)
		os.Exit(1)
	}

	greenBold.Println("\n✅ Audit Passed: No security findings exceeded threshold.")
	return nil
}

func printSummaryTable(summary *aggregator.Summary, elapsed time.Duration, failThreshold string) {
	whiteBold.Println("====================== SCAN SUMMARY ======================")
	fmt.Printf(" Total Findings: %s\n", whiteBold.Sprintf("%d", summary.Total))
	fmt.Printf("   • CRITICAL:   %s\n", color.RedString("%d", summary.Critical))
	fmt.Printf("   • HIGH:       %s\n", color.MagentaString("%d", summary.High))
	fmt.Printf("   • MEDIUM:     %s\n", color.YellowString("%d", summary.Medium))
	fmt.Printf("   • LOW:        %s\n", color.BlueString("%d", summary.Low))
	fmt.Printf("   • NOTE:       %s\n", color.WhiteString("%d", summary.Note))
	fmt.Printf(" Fail Threshold: %s\n", color.HiYellowString(failThreshold))
	fmt.Printf(" Execution Time: %s\n", gray.Sprint(elapsed.Round(time.Millisecond)))
	whiteBold.Println("==========================================================")

	if len(summary.Findings) > 0 {
		fmt.Println()
		whiteBold.Println("Detected Vulnerabilities:")
		for i, f := range summary.Findings {
			if i >= 15 {
				gray.Printf("... and %d more findings (see %s)\n", len(summary.Findings)-15, "results.sarif")
				break
			}
			sevBadge := color.GreenString("[%s]", f.Severity)
			switch strings.ToUpper(f.Severity) {
			case config.SeverityCritical:
				sevBadge = color.RedString("[%s]", f.Severity)
			case config.SeverityHigh:
				sevBadge = color.MagentaString("[%s]", f.Severity)
			case config.SeverityMedium:
				sevBadge = color.YellowString("[%s]", f.Severity)
			case config.SeverityLow:
				sevBadge = color.BlueString("[%s]", f.Severity)
			}

			fmt.Printf("  %s %s - %s (%s:%d)\n",
				sevBadge,
				color.HiWhiteString(f.RuleID),
				f.Message,
				f.FilePath,
				f.Line,
			)
		}
	}
}
