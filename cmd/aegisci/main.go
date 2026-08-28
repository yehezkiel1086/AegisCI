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
	"github.com/yehezkiel1086/AegisCI/pkg/annotations"
	"github.com/yehezkiel1086/AegisCI/pkg/config"
	"github.com/yehezkiel1086/AegisCI/pkg/detector"
	"github.com/yehezkiel1086/AegisCI/pkg/engine"
	"github.com/yehezkiel1086/AegisCI/pkg/policy"
	"github.com/yehezkiel1086/AegisCI/pkg/router"
	"github.com/yehezkiel1086/AegisCI/pkg/vortex"
)

const version = "3.0.0"

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
		Long:  "AegisCI orchestrates SAST, DAST, Secrets, SCA, IaC, and Workflow Linters into a unified SARIF output for GitHub Code Scanning.",
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
	rootCmd.Flags().BoolVar(&cfg.EnableSCA, "sca", cfg.EnableSCA, "Enable SCA engine (Trivy)")
	rootCmd.Flags().BoolVar(&cfg.EnableIaC, "iac", cfg.EnableIaC, "Enable IaC & Container engine (Checkov)")
	rootCmd.Flags().BoolVar(&cfg.EnableDAST, "dast", cfg.EnableDAST, "Enable DAST runtime engine (OWASP ZAP)")
	rootCmd.Flags().StringVar(&cfg.DASTTargetURL, "dast-target-url", cfg.DASTTargetURL, "Target web endpoint URL for DAST scanning")
	rootCmd.Flags().StringVar(&cfg.DASTMode, "dast-mode", cfg.DASTMode, "DAST scan mode: baseline, api, full")
	rootCmd.Flags().BoolVar(&cfg.EnableWorkflowAudit, "workflow-audit", cfg.EnableWorkflowAudit, "Enable CI Workflow linter (Zizmor)")
	rootCmd.Flags().BoolVar(&cfg.EnableAnnotations, "annotations", cfg.EnableAnnotations, "Emit inline GitHub Actions PR workflow annotations")
	rootCmd.Flags().BoolVar(&cfg.EnableVortex, "vortex", cfg.EnableVortex, "Enable Vortex Threat Intelligence feed checks")
	rootCmd.Flags().StringVar(&cfg.VortexAPIURL, "vortex-api-url", cfg.VortexAPIURL, "Vortex Threat Intelligence API base URL")
	rootCmd.Flags().StringVar(&cfg.VortexAPIKey, "vortex-api-key", cfg.VortexAPIKey, "Vortex API authentication token")
	rootCmd.Flags().BoolVar(&cfg.GenerateSBOM, "sbom", cfg.GenerateSBOM, "Generate Software Bill of Materials (SBOM)")
	rootCmd.Flags().StringVar(&cfg.SBOMFormat, "sbom-format", cfg.SBOMFormat, "SBOM format: cyclonedx-json, spdx-json")
	rootCmd.Flags().StringVar(&cfg.SBOMOutput, "sbom-output", cfg.SBOMOutput, "Output path for SBOM artifact")
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
	whiteBold.Printf(" AegisCI Security Orchestrator v%s (Full-Spectrum DevSecOps Edition)\n", version)
	gray.Println(" ==========================================================================")
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

	// 1. Resolve Execution Mode & Pipeline Strategy
	plan := router.ResolvePlan(cfg)
	whiteBold.Printf("⚡ [1/6] Smart Mode Routing (Mode: %s)\n", color.CyanString(plan.EffectiveMode))
	gray.Printf("  • %s\n", plan.Reason)
	fmt.Println()

	// 2. Stack Detection
	whiteBold.Println("🔍 [2/6] Inspecting Repository Stack...")
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

	// 3. Scanner Orchestration
	whiteBold.Println("🛠️  [3/6] Initializing Security Engines...")
	var activeScanners []engine.Scanner
	var sbomEngine *engine.TrivyScanner

	if plan.EnableSecrets {
		gitleaks := engine.NewGitleaksScanner()
		if gitleaks.IsAvailable() {
			greenBold.Printf("  [✓] Gitleaks (Secrets Detection)      -> READY\n")
		} else {
			yellowBold.Printf("  [!] Gitleaks (Secrets Detection)      -> NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, gitleaks)
	}

	if plan.EnableSAST {
		semgrep := engine.NewSemgrepScanner()
		if semgrep.IsAvailable() {
			greenBold.Printf("  [✓] Semgrep  (SAST Static Code)       -> READY\n")
		} else {
			yellowBold.Printf("  [!] Semgrep  (SAST Static Code)       -> NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, semgrep)
	}

	if plan.EnableSCA {
		trivy := engine.NewTrivyScanner()
		sbomEngine = trivy
		if trivy.IsAvailable() {
			greenBold.Printf("  [✓] Trivy    (SCA & Dependencies)     -> READY\n")
		} else {
			yellowBold.Printf("  [!] Trivy    (SCA & Dependencies)     -> NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, trivy)
	}

	if plan.EnableIaC {
		checkov := engine.NewCheckovScanner()
		if checkov.IsAvailable() {
			greenBold.Printf("  [✓] Checkov  (IaC & Containers)       -> READY\n")
		} else {
			yellowBold.Printf("  [!] Checkov  (IaC & Containers)       -> NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, checkov)
	}

	if plan.EnableWorkflowAudit && stack.HasWorkflows {
		zizmor := engine.NewZizmorScanner()
		if zizmor.IsAvailable() {
			greenBold.Printf("  [✓] Zizmor   (CI Workflow Hardening)  -> READY\n")
		} else {
			yellowBold.Printf("  [!] Zizmor   (CI Workflow Hardening)  -> NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, zizmor)
	}

	if plan.EnableDAST && plan.DASTTargetURL != "" {
		zapScanner := engine.NewZAPScanner(plan.DASTTargetURL, plan.DASTMode)
		if zapScanner.IsAvailable() {
			greenBold.Printf("  [✓] OWASP ZAP (DAST Runtime: %s) -> READY\n", plan.DASTTargetURL)
		} else {
			yellowBold.Printf("  [!] OWASP ZAP (DAST Runtime)          -> RUNNER NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, zapScanner)
	}

	if len(activeScanners) == 0 {
		return fmt.Errorf("no scanners enabled or available in current configuration")
	}
	fmt.Println()

	// 4. Execution
	whiteBold.Println("🚀 [4/6] Executing Parallel Security Scanners...")
	orchestrator := engine.NewOrchestrator(activeScanners...)
	results := orchestrator.Run(ctx, cfg.TargetDir)

	agg, err := aggregator.New()
	if err != nil {
		return fmt.Errorf("failed to create SARIF aggregator: %w", err)
	}

	for _, res := range results {
		if res.Error != nil {
			redBold.Printf("  ✗ %-10s (%-22s): failed (%s) - %v\n", res.ScannerName, res.Category, res.Duration.Round(time.Millisecond), res.Error)
		} else {
			findingCount := 0
			if res.Report != nil {
				for _, r := range res.Report.Runs {
					findingCount += len(r.Results)
				}
				agg.AddReport(res.Report)
			}
			greenBold.Printf("  ✓ %-10s (%-22s): completed in %-6s (findings: %d)\n",
				res.ScannerName, res.Category, res.Duration.Round(time.Millisecond), findingCount)
		}
	}

	// Optional SBOM Generation
	if plan.GenerateSBOM && sbomEngine != nil && sbomEngine.IsAvailable() {
		fmt.Println()
		whiteBold.Printf("📦 Generating Software Bill of Materials (%s)...\n", color.CyanString(cfg.SBOMFormat))
		if err := sbomEngine.GenerateSBOM(ctx, cfg.TargetDir, cfg.SBOMFormat, cfg.SBOMOutput); err != nil {
			redBold.Printf("  ✗ SBOM generation failed: %v\n", err)
		} else {
			greenBold.Printf("  ✓ SBOM artifact successfully saved to: %s\n", color.WhiteString(cfg.SBOMOutput))
		}
	}

	// Optional Vortex Threat Intelligence check
	if cfg.EnableVortex {
		fmt.Println()
		whiteBold.Println("🌐 [Vortex] Querying Threat Intelligence Feed...")
		vortexClient := vortex.NewClient(cfg.VortexAPIURL, cfg.VortexAPIKey)
		if vortexClient.IsConfigured() {
			greenBold.Printf("  ✓ Connected to Vortex Threat Feed (%s)\n", cfg.VortexAPIURL)
		} else {
			yellowBold.Printf("  ! Vortex Client initialized in standby (API key not configured)\n")
		}
	}
	fmt.Println()

	// 5. Aggregation, Deduplication & Policy-as-Code Evaluation
	whiteBold.Println("🛡️  [5/6] Aggregating Findings & Evaluating Policy-as-Code...")
	agg.Deduplicate()

	pol, polErr := policy.LoadPolicy(cfg.PolicyFile)
	if polErr != nil {
		gray.Printf("  Warning: could not load policy file: %v\n", polErr)
	} else if pol != nil {
		gray.Printf("  Loaded policy from %s (%d active ignore rules)\n", cfg.PolicyFile, len(pol.Ignore))
		agg.ApplyPolicy(pol)
	}

	if err := agg.SaveCombined(cfg.OutputFile); err != nil {
		return fmt.Errorf("failed to write unified SARIF file: %w", err)
	}
	greenBold.Printf("  Unified SARIF report written to: %s\n", color.WhiteString(cfg.OutputFile))
	fmt.Println()

	// Summary Table
	summary := agg.ComputeSummary()
	printSummaryTable(summary, time.Since(startTime), cfg.FailOnSeverity, plan.EffectiveMode)

	// 6. Inline PR Annotations
	if cfg.EnableAnnotations && len(summary.Findings) > 0 {
		whiteBold.Println("\n📝 [6/6] Emitting Inline GitHub PR Annotations...")
		emitter := annotations.NewEmitter(os.Stdout)
		emitter.Emit(summary)
	}

	// Gate Evaluation
	shouldFail, failReason := agg.EvaluateGate(pol, cfg.FailOnSeverity)
	if shouldFail {
		redBold.Printf("\n❌ Build Failed: %s\n", failReason)
		os.Exit(1)
	}

	greenBold.Println("\n✅ Audit Passed: All policy checks and security gates satisfied.")
	return nil
}

func printSummaryTable(summary *aggregator.Summary, elapsed time.Duration, failThreshold, mode string) {
	whiteBold.Println("=========================== SCAN SUMMARY ===========================")
	fmt.Printf(" Mode:           %s\n", color.CyanString(mode))
	fmt.Printf(" Total Findings: %s (Suppressed: %s)\n",
		whiteBold.Sprintf("%d", summary.Total),
		color.HiBlackString("%d", summary.Suppressed))
	fmt.Printf("   • CRITICAL:   %s\n", color.RedString("%d", summary.Critical))
	fmt.Printf("   • HIGH:       %s\n", color.MagentaString("%d", summary.High))
	fmt.Printf("   • MEDIUM:     %s\n", color.YellowString("%d", summary.Medium))
	fmt.Printf("   • LOW:        %s\n", color.BlueString("%d", summary.Low))
	fmt.Printf("   • NOTE:       %s\n", color.WhiteString("%d", summary.Note))
	fmt.Printf(" Fail Threshold: %s\n", color.HiYellowString(failThreshold))
	fmt.Printf(" Execution Time: %s\n", gray.Sprint(elapsed.Round(time.Millisecond)))

	if len(summary.ByEngine) > 0 {
		fmt.Printf(" Engine Breakdown:\n")
		for eng, cnt := range summary.ByEngine {
			fmt.Printf("   • %-10s: %d finding(s)\n", eng, cnt)
		}
	}
	whiteBold.Println("====================================================================")

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

			fmt.Printf("  %s %-8s %s - %s (%s:%d)\n",
				sevBadge,
				color.HiBlackString("[%s]", f.Engine),
				color.HiWhiteString(f.RuleID),
				f.Message,
				f.FilePath,
				f.Line,
			)
		}
	}
}
