package cli

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
	"github.com/yehezkiel1086/AegisCI/pkg/exporter"
	"github.com/yehezkiel1086/AegisCI/pkg/plugin"
	"github.com/yehezkiel1086/AegisCI/pkg/policy"
	"github.com/yehezkiel1086/AegisCI/pkg/remediation"
	"github.com/yehezkiel1086/AegisCI/pkg/router"
	"github.com/yehezkiel1086/AegisCI/pkg/vortex"
)

var (
	greenBold  = color.New(color.FgGreen, color.Bold)
	redBold    = color.New(color.FgRed, color.Bold)
	yellowBold = color.New(color.FgYellow, color.Bold)
)

var scanCfg = config.DefaultConfig()

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Execute full-spectrum security audit across code, dependencies, IaC, and runtime",
	Long: `Execute parallel security scans across all configured engines (SAST, Secrets, SCA, IaC, DAST, CI Workflows, Custom Plugins).
Outputs a unified SARIF v2.1.0 report, emits PR annotations, and evaluates Policy-as-Code quality gates.`,
	Example: `  # basic scan on current directory
  aegisci scan --target .

  # fast PR check mode
  aegisci scan --target . --mode pr-check

  # deep scan with SBOM and AI Remediation
  aegisci scan --target . --mode deep-scan --sbom --ai-remediation --ai-api-key $GEMINI_API_KEY

  # DAST scan targeting staging endpoint
  aegisci scan --dast --dast-target-url https://staging.example.com --fail-on CRITICAL`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(scanCfg)
	},
}

func init() {
	flags := scanCmd.Flags()

	flags.StringVarP(&scanCfg.TargetDir, "target", "t", scanCfg.TargetDir, "Target directory or repository root to scan")
	flags.StringVarP(&scanCfg.OutputFile, "output", "o", scanCfg.OutputFile, "Output SARIF report destination")
	flags.StringVarP(&scanCfg.Mode, "mode", "m", scanCfg.Mode, "Pipeline mode: auto, pr-check, deep-scan")
	flags.StringVarP(&scanCfg.FailOnSeverity, "fail-on", "f", scanCfg.FailOnSeverity, "Severity threshold to fail the build (NONE, LOW, MEDIUM, HIGH, CRITICAL)")
	flags.StringVar(&scanCfg.FailOnSeverity, "fail-on-severity", scanCfg.FailOnSeverity, "Alias for --fail-on")
	flags.StringVarP(&scanCfg.PolicyFile, "config", "c", scanCfg.PolicyFile, "Path to .aegisci.yml policy configuration file")
	flags.StringVar(&scanCfg.PolicyFile, "policy-file", scanCfg.PolicyFile, "Alias for --config")

	flags.BoolVar(&scanCfg.EnableSAST, "sast", scanCfg.EnableSAST, "Enable Static Application Security Testing (Semgrep)")
	flags.BoolVar(&scanCfg.EnableSecrets, "secrets", scanCfg.EnableSecrets, "Enable Secret Detection (Gitleaks)")
	flags.BoolVar(&scanCfg.EnableSCA, "sca", scanCfg.EnableSCA, "Enable Software Composition Analysis (Trivy)")
	flags.BoolVar(&scanCfg.EnableIaC, "iac", scanCfg.EnableIaC, "Enable Infrastructure-as-Code Auditing (Checkov)")
	flags.BoolVar(&scanCfg.EnableWorkflowAudit, "workflow-audit", scanCfg.EnableWorkflowAudit, "Enable CI Workflow Security Linter (Zizmor)")
	flags.BoolVar(&scanCfg.EnableDAST, "dast", scanCfg.EnableDAST, "Enable Dynamic Application Security Testing (OWASP ZAP)")
	flags.StringVar(&scanCfg.DASTTargetURL, "dast-target-url", scanCfg.DASTTargetURL, "Target web endpoint URL for DAST scanning")
	flags.StringVar(&scanCfg.DASTMode, "dast-mode", scanCfg.DASTMode, "DAST scan mode: baseline, api, full")

	flags.BoolVar(&scanCfg.EnableAnnotations, "annotations", scanCfg.EnableAnnotations, "Emit inline GitHub Actions PR annotations (::error/::warning)")
	flags.BoolVar(&scanCfg.GenerateSBOM, "sbom", scanCfg.GenerateSBOM, "Generate Software Bill of Materials (SBOM)")
	flags.StringVar(&scanCfg.SBOMFormat, "sbom-format", scanCfg.SBOMFormat, "SBOM format: cyclonedx-json, spdx-json")
	flags.StringVar(&scanCfg.SBOMOutput, "sbom-output", scanCfg.SBOMOutput, "Output path for SBOM artifact")

	flags.BoolVar(&scanCfg.EnableAIRemediation, "ai-remediation", scanCfg.EnableAIRemediation, "Generate AI-powered code fix patches (.patch)")
	flags.StringVar(&scanCfg.AIProvider, "ai-provider", scanCfg.AIProvider, "AI Provider for remediation: gemini, openai, custom")
	flags.StringVar(&scanCfg.AIAPIKey, "ai-api-key", scanCfg.AIAPIKey, "API key for AI Remediation provider")
	flags.StringVar(&scanCfg.AIModel, "ai-model", scanCfg.AIModel, "LLM model name for AI remediation")
	flags.StringVar(&scanCfg.AIBaseURL, "ai-base-url", scanCfg.AIBaseURL, "Custom LLM API base URL endpoint")
	flags.StringVar(&scanCfg.PatchesDir, "patches-dir", scanCfg.PatchesDir, "Directory to output AI patch files (.patch)")
	flags.StringVar(&scanCfg.PluginsDir, "plugins-dir", scanCfg.PluginsDir, "Directory containing custom WASM/binary plugins")
	flags.StringVar(&scanCfg.DashboardURL, "dashboard-url", scanCfg.DashboardURL, "Centralized Enterprise Dashboard webhook URL")
	flags.StringVar(&scanCfg.DashboardToken, "dashboard-token", scanCfg.DashboardToken, "Authentication token for Dashboard webhook")

	flags.BoolVar(&scanCfg.EnableVortex, "vortex", scanCfg.EnableVortex, "Enable Vortex Threat Intelligence feed checks")
	flags.StringVar(&scanCfg.VortexAPIURL, "vortex-api-url", scanCfg.VortexAPIURL, "Vortex Threat Intelligence API base URL")
	flags.StringVar(&scanCfg.VortexAPIKey, "vortex-api-key", scanCfg.VortexAPIKey, "Vortex API authentication token")

	flags.BoolVarP(&scanCfg.Verbose, "verbose", "v", scanCfg.Verbose, "Enable verbose output")
}

func runScan(cfg *config.Config) error {
	printBanner()

	// normalize severity input
	normSev, err := config.NormalizeSeverity(cfg.FailOnSeverity)
	if err != nil {
		return err
	}
	cfg.FailOnSeverity = normSev

	// graceful interrupt handling
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startTime := time.Now()

	// resolve mode and scanner routing
	plan := router.ResolvePlan(cfg)
	whiteBold.Printf("[1/7] Mode Routing (mode: %s)\n", color.CyanString(plan.EffectiveMode))
	gray.Printf("  • %s\n", plan.Reason)
	fmt.Println()

	// detect repository technology stack
	whiteBold.Println("[2/7] Inspecting Repository Stack...")
	stack, err := detector.Detect(cfg.TargetDir)
	if err != nil {
		gray.Printf("  warning: could not inspect stack: %v\n", err)
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

	// initialize configured scanner engines
	whiteBold.Println("[3/7] Initializing Security Engines...")
	var activeScanners []engine.Scanner
	var engineNames []string
	var sbomEngine *engine.TrivyScanner

	if plan.EnableSecrets {
		gitleaks := engine.NewGitleaksScanner()
		if gitleaks.IsAvailable() {
			greenBold.Printf("  [READY] Gitleaks (Secrets Detection)\n")
		} else {
			yellowBold.Printf("  [MISSING] Gitleaks (Secrets Detection)\n")
		}
		activeScanners = append(activeScanners, gitleaks)
		engineNames = append(engineNames, gitleaks.Name())
	}

	if plan.EnableSAST {
		semgrep := engine.NewSemgrepScanner()
		if semgrep.IsAvailable() {
			greenBold.Printf("  [READY] Semgrep  (SAST Static Code)\n")
		} else {
			yellowBold.Printf("  [MISSING] Semgrep  (SAST Static Code)\n")
		}
		activeScanners = append(activeScanners, semgrep)
		engineNames = append(engineNames, semgrep.Name())
	}

	if plan.EnableSCA {
		trivy := engine.NewTrivyScanner()
		sbomEngine = trivy
		if trivy.IsAvailable() {
			greenBold.Printf("  [READY] Trivy    (SCA & Dependencies)\n")
		} else {
			yellowBold.Printf("  [MISSING] Trivy    (SCA & Dependencies)\n")
		}
		activeScanners = append(activeScanners, trivy)
		engineNames = append(engineNames, trivy.Name())
	}

	if plan.EnableIaC {
		checkov := engine.NewCheckovScanner()
		if checkov.IsAvailable() {
			greenBold.Printf("  [READY] Checkov  (IaC & Containers)\n")
		} else {
			yellowBold.Printf("  [MISSING] Checkov  (IaC & Containers)\n")
		}
		activeScanners = append(activeScanners, checkov)
		engineNames = append(engineNames, checkov.Name())
	}

	if plan.EnableWorkflowAudit && stack.HasWorkflows {
		zizmor := engine.NewZizmorScanner()
		if zizmor.IsAvailable() {
			greenBold.Printf("  [READY] Zizmor   (CI Workflow Hardening)\n")
		} else {
			yellowBold.Printf("  [MISSING] Zizmor   (CI Workflow Hardening)\n")
		}
		activeScanners = append(activeScanners, zizmor)
		engineNames = append(engineNames, zizmor.Name())
	}

	if plan.EnableDAST && plan.DASTTargetURL != "" {
		zapScanner := engine.NewZAPScanner(plan.DASTTargetURL, plan.DASTMode)
		if zapScanner.IsAvailable() {
			greenBold.Printf("  [READY] OWASP ZAP (DAST Runtime: %s)\n", plan.DASTTargetURL)
		} else {
			yellowBold.Printf("  [MISSING] OWASP ZAP (DAST Runtime)\n")
		}
		activeScanners = append(activeScanners, zapScanner)
		engineNames = append(engineNames, zapScanner.Name())
	}

	// discover plugins from plugins directory
	discoveredPlugins, err := plugin.DiscoverPlugins(cfg.PluginsDir)
	if err == nil && len(discoveredPlugins) > 0 {
		for _, p := range discoveredPlugins {
			greenBold.Printf("  [READY] Plugin: %-25s (v%s)\n", p.Name(), p.Version())
			activeScanners = append(activeScanners, plugin.AsScanner(p))
			engineNames = append(engineNames, p.Name())
		}
	}

	if len(activeScanners) == 0 {
		return fmt.Errorf("no scanners enabled or available in current configuration")
	}
	fmt.Println()

	// execute scanners concurrently
	whiteBold.Println("[4/7] Executing Parallel Security Engines...")
	orchestrator := engine.NewOrchestrator(activeScanners...)
	results := orchestrator.Run(ctx, cfg.TargetDir)

	agg, err := aggregator.New()
	if err != nil {
		return fmt.Errorf("failed to create SARIF aggregator: %w", err)
	}

	for _, res := range results {
		if res.Error != nil {
			redBold.Printf("  [FAIL] %-10s (%-22s): failed (%s) - %v\n", res.ScannerName, res.Category, res.Duration.Round(time.Millisecond), res.Error)
		} else {
			findingCount := 0
			if res.Report != nil {
				for _, r := range res.Report.Runs {
					findingCount += len(r.Results)
				}
				agg.AddReport(res.Report)
			}
			greenBold.Printf("  [PASS] %-10s (%-22s): completed in %-6s (findings: %d)\n",
				res.ScannerName, res.Category, res.Duration.Round(time.Millisecond), findingCount)
		}
	}

	// generate optional SBOM
	if plan.GenerateSBOM && sbomEngine != nil && sbomEngine.IsAvailable() {
		fmt.Println()
		whiteBold.Printf("Generating Software Bill of Materials (%s)...\n", color.CyanString(cfg.SBOMFormat))
		if err := sbomEngine.GenerateSBOM(ctx, cfg.TargetDir, cfg.SBOMFormat, cfg.SBOMOutput); err != nil {
			redBold.Printf("  [FAIL] SBOM generation failed: %v\n", err)
		} else {
			greenBold.Printf("  [PASS] SBOM artifact saved to: %s\n", color.WhiteString(cfg.SBOMOutput))
		}
	}

	// optional threat feed query
	if cfg.EnableVortex {
		fmt.Println()
		whiteBold.Println("Querying Vortex Threat Feed...")
		vortexClient := vortex.NewClient(cfg.VortexAPIURL, cfg.VortexAPIKey)
		if vortexClient.IsConfigured() {
			greenBold.Printf("  [OK] Connected to Vortex Threat Feed (%s)\n", cfg.VortexAPIURL)
		} else {
			yellowBold.Printf("  [INFO] Vortex Client in standby (API key not configured)\n")
		}
	}
	fmt.Println()

	// aggregate, deduplicate, and apply policy exceptions
	whiteBold.Println("[5/7] Aggregating Findings & Evaluating Policy...")
	agg.Deduplicate()

	pol, polErr := policy.LoadPolicy(cfg.PolicyFile)
	if polErr != nil {
		gray.Printf("  warning: could not load policy file: %v\n", polErr)
	} else if pol != nil {
		gray.Printf("  loaded policy from %s (%d active ignore rules)\n", cfg.PolicyFile, len(pol.Ignore))
		agg.ApplyPolicy(pol)
	}

	if err := agg.SaveCombined(cfg.OutputFile); err != nil {
		return fmt.Errorf("failed to write unified SARIF file: %w", err)
	}
	greenBold.Printf("  Unified SARIF report written to: %s\n", color.WhiteString(cfg.OutputFile))
	fmt.Println()

	summary := agg.ComputeSummary()
	elapsed := time.Since(startTime)
	printSummaryTable(summary, elapsed, cfg.FailOnSeverity, plan.EffectiveMode)

	// generate AI remediation suggestions if enabled
	if cfg.EnableAIRemediation && len(summary.Findings) > 0 {
		fmt.Println()
		whiteBold.Printf("[6/7] Generating AI Remediation Fixes (%s)...\n", color.CyanString(cfg.AIProvider))
		aiEngine := remediation.NewEngine(cfg.AIProvider, cfg.AIAPIKey, cfg.AIModel, cfg.AIBaseURL)
		suggestions, err := aiEngine.GenerateRemediations(ctx, summary.Findings, cfg.TargetDir)
		if err != nil {
			gray.Printf("  warning: AI remediation encountered an issue: %v\n", err)
		} else if len(suggestions) > 0 {
			if err := remediation.SavePatches(suggestions, cfg.PatchesDir); err != nil {
				redBold.Printf("  [FAIL] Failed to write patch files: %v\n", err)
			} else {
				greenBold.Printf("  [PASS] Generated %d code fix patch(es) in %s/\n", len(suggestions), color.WhiteString(cfg.PatchesDir))
			}
		}
	}

	// emit workflow annotations on PRs
	if cfg.EnableAnnotations && len(summary.Findings) > 0 {
		whiteBold.Println("\n[7/7] Emitting PR Annotations...")
		emitter := annotations.NewEmitter(os.Stdout)
		emitter.Emit(summary)
	}

	// evaluate pipeline gate threshold
	shouldFail, failReason := agg.EvaluateGate(pol, cfg.FailOnSeverity)

	// dispatch metrics to telemetry endpoint if configured
	if cfg.DashboardURL != "" {
		exporterClient := exporter.NewExporter(cfg.DashboardURL, cfg.DashboardToken)
		payload := exporter.BuildPayload(summary, elapsed, plan.EffectiveMode, cfg.FailOnSeverity, !shouldFail, engineNames)
		if err := exporterClient.Export(ctx, payload); err != nil {
			gray.Printf("\n  warning: could not dispatch telemetry: %v\n", err)
		} else {
			greenBold.Printf("\n  [PASS] Scan telemetry streamed to dashboard (%s)\n", cfg.DashboardURL)
		}
	}

	if shouldFail {
		redBold.Printf("\n[FAIL] Quality Gate Failed: %s\n", failReason)
		os.Exit(1)
	}

	greenBold.Println("\n[PASS] Quality Gate Passed: All policy checks satisfied.")
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
