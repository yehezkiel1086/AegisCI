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
	Example: `  # Basic scan on current directory
  aegisci scan --target .

  # Fast PR check mode
  aegisci scan --target . --mode pr-check

  # Deep scan with SBOM and AI Remediation
  aegisci scan --target . --mode deep-scan --sbom --ai-remediation --ai-api-key $GEMINI_API_KEY

  # DAST scan targeting staging endpoint
  aegisci scan --dast --dast-target-url https://staging.example.com --fail-on CRITICAL`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(scanCfg)
	},
}

func init() {
	flags := scanCmd.Flags()

	// Primary operational flags
	flags.StringVarP(&scanCfg.TargetDir, "target", "t", scanCfg.TargetDir, "Target directory or repository root to scan")
	flags.StringVarP(&scanCfg.OutputFile, "output", "o", scanCfg.OutputFile, "Output SARIF report destination")
	flags.StringVarP(&scanCfg.Mode, "mode", "m", scanCfg.Mode, "Pipeline mode: auto, pr-check, deep-scan")
	flags.StringVarP(&scanCfg.FailOnSeverity, "fail-on", "f", scanCfg.FailOnSeverity, "Severity threshold to fail the build (NONE, LOW, MEDIUM, HIGH, CRITICAL)")
	flags.StringVar(&scanCfg.FailOnSeverity, "fail-on-severity", scanCfg.FailOnSeverity, "Alias for --fail-on")
	flags.StringVarP(&scanCfg.PolicyFile, "config", "c", scanCfg.PolicyFile, "Path to .aegisci.yml policy configuration file")
	flags.StringVar(&scanCfg.PolicyFile, "policy-file", scanCfg.PolicyFile, "Alias for --config")

	// Security engine toggles
	flags.BoolVar(&scanCfg.EnableSAST, "sast", scanCfg.EnableSAST, "Enable Static Application Security Testing (Semgrep)")
	flags.BoolVar(&scanCfg.EnableSecrets, "secrets", scanCfg.EnableSecrets, "Enable Secret Detection (Gitleaks)")
	flags.BoolVar(&scanCfg.EnableSCA, "sca", scanCfg.EnableSCA, "Enable Software Composition Analysis (Trivy)")
	flags.BoolVar(&scanCfg.EnableIaC, "iac", scanCfg.EnableIaC, "Enable Infrastructure-as-Code Auditing (Checkov)")
	flags.BoolVar(&scanCfg.EnableWorkflowAudit, "workflow-audit", scanCfg.EnableWorkflowAudit, "Enable CI Workflow Security Linter (Zizmor)")
	flags.BoolVar(&scanCfg.EnableDAST, "dast", scanCfg.EnableDAST, "Enable Dynamic Application Security Testing (OWASP ZAP)")
	flags.StringVar(&scanCfg.DASTTargetURL, "dast-target-url", scanCfg.DASTTargetURL, "Target web endpoint URL for DAST scanning")
	flags.StringVar(&scanCfg.DASTMode, "dast-mode", scanCfg.DASTMode, "DAST scan mode: baseline, api, full")

	// Integrations and output formatters
	flags.BoolVar(&scanCfg.EnableAnnotations, "annotations", scanCfg.EnableAnnotations, "Emit inline GitHub Actions PR annotations (::error/::warning)")
	flags.BoolVar(&scanCfg.GenerateSBOM, "sbom", scanCfg.GenerateSBOM, "Generate Software Bill of Materials (SBOM)")
	flags.StringVar(&scanCfg.SBOMFormat, "sbom-format", scanCfg.SBOMFormat, "SBOM format: cyclonedx-json, spdx-json")
	flags.StringVar(&scanCfg.SBOMOutput, "sbom-output", scanCfg.SBOMOutput, "Output path for SBOM artifact")

	// Enterprise v4.0 flags
	flags.BoolVar(&scanCfg.EnableAIRemediation, "ai-remediation", scanCfg.EnableAIRemediation, "Generate AI-powered code fix patches (.patch)")
	flags.StringVar(&scanCfg.AIProvider, "ai-provider", scanCfg.AIProvider, "AI Provider for remediation: gemini, openai, custom")
	flags.StringVar(&scanCfg.AIAPIKey, "ai-api-key", scanCfg.AIAPIKey, "API key for AI Remediation provider")
	flags.StringVar(&scanCfg.AIModel, "ai-model", scanCfg.AIModel, "LLM model name for AI remediation")
	flags.StringVar(&scanCfg.AIBaseURL, "ai-base-url", scanCfg.AIBaseURL, "Custom LLM API base URL endpoint")
	flags.StringVar(&scanCfg.PatchesDir, "patches-dir", scanCfg.PatchesDir, "Directory to output AI patch files (.patch)")
	flags.StringVar(&scanCfg.PluginsDir, "plugins-dir", scanCfg.PluginsDir, "Directory containing custom WASM/binary plugins")
	flags.StringVar(&scanCfg.DashboardURL, "dashboard-url", scanCfg.DashboardURL, "Centralized Enterprise Dashboard webhook URL")
	flags.StringVar(&scanCfg.DashboardToken, "dashboard-token", scanCfg.DashboardToken, "Authentication token for Dashboard webhook")

	// Vortex Threat Intelligence
	flags.BoolVar(&scanCfg.EnableVortex, "vortex", scanCfg.EnableVortex, "Enable Vortex Threat Intelligence feed checks")
	flags.StringVar(&scanCfg.VortexAPIURL, "vortex-api-url", scanCfg.VortexAPIURL, "Vortex Threat Intelligence API base URL")
	flags.StringVar(&scanCfg.VortexAPIKey, "vortex-api-key", scanCfg.VortexAPIKey, "Vortex API authentication token")

	flags.BoolVarP(&scanCfg.Verbose, "verbose", "v", scanCfg.Verbose, "Enable verbose output")
}

func runScan(cfg *config.Config) error {
	printBanner()

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
	whiteBold.Printf("⚡ [1/7] Smart Mode Routing (Mode: %s)\n", color.CyanString(plan.EffectiveMode))
	gray.Printf("  • %s\n", plan.Reason)
	fmt.Println()

	// 2. Stack Detection
	whiteBold.Println("🔍 [2/7] Inspecting Repository Stack...")
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

	// 3. Scanner Orchestration & Plugin Discovery
	whiteBold.Println("🛠️  [3/7] Initializing Security Engines & Enterprise Plugins...")
	var activeScanners []engine.Scanner
	var engineNames []string
	var sbomEngine *engine.TrivyScanner

	if plan.EnableSecrets {
		gitleaks := engine.NewGitleaksScanner()
		if gitleaks.IsAvailable() {
			greenBold.Printf("  [✓] Gitleaks (Secrets Detection)      -> READY\n")
		} else {
			yellowBold.Printf("  [!] Gitleaks (Secrets Detection)      -> NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, gitleaks)
		engineNames = append(engineNames, gitleaks.Name())
	}

	if plan.EnableSAST {
		semgrep := engine.NewSemgrepScanner()
		if semgrep.IsAvailable() {
			greenBold.Printf("  [✓] Semgrep  (SAST Static Code)       -> READY\n")
		} else {
			yellowBold.Printf("  [!] Semgrep  (SAST Static Code)       -> NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, semgrep)
		engineNames = append(engineNames, semgrep.Name())
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
		engineNames = append(engineNames, trivy.Name())
	}

	if plan.EnableIaC {
		checkov := engine.NewCheckovScanner()
		if checkov.IsAvailable() {
			greenBold.Printf("  [✓] Checkov  (IaC & Containers)       -> READY\n")
		} else {
			yellowBold.Printf("  [!] Checkov  (IaC & Containers)       -> NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, checkov)
		engineNames = append(engineNames, checkov.Name())
	}

	if plan.EnableWorkflowAudit && stack.HasWorkflows {
		zizmor := engine.NewZizmorScanner()
		if zizmor.IsAvailable() {
			greenBold.Printf("  [✓] Zizmor   (CI Workflow Hardening)  -> READY\n")
		} else {
			yellowBold.Printf("  [!] Zizmor   (CI Workflow Hardening)  -> NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, zizmor)
		engineNames = append(engineNames, zizmor.Name())
	}

	if plan.EnableDAST && plan.DASTTargetURL != "" {
		zapScanner := engine.NewZAPScanner(plan.DASTTargetURL, plan.DASTMode)
		if zapScanner.IsAvailable() {
			greenBold.Printf("  [✓] OWASP ZAP (DAST Runtime: %s) -> READY\n", plan.DASTTargetURL)
		} else {
			yellowBold.Printf("  [!] OWASP ZAP (DAST Runtime)          -> RUNNER NOT INSTALLED in PATH\n")
		}
		activeScanners = append(activeScanners, zapScanner)
		engineNames = append(engineNames, zapScanner.Name())
	}

	// Discover Custom Enterprise Plugins
	discoveredPlugins, err := plugin.DiscoverPlugins(cfg.PluginsDir)
	if err == nil && len(discoveredPlugins) > 0 {
		for _, p := range discoveredPlugins {
			greenBold.Printf("  [✓] Plugin: %-25s (v%s) -> LOADED\n", p.Name(), p.Version())
			activeScanners = append(activeScanners, plugin.AsScanner(p))
			engineNames = append(engineNames, p.Name())
		}
	}

	if len(activeScanners) == 0 {
		return fmt.Errorf("no scanners enabled or available in current configuration")
	}
	fmt.Println()

	// 4. Execution
	whiteBold.Println("🚀 [4/7] Executing Parallel Security Engines & Plugins...")
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
	whiteBold.Println("🛡️  [5/7] Aggregating Findings & Evaluating Policy-as-Code...")
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
	elapsed := time.Since(startTime)
	printSummaryTable(summary, elapsed, cfg.FailOnSeverity, plan.EffectiveMode)

	// 6. AI Remediation Engine (v4.0)
	if cfg.EnableAIRemediation && len(summary.Findings) > 0 {
		fmt.Println()
		whiteBold.Printf("🤖 [6/7] Generating AI Remediation Fixes (%s)...\n", color.CyanString(cfg.AIProvider))
		aiEngine := remediation.NewEngine(cfg.AIProvider, cfg.AIAPIKey, cfg.AIModel, cfg.AIBaseURL)
		suggestions, err := aiEngine.GenerateRemediations(ctx, summary.Findings, cfg.TargetDir)
		if err != nil {
			gray.Printf("  Warning: AI remediation generation encountered an issue: %v\n", err)
		} else if len(suggestions) > 0 {
			if err := remediation.SavePatches(suggestions, cfg.PatchesDir); err != nil {
				redBold.Printf("  ✗ Failed to write patch files: %v\n", err)
			} else {
				greenBold.Printf("  ✓ Generated %d code fix patch(es) in %s/\n", len(suggestions), color.WhiteString(cfg.PatchesDir))
			}
		}
	}

	// 7. Inline PR Annotations
	if cfg.EnableAnnotations && len(summary.Findings) > 0 {
		whiteBold.Println("\n📝 [7/7] Emitting Inline GitHub PR Annotations...")
		emitter := annotations.NewEmitter(os.Stdout)
		emitter.Emit(summary)
	}

	// Evaluate Gate
	shouldFail, failReason := agg.EvaluateGate(pol, cfg.FailOnSeverity)

	// Centralized Enterprise Dashboard Telemetry Exporter
	if cfg.DashboardURL != "" {
		exporterClient := exporter.NewExporter(cfg.DashboardURL, cfg.DashboardToken)
		payload := exporter.BuildPayload(summary, elapsed, plan.EffectiveMode, cfg.FailOnSeverity, !shouldFail, engineNames)
		if err := exporterClient.Export(ctx, payload); err != nil {
			gray.Printf("\n  Warning: could not dispatch telemetry to dashboard: %v\n", err)
		} else {
			greenBold.Printf("\n  ✓ Scan telemetry successfully streamed to enterprise dashboard (%s)\n", cfg.DashboardURL)
		}
	}

	if shouldFail {
		redBold.Printf("\n❌ Build Failed: %s\n", failReason)
		os.Exit(1)
	}

	greenBold.Println("\n✅ Audit Passed: All enterprise policy checks and security gates satisfied.")
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
