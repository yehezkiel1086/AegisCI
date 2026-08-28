package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	// build metadata injected by goreleaser
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
	BuiltBy = "source"

	banner = `
    _              _       ____ ___ 
   / \   ___  __ _(_)___  / ___|_ _|
  / _ \ / _ \/ _` + "`" + ` | / __|| |    | | 
 / ___ \  __/ (_| | \__ \| |___ | | 
/_/   \_\___|\__, |_|___(_)____|___|
             |___/                  
`
	cyanBold  = color.New(color.FgCyan, color.Bold)
	whiteBold = color.New(color.FgWhite, color.Bold)
	gray      = color.New(color.FgHiBlack)
)

var rootCmd = &cobra.Command{
	Use:   "aegisci",
	Short: "AegisCI - All-in-One DevSecOps Scanner & Security Orchestrator",
	Long: `AegisCI is a multi-engine DevSecOps scanner and security orchestrator.
It consolidates SAST, DAST, Secrets, SCA, IaC, CI Linters, Custom Plugins, and AI Remediation into a unified SARIF report.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		printBanner()
		return cmd.Help()
	},
}

func printBanner() {
	cyanBold.Print(banner)
	whiteBold.Printf(" AegisCI Security Orchestrator (v%s)\n", Version)
	gray.Println(" ==========================================================================")
	fmt.Println()
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}
