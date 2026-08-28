package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print AegisCI version, commit, build date, and runtime platform",
	Long:  "Displays detailed version and build information for the AegisCI CLI binary.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("aegisci version %s\n", Version)
		fmt.Printf("  commit:     %s\n", Commit)
		fmt.Printf("  built at:   %s\n", Date)
		fmt.Printf("  built by:   %s\n", BuiltBy)
		fmt.Printf("  os/arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("  go version: %s\n", runtime.Version())
	},
}
