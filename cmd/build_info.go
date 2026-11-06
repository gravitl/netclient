package cmd

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/gravitl/netclient/config"
	"github.com/spf13/cobra"
)

// buildInfoCmd prints compile-time identity so operators can tell a headless
// binary from a Desktop (-tags desktop) GUI daemon.
var buildInfoCmd = &cobra.Command{
	Use:     "build-info",
	Aliases: []string{"info"},
	Short:   "show netclient build profile and version",
	Long: `Show which netclient binary this is.

Default builds are headless (no uiapi / Desktop hooks).
Desktop GUI daemons are built with -tags desktop and report profile=desktop.

Examples:
  netclient build-info
  netclient info
  netclient build-info -l`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		long, err := cmd.Flags().GetBool("long")
		if err != nil {
			return err
		}
		printBuildInfo(long)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(buildInfoCmd)
	buildInfoCmd.Flags().BoolP("long", "l", false, "include Go toolchain and VCS settings")
}

func printBuildInfo(long bool) {
	fmt.Printf("version:\t%s\n", config.Version)
	fmt.Printf("profile:\t%s\n", buildProfile)
	fmt.Printf("desktop:\t%v\n", desktopLinked)
	fmt.Printf("os/arch:\t%s/%s\n", runtime.GOOS, runtime.GOARCH)

	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return
	}
	fmt.Printf("go:\t\t%s\n", info.GoVersion)

	rev := setting(info, "vcs.revision")
	if rev != "" {
		short := rev
		if len(short) > 12 {
			short = short[:12]
		}
		fmt.Printf("commit:\t\t%s\n", short)
	}
	if !long {
		return
	}
	if rev != "" {
		fmt.Printf("vcs.revision:\t%s\n", rev)
	}
	for _, k := range []string{"vcs.time", "vcs.modified", "CGO_ENABLED"} {
		if v := setting(info, k); v != "" {
			fmt.Printf("%s:\t%s\n", k, v)
		}
	}
	// Build tags appear as a -tags setting when set via -tags on go build.
	if tags := setting(info, "-tags"); tags != "" {
		fmt.Printf("tags:\t\t%s\n", tags)
	}
}

func setting(info *debug.BuildInfo, key string) string {
	for _, s := range info.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}
