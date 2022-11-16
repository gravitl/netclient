/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/gravitl/netclient/config"
	"github.com/kr/pretty"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Displays version information",
	Long: `Displays the current version of netclient

-l, --long flag provides detailed information`,
	Run: func(cmd *cobra.Command, args []string) {
		long, _ := cmd.Flags().GetBool("long")
		if long {
			info, _ := debug.ReadBuildInfo()
			pretty.Println(info.Settings)
		}
		fmt.Println(config.Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().BoolP("long", "l", false, "display detailded version information")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// versionCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// versionCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
