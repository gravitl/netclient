/*
Copyright © 2026 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/gravitl/netclient/functions"
	"github.com/spf13/cobra"
)

var postureCmd = &cobra.Command{
	Use:   "posture",
	Short: "Inspect the host's posture status",
	Long:  `Subcommands for inspecting Netmaker posture-check evaluation results for this host.`,
}

var postureStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the host's last-evaluated posture status",
	Long: `Fetches the most recent posture status evaluated by the Netmaker server for this host.

The output includes the active MDM enrollment/compliance snapshot (when MDM is configured)
and per-network violation summaries.

Exit codes:
  0 - all networks pass
  1 - one or more networks have a 'fail' status (high severity violation)
  2 - transport / authentication error`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		code, err := functions.PostureStatus(jsonOutput)
		if err != nil {
			fmt.Fprintln(os.Stderr, "posture status error:", err)
		}
		os.Exit(code)
	},
}

func init() {
	rootCmd.AddCommand(postureCmd)
	postureCmd.AddCommand(postureStatusCmd)
	postureStatusCmd.Flags().BoolP("json", "j", false, "dump the raw JSON response")
}
