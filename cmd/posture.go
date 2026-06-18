/*
Copyright © 2026 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netclient/posture"
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

var postureIdentityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Print locally collected device identity fields",
	Long: `Shows hostname, serial, hardware UUID, and Entra device ID as
collected on this machine. Useful for verifying posture identity before check-in.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		id := posture.Collect()
		b, err := json.MarshalIndent(id, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "posture identity error:", err)
			os.Exit(2)
		}
		fmt.Println(string(b))
	},
}

func init() {
	rootCmd.AddCommand(postureCmd)
	postureCmd.AddCommand(postureStatusCmd)
	postureCmd.AddCommand(postureIdentityCmd)
	postureStatusCmd.Flags().BoolP("json", "j", false, "dump the raw JSON response")
}
