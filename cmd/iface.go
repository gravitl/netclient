/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/gravitl/netclient/wireguard"
	"github.com/spf13/cobra"
)

var ifaceCmd = &cobra.Command{
	Use:   "iface",
	Short: "dump wireguard interface reconciliation state",
	Long: `Show desired, existing, and planned wireguard interface actions.

Example:
  netclient iface
  netclient iface -j`,
	Run: func(cmd *cobra.Command, args []string) {
		plan := wireguard.DumpReconcilePlan()
		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			out, err := json.MarshalIndent(plan, "", "  ")
			if err != nil {
				fmt.Println("failed to encode reconciliation plan:", err)
				return
			}
			fmt.Println(string(out))
			return
		}
		fmt.Printf("desired interface: %s\n", plan.Desired)
		fmt.Printf("generated at: %s\n\n", plan.Generated.Format("2006-01-02T15:04:05Z07:00"))
		if len(plan.Existing) == 0 {
			fmt.Println("no wireguard interfaces found on host")
			return
		}
		for _, entry := range plan.Existing {
			fmt.Printf("- name=%s present=%v owned=%v wireguard=%v action=%s alias=%q type=%s\n",
				entry.Name, entry.Present, entry.Owned, entry.IsWireGuard, entry.Action, entry.Alias, entry.Type)
		}
		fmt.Printf("\nmetrics: create=%d reuse=%d delete=%d create_errors=%d\n",
			wireguard.IfaceMetrics.CreateTotal.Load(),
			wireguard.IfaceMetrics.ReuseTotal.Load(),
			wireguard.IfaceMetrics.DeleteTotal.Load(),
			wireguard.IfaceMetrics.CreateErrorsTotal.Load(),
		)
	},
}

func init() {
	rootCmd.AddCommand(ifaceCmd)
	ifaceCmd.Flags().BoolP("json", "j", false, "output reconciliation plan as JSON")
}
