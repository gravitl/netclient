/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"fmt"

	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
)

var peersCmd = &cobra.Command{
	Use:   "peers [network]",
	Short: "display WireGuard peer information",
	Long: `display peer information from the WireGuard interface including:
- Public key
- Node/host name
- Endpoint
- Last handshake time
- Traffic statistics (bytes received/sent)
- Allowed IPs

For example:
netclient peers           // display peers for all networks (grouped by network)
netclient peers mynet     // display peers only for network "mynet"
netclient peers -j        // display peers for all networks in JSON format
netclient peers mynet -j  // display peers for network "mynet" in JSON format`,
	Args: cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, err := cmd.Flags().GetBool("json")
		if err != nil {
			logger.Log(0, "error getting flags", err.Error())
			return
		}
		var network string
		if len(args) == 1 {
			network = args[0]
		}
		if err := functions.ShowPeers(jsonOutput, network); err != nil {
			fmt.Println("\nFailed to get peer information:", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(peersCmd)
	peersCmd.Flags().BoolP("json", "j", false, "display peer information in JSON format")
}
