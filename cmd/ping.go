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

// pingCmd represents the ping command
var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "check connectivity and latency to peers",
	Long: `check connectivity and latency from this host to WireGuard peers.

Examples:
  netclient ping                    # check all peers on all networks (uses default address)
  netclient ping -n mynet           # check all peers on network "mynet"
  netclient ping -p node-a          # check connectivity to peer "node-a" across all networks
  netclient ping -n mynet -p node-a # check connectivity to peer "node-a" on "mynet"
  netclient ping -4                 # use IPv4 addresses (Address4 field)
  netclient ping -6                 # use IPv6 addresses (Address6 field)`,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, err := cmd.Flags().GetBool("json")
		if err != nil {
			logger.Log(0, "error getting flags", err.Error())
			return
		}

		count, err := cmd.Flags().GetInt("count")
		if err != nil {
			logger.Log(0, "error getting count flag", err.Error())
			return
		}
		if count <= 0 {
			count = 2
		}

		network, err := cmd.Flags().GetString("network")
		if err != nil {
			logger.Log(0, "error getting network flag", err.Error())
			return
		}

		peer, err := cmd.Flags().GetString("peer")
		if err != nil {
			logger.Log(0, "error getting peer flag", err.Error())
			return
		}

		ipv4, err := cmd.Flags().GetBool("4")
		if err != nil {
			logger.Log(0, "error getting ipv4 flag", err.Error())
			return
		}

		ipv6, err := cmd.Flags().GetBool("6")
		if err != nil {
			logger.Log(0, "error getting ipv6 flag", err.Error())
			return
		}

		ipVersion := ""
		if ipv4 {
			ipVersion = "4"
		} else if ipv6 {
			ipVersion = "6"
		}

		if err := functions.PingPeers(network, peer, jsonOutput, count, ipVersion); err != nil {
			fmt.Println("\nFailed to ping peers:", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(pingCmd)
	pingCmd.Flags().BoolP("json", "j", false, "display ping results in JSON format")
	pingCmd.Flags().IntP("count", "c", 3, "number of packets/probes to send per peer")
	pingCmd.Flags().StringP("network", "n", "", "network name to filter peers")
	pingCmd.Flags().StringP("peer", "p", "", "peer name, address, or ID to filter (case-insensitive)")
	pingCmd.Flags().BoolP("4", "4", false, "use IPv4 address (Address4 field)")
	pingCmd.Flags().BoolP("6", "6", false, "use IPv6 address (Address6 field)")
}
