/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// joinCmd represents the join command
var joinCmd = &cobra.Command{
	Use:   "join",
	Short: "join a network",
	Long: `join a netmaker network using: 

token: netclient join -t <token> // join using token

NOTE: Joining via SSO/basic auth (-s/-u/-n/-A) is no longer supported. Use -t <token> to join your device.`,

	PreRunE: refuseIfDesktopSession,
	Run: func(cmd *cobra.Command, args []string) {
		runEnrollmentRegistration(cmd)
	},
}

func init() {
	joinCmd.Flags().StringP(registerFlags.Server, "s", "", "deprecated: SSO/Auth join is no longer supported")
	joinCmd.Flags().StringP(registerFlags.Token, "t", "", "enrollment token for joining/registering")
	joinCmd.Flags().StringP(registerFlags.User, "u", "", "deprecated: Basic Auth join is no longer supported")
	joinCmd.Flags().StringP(registerFlags.Network, "n", "", "deprecated: SSO/Auth join is no longer supported")
	joinCmd.Flags().BoolP(registerFlags.AllNetworks, "A", false, "deprecated: SSO/Auth join is no longer supported")
	joinCmd.Flags().StringP(registerFlags.EndpointIP, "e", "", "sets endpoint on host")
	joinCmd.Flags().StringP(registerFlags.EndpointIP6, "E", "", "sets ipv6 endpoint on host")
	joinCmd.Flags().IntP(registerFlags.Port, "p", 0, "sets wg listen port")
	joinCmd.Flags().StringP(registerFlags.Name, "o", "", "sets host name")
	joinCmd.Flags().StringP(registerFlags.Interface, "I", "", "sets netmaker interface to use on host")
	joinCmd.Flags().StringP(registerFlags.Firewall, "f", "", "selects firewall to use on host: iptables/nftables")
	rootCmd.AddCommand(joinCmd)
}
