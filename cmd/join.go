/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
)

// joinCmd represents the join command
var joinCmd = &cobra.Command{
	Use:   "join",
	Short: "join a network",
	Long: `join a netmaker network using: 

token: netclient join -t <token> // join using token
server: netclient join -s <server> // join a specific server via SSO if Oauth configured
net: netclient join -s <server> -n <net> // attempt to join specified network via auth
all-networks: netclient join -s <server> -A // attempt to register to all allowed networks on given server via auth
user: netclient join -s <server> -u <user_name> // attempt to join/register via basic auth`,

	Run: func(cmd *cobra.Command, args []string) {
		setHostFields(cmd)
		token, err := cmd.Flags().GetString(registerFlags.Token)
		if err != nil || len(token) == 0 {
			if regErr := checkUserRegistration(cmd); regErr != nil {
				cmd.Usage()
				return
			}
		} else {
			if err := functions.Register(token, false); err != nil {
				logger.Log(0, "registration failed", err.Error())
			}
		}
	},
}

func init() {
	joinCmd.Flags().StringP(registerFlags.Server, "s", "", "server for attempting SSO/Auth registration")
	joinCmd.Flags().StringP(registerFlags.Token, "t", "", "enrollment token for joining/registering")
	joinCmd.Flags().StringP(registerFlags.User, "u", "", "user name for attempting Basic Auth join/registration")
	joinCmd.Flags().StringP(registerFlags.Network, "n", "", "network to attempt to join/register to")
	joinCmd.Flags().BoolP(registerFlags.AllNetworks, "A", false, "attempts to join/register to all available networks to user")
	joinCmd.Flags().StringP(registerFlags.EndpointIP, "e", "", "sets endpoint on host")
	joinCmd.Flags().IntP(registerFlags.Port, "p", 0, "sets wg listen port")
	joinCmd.Flags().StringP(registerFlags.MTU, "m", "", "sets MTU on host")
	joinCmd.Flags().BoolP(registerFlags.Static, "i", false, "flag to set host as static")
	joinCmd.Flags().StringP(registerFlags.Name, "o", "", "sets host name")
	rootCmd.AddCommand(joinCmd)
}
