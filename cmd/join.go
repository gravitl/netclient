/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
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
user: netclient join -s <server> -u <user_name> // attempt to join/register via basic auth
custom port and ip: netclient register -t <token> -p <port> -e <ip> // attempt to join/register via token with custom port and ip (custom port and ip only works on first register)`,

	Run: func(cmd *cobra.Command, args []string) {
		endpointIp, err := cmd.Flags().GetString(registerFlags.EndpointIp)
		if err != nil {
			slog.Error("error parsing endpoint ip", "error", err)
			return
		}
		listenPort, err := cmd.Flags().GetInt(registerFlags.ListenPort)
		if err != nil {
			slog.Error("error parsing listen port", "error", err)
			return
		}
		token, err := cmd.Flags().GetString(registerFlags.Token)
		if err != nil || len(token) == 0 {
			if regErr := checkUserRegistration(cmd); regErr != nil {
				cmd.Usage()
				return
			}
		} else {
			if err := functions.Register(functions.TokenRegisterData{
				Token:            token,
				CustomEndpointIp: endpointIp,
				CustomListenPort: listenPort,
			}, false); err != nil {
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
	joinCmd.Flags().StringP(registerFlags.EndpointIp, "e", "", "custom endpoint ip to join with")
	joinCmd.Flags().IntP(registerFlags.ListenPort, "p", 0, "custom listen port to join with")
	joinCmd.Flags().BoolP(registerFlags.AllNetworks, "A", false, "attempts to join/register to all available networks to user")
	rootCmd.AddCommand(joinCmd)
}
