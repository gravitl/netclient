/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"fmt"
	"syscall"

	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
	"golang.org/x/term"
)

var registerFlags = struct {
	Server      string
	User        string
	Token       string
	Network     string
	AllNetworks string
	EndpointIp  string
	ListenPort  string
}{
	Server:      "server",
	User:        "user",
	Token:       "token",
	Network:     "net",
	AllNetworks: "all-networks",
	EndpointIp:  "endpoint-ip",
	ListenPort:  "listen-port",
}

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "register to a Netmaker instance",
	Long: `register to a Netmaker instance using: 
token: netclient register -t <token> // join using an enrollment token
server: netclient register -s <server> // join a specific server via SSO if Oauth configured
net: netclient register -s <server> -n <net> // attempt to join specified network via auth
all-networks: netclient register -s <server> -A // attempt to register to all allowed networks on given server via auth
user: netclient register -s <server> -u <user_name> // attempt to join/register via basic auth
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

func checkUserRegistration(cmd *cobra.Command) error {
	apiURI, err := cmd.Flags().GetString(registerFlags.Server)
	if err != nil {
		return err
	}

	var regData = functions.SSORegisterData{
		API:      apiURI,
		UsingSSO: true,
	}

	network, err := cmd.Flags().GetString(registerFlags.Network)
	if err == nil {
		regData.Network = network
	}

	useAllNetworks, err := cmd.Flags().GetBool(registerFlags.AllNetworks)
	if err == nil {
		regData.AllNetworks = useAllNetworks
	}

	userName, err := cmd.Flags().GetString(registerFlags.User)
	if err == nil && len(userName) > 0 {
		fmt.Printf("Continuing with user, %s.\nPlease input password:\n", userName)
		pass, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil || len(pass) == 0 {
			logger.FatalLog("no password provided, exiting")
		}
		regData.User = userName
		regData.Pass = string(pass)
		pass = nil
		regData.UsingSSO = false
	}

	endpointIp, err := cmd.Flags().GetString(registerFlags.EndpointIp)
	if err != nil {
		slog.Error("error parsing endpoint ip", "error", err)
		return err
	}
	listenPort, err := cmd.Flags().GetInt(registerFlags.ListenPort)
	if err != nil {
		slog.Error("error parsing listen port", "error", err)
		return err
	}
	regData.CustomEndpointIp = endpointIp
	regData.CustomListenPort = listenPort

	return functions.RegisterWithSSO(&regData, false)
}

func init() {
	registerCmd.Flags().StringP(registerFlags.Server, "s", "", "server for attempting SSO/Auth registration")
	registerCmd.Flags().StringP(registerFlags.Token, "t", "", "enrollment token for registering to a Netmaker instance")
	registerCmd.Flags().StringP(registerFlags.User, "u", "", "user name for attempting Basic Auth registration")
	registerCmd.Flags().StringP(registerFlags.Network, "n", "", "network to attempt to register to")
	registerCmd.Flags().StringP(registerFlags.EndpointIp, "e", "", "custom endpoint ip to register with")
	registerCmd.Flags().IntP(registerFlags.ListenPort, "p", 0, "custom listen port to register with")
	registerCmd.Flags().BoolP(registerFlags.AllNetworks, "A", false, "attempts to register to all available networks to user")
	rootCmd.AddCommand(registerCmd)
}
