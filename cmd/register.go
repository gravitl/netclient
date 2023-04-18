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
	"golang.org/x/term"
)

var registerFlags = struct {
	Server      string
	User        string
	Token       string
	Network     string
	AllNetworks string
}{
	Server:      "server",
	User:        "user",
	Token:       "token",
	Network:     "net",
	AllNetworks: "all-networks",
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
user: netclient register -s <server> -u <user_name> // attempt to join/register via basic auth`,
	Run: func(cmd *cobra.Command, args []string) {
		token, err := cmd.Flags().GetString(registerFlags.Token)
		if err != nil || len(token) == 0 {
			if regErr := checkUserRegistration(cmd); regErr != nil {
				cmd.Usage()
				return
			}
		} else {
			if err := functions.Register(token); err != nil {
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

	var regData = functions.RegisterSSO{
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

	return functions.RegisterWithSSO(&regData)
}

func init() {
	registerCmd.Flags().StringP(registerFlags.Server, "s", "", "server for attempting SSO/Auth registration")
	registerCmd.Flags().StringP(registerFlags.Token, "t", "", "enrollment token for registering to a Netmaker instance")
	registerCmd.Flags().StringP(registerFlags.User, "u", "", "user name for attempting Basic Auth registration")
	registerCmd.Flags().StringP(registerFlags.Network, "n", "", "network to attempt to register to")
	registerCmd.Flags().BoolP(registerFlags.AllNetworks, "A", false, "attempts to register to all available networks to user")
	rootCmd.AddCommand(registerCmd)
}
