/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netmaker/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// joinCmd represents the join command
var joinCmd = &cobra.Command{
	Use:   "join",
	Short: "join a network",

	Long: `join a netmaker network using: A longer description that spans multiple lines and likely contains examples

token: netclient join -t <token>
user: netclient join -s <api endpoint> -n <network name> -u <user>
additional paramaters can be be specified such as listenport or macaddress -- see help for fulll list`,
	Run: func(cmd *cobra.Command, args []string) {
		node := &config.Node{}
		server := &config.Server{}
		//config.ParseJoinFlags(cmd)
		flags := viper.New()
		flags.BindPFlags(cmd.Flags())
		if flags.Get("server") == "" && flags.Get("token") == "" && flags.Get("key") == "" {
			cmd.Usage()
			return
		}
		fmt.Println("join called")
		//pretty.Println(cmd.Flags())
		//pretty.Println(viper.AllSettings())

		if flags.Get("server") != "" {
			//SSO sign on
			if flags.Get("network") == "" {
				logger.Log(0, "no network provided")
			}
			token, err := functions.JoinViaSSo(flags)
			if err != nil {
				logger.Log(0, "Join failed:", err.Error())
				return
			}
			if token.Key == "" {
				fmt.Println("login failed")
				return
			}
			node.Network = token.ClientConfig.Network
			node.AccessKey = token.ClientConfig.Key
			node.LocalRange = config.ToIPNet(token.ClientConfig.LocalRange)
			server.API = token.APIConnString

		}
		logger.Log(1, "Joining network: ", node.Network)
		token := flags.Get("token").(string)
		if token != "" {
			logger.Log(3, "parsing token flag")
			accessToken, err := config.ParseAccessToken(token)
			if err != nil {
				logger.Log(0, "failed to parse access token", token, err.Error())
				return
			}
			flags.Set("network", accessToken.ClientConfig.Network)
			flags.Set("accesskey", accessToken.ClientConfig.Key)
			flags.Set("localrange", accessToken.ClientConfig.LocalRange)
			flags.Set("apiconn", accessToken.APIConnString)

		}
		if err := functions.JoinNetwork(flags); err != nil {
			if !strings.Contains(err.Error(), "ALREADY_INSTALLED") {
				logger.Log(0, "error installing: ", err.Error())
				err = functions.WipeLocal(node)
				if err != nil {
					logger.Log(1, "error removing artifacts: ", err.Error())
				}
			}
			if strings.Contains(err.Error(), "ALREADY_INSTALLED") {
				logger.FatalLog(err.Error())
			}
			return
		}
		logger.Log(1, "joined", node.Network)
	},
}

func init() {
	hostname, _ := os.Hostname()
	rootCmd.AddCommand(joinCmd)
	joinCmd.Flags().StringP("token", "t", "", "access token for joining network")
	joinCmd.Flags().StringP("key", "k", "", "access key for joining network")
	joinCmd.Flags().StringP("server", "s", "", "api endpoint of netmaker server (api.example.com)")
	joinCmd.Flags().StringP("user", "u", "", "username of netmaker user")
	joinCmd.Flags().StringP("network", "n", "", "network to perform spedified action against")
	joinCmd.Flags().StringP("password", "p", "", "password for authentication with netmaker")
	joinCmd.Flags().StringP("endpoint", "e", "", "reachable(usually public) address for wireguard (not the private wg address")
	joinCmd.Flags().StringP("macaddress", "m", "", "macaddress for this machine")
	joinCmd.Flags().String("name", hostname, "indentifiable name for machine in netmaker network")
	joinCmd.Flags().String("publickey", "", "public key for wireguard")
	joinCmd.Flags().String("privatekey", "", "private key for wireguard")
	joinCmd.Flags().String("localaddress", "", "localaddress for machine. can be used in place of endpoint for machines on same lan")
	joinCmd.Flags().String("address", "", "wireguard address (ipv4) for machine in netmaker network")
	joinCmd.Flags().String("address6", "", "wireguard address (ipv6) for machine in netmaker network")
	joinCmd.Flags().String("interface", "", "wireguard interface name")
	joinCmd.Flags().String("postup", "", "wireguard postup command(s)")
	joinCmd.Flags().String("postdown", "", "wireguard postdown command(s)")
	joinCmd.Flags().String("publicipservice", "", "service to call to obtain the public ip of machine")

	joinCmd.Flags().Bool("static", false, "netclient will not check for public address changes")
	joinCmd.Flags().Bool("dnson", true, "use private dns")
	joinCmd.Flags().Bool("islocal", false, "use localaddress for wg endpoint")
	joinCmd.Flags().Bool("udpholepunch", false, "use udpholepunching (dynamic listen ports)")
	joinCmd.Flags().Bool("ipforwarding", true, "set ipforwarding on/off")

	joinCmd.Flags().Int("keepalive", 20, "persistent keepalive for wireguard peers")
	joinCmd.Flags().Int("port", 51821, "port for wireguard interface")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// joinCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// joinCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
