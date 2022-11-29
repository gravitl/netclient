/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"os"

	"github.com/gravitl/netclient/functions"
	ncmodels "github.com/gravitl/netclient/models"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// joinCmd represents the join command
var joinCmd = &cobra.Command{
	Use:   "join",
	Short: "join a network",

	Long: `join a netmaker network using: 

token: netclient join -t <token> // join using token
user: netclient join -s <api endpoint> -n <network name> [-u <user>] // join by signing in
additional paramaters can be be specified such as listenport or macaddress -- see help for fulll list`,
	Run: func(cmd *cobra.Command, args []string) {
		flags := viper.New()
		flags.BindPFlags(cmd.Flags())
		if flags.Get("server") == "" && flags.Get("token") == "" && flags.Get("key") == "" {
			cmd.Usage()
			return
		}
		nwParams := parseJoinFlags(flags)
		functions.Join(nwParams)
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
	joinCmd.Flags().Bool("ipforwarding", true, "set ipforwarding on/off")

	joinCmd.Flags().Int("keepalive", 20, "persistent keepalive for wireguard peers")
	joinCmd.Flags().Int("port", 0, "port for wireguard interface, will turn udpholepunching off")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// joinCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// joinCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// parseJoinFlags converts join flags into NetworkParams
func parseJoinFlags(flags *viper.Viper) *ncmodels.NetworkParams {
	return &ncmodels.NetworkParams{
		Network:         flags.GetString("network"),
		Server:          flags.GetString("server"),
		Port:            flags.GetInt32("port"),
		Endpoint:        flags.GetString("endpoint"),
		IsLocal:         flags.GetBool("islocal"),
		ApiConn:         flags.GetString("apiconn"),
		PrivateKey:      flags.GetString("privatekey"),
		MacAddress:      flags.GetString("macaddress"),
		Name:            flags.GetString("name"),
		AccessKey:       flags.GetString("accesskey"),
		Password:        flags.GetString("password"),
		Key:             flags.GetString("key"),
		Token:           flags.GetString("token"),
		User:            flags.GetString("user"),
		PublicKey:       flags.GetString("publickey"),
		LocalAddress:    flags.GetString("localaddress"),
		Address:         flags.GetString("address"),
		Address6:        flags.GetString("address6"),
		Interface:       flags.GetString("interface"),
		PostUp:          flags.GetString("postup"),
		PostDown:        flags.GetString("postdown"),
		PublicIpService: flags.GetString("publicipservice"),
		IsStatic:        flags.GetBool("static"),
		IsDnsOn:         flags.GetBool("dnson"),
		IsIpForwarding:  flags.GetBool("ipforwarding"),
		KeepAlive:       flags.GetInt("keepalive"),
	}
}
