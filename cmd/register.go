/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package cmd

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/schema"
	"github.com/spf13/cobra"
)

var registerFlags = struct {
	Firewall    string
	Server      string
	User        string
	Token       string
	Network     string
	AllNetworks string
	EndpointIP  string
	EndpointIP6 string
	Port        string
	Interface   string
	Name        string
	FwMark      string
}{
	Server:      "server",
	User:        "user",
	Token:       "token",
	Network:     "net",
	AllNetworks: "all-networks",
	EndpointIP:  "endpoint-ip",
	EndpointIP6: "endpoint-ip6",
	Port:        "port",
	Name:        "name",
	Interface:   "interface",
	Firewall:    "firewall",
	FwMark:      "fwmark",
}

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "register to a Netmaker instance",
	Long: `register to a Netmaker instance using: 
token: netclient register -t <token> // join using an enrollment token

NOTE: Registering via SSO/basic auth (-s/-u/-n/-A) is no longer supported. Use -t <token> to register your device.`,
	PreRunE: refuseIfDesktopSession,
	Run: func(cmd *cobra.Command, args []string) {
		runEnrollmentRegistration(cmd)
	},
}

// runEnrollmentRegistration registers the host using an enrollment token.
// Registration via SSO/basic auth (-s/-u/-n/-A) is no longer supported.
func runEnrollmentRegistration(cmd *cobra.Command) {
	token, err := cmd.Flags().GetString(registerFlags.Token)
	if err != nil || len(token) == 0 {
		logUnsupportedAuthRegistration(cmd)
		cmd.Usage()
		return
	}
	setHostFields(cmd)
	functions.Push(false)
	if err := functions.Register(token); err != nil {
		logger.Log(0, "registration failed", err.Error())
	}
}

func setHostFields(cmd *cobra.Command) {
	fmt.Println("setting host fields")
	port, err := cmd.Flags().GetInt(registerFlags.Port)
	if err == nil && port != 0 && port != config.Netclient().ListenPort {
		// check if port is available
		if !ncutils.IsPortFree(port) {
			fmt.Printf("port %d is not free\n", port)
			os.Exit(1)
		}
		config.Netclient().ListenPort = port
		config.Netclient().IsStaticPort = true
	}
	endpointIP, err := cmd.Flags().GetString(registerFlags.EndpointIP)
	if err == nil && endpointIP != "" {
		config.Netclient().EndpointIP = net.ParseIP(endpointIP)
		config.Netclient().IsStatic = true
	}
	endpointIP6, err := cmd.Flags().GetString(registerFlags.EndpointIP6)
	if err == nil && endpointIP6 != "" {
		config.Netclient().EndpointIPv6 = net.ParseIP(endpointIP6)
		config.Netclient().IsStatic = true
	}
	if hostName, err := cmd.Flags().GetString(registerFlags.Name); err == nil && hostName != "" {
		config.Netclient().Name = hostName
	}
	if ifaceName, err := cmd.Flags().GetString(registerFlags.Interface); err == nil && ifaceName != "" {
		if !validateIface(ifaceName) {
			fmt.Println("invalid interface name", ifaceName)
			os.Exit(1)
		}
		config.Netclient().Interface = ifaceName
	}
	if firewall, err := cmd.Flags().GetString(registerFlags.Firewall); err == nil {
		if ncutils.IsLinux() && (firewall == schema.FIREWALL_IPTABLES || firewall == schema.FIREWALL_NFTABLES) {
			// check if firewall is present
			if firewall == schema.FIREWALL_IPTABLES {
				if !ncutils.IsIPTablesPresent() {
					fmt.Println("iptables is not present")
					os.Exit(1)
				}
			}
			if firewall == schema.FIREWALL_NFTABLES {
				if !ncutils.IsNFTablesPresent() {
					fmt.Println("nftables is not present")
					os.Exit(1)
				}
			}
			config.Netclient().FirewallInUse = firewall
		}
	}
}
func validateIface(iface string) bool {
	if iface == "" {
		return false
	}
	exists, err := ncutils.InterfaceExists(iface)
	if err != nil {
		fmt.Println("error checking for interfaces ", err)
		return false
	}
	if exists {
		fmt.Printf("iface `%s` already exists\n", iface)
		return false
	}
	if iface == "netmaker-test" || iface == "utun70" {
		fmt.Println("cannot use `netmaker-test` interface")
		return false
	}
	if runtime.GOOS == "darwin" && !strings.HasPrefix(iface, "utun") {
		fmt.Println("use utun as interface on darwin")
		return false
	}
	if runtime.GOOS != "darwin" && !strings.HasPrefix(iface, "netmaker") {
		fmt.Println("invalid interface name, should contain `netmaker` as prefix")
		return false
	}
	return true
}

func logUnsupportedAuthRegistration(cmd *cobra.Command) {
	msg := "joining/registering without an enrollment token is no longer supported; use an enrollment token instead: netclient join -t <token>"
	for _, flag := range []string{registerFlags.Server, registerFlags.User, registerFlags.Network, registerFlags.AllNetworks} {
		if cmd.Flags().Changed(flag) {
			msg = "joining/registering via -s (SSO), -u (basic auth), -n or -A is no longer supported; use an enrollment token instead: netclient join -t <token>"
			break
		}
	}
	logger.Log(0, msg)
}

func init() {
	registerCmd.Flags().StringP(registerFlags.Server, "s", "", "deprecated: SSO/Auth registration is no longer supported")
	registerCmd.Flags().StringP(registerFlags.Token, "t", "", "enrollment token for registering to a Netmaker instance")
	registerCmd.Flags().StringP(registerFlags.User, "u", "", "deprecated: Basic Auth registration is no longer supported")
	registerCmd.Flags().StringP(registerFlags.Network, "n", "", "deprecated: SSO/Auth registration is no longer supported")
	registerCmd.Flags().BoolP(registerFlags.AllNetworks, "A", false, "deprecated: SSO/Auth registration is no longer supported")
	registerCmd.Flags().StringP(registerFlags.EndpointIP, "e", "", "sets endpoint on host")
	registerCmd.Flags().StringP(registerFlags.EndpointIP6, "E", "", "sets ipv6 endpoint on host")
	registerCmd.Flags().IntP(registerFlags.Port, "p", 0, "sets wg listen port")
	registerCmd.Flags().StringP(registerFlags.Name, "o", "", "sets host name")
	registerCmd.Flags().StringP(registerFlags.Interface, "I", "", "sets netmaker interface to use on host")
	registerCmd.Flags().StringP(registerFlags.Firewall, "f", "", "selects firewall to use on host")
	rootCmd.AddCommand(registerCmd)
}
