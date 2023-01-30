/*
Copyright © 2023 Matthew R Kasun <mkasun@nusak.ca>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"log"
	"os/exec"
	"sync"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// test2Cmd represents the test2 command
var test2Cmd = &cobra.Command{
	Use:   "test2",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("test2 called")
		wgMutex := sync.Mutex{}
		client, err := wgctrl.New()
		if err != nil {
			log.Fatal(err)
		}
		defer client.Close()
		//create
		ifconfig, _ := exec.LookPath("ifconfig")
		if _, err := ncutils.RunCmd(ifconfig+" netmaker", false); err == nil {
			if _, err := ncutils.RunCmd(ifconfig+" netmaker destroy", false); err != nil {
				log.Fatal("deleting interface", err)
			}
		}
		if out, err := ncutils.RunCmd(ifconfig+" wg create name netmaker", true); err != nil {
			log.Println(out)
			log.Fatal("ifconfig ", err)
		}

		//NewIface
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Fatal("key gen", err)
		}
		port := 51830
		mtu := 1420

		config := wgtypes.Config{
			PrivateKey: &key,
			ListenPort: &port,
		}
		netmaker := wireguard.NCIface{

			Name: ncutils.GetInterfaceName(),
			MTU:  mtu,
			//Iface:     "",
			Addresses: nil,
			Config: wgtypes.Config{
				PrivateKey:   &key,
				FirewallMark: nil,
				ListenPort:   &port,
				ReplacePeers: true,
				Peers:        nil,
			},
		}

		// configure
		wgMutex.Lock()
		defer wgMutex.Unlock()
		netmaker.SetMTU()
		if err := client.ConfigureDevice("netmaker", config); err != nil {
			log.Fatal("apply --> ", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(test2Cmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// test2Cmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// test2Cmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
