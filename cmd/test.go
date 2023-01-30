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
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/kr/pretty"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// testCmd represents the test command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("test called")
		config.ReadNetclientConfig()
		config.ReadNodeConfig()
		config.ReadServerConf()
		nodes := config.GetNodes()
		nc := wireguard.NewNCIface(config.Netclient(), nodes)
		pretty.Println(nc)
		if err := nc.Create(); err != nil {
			log.Fatal("create", err)
		}
		out, _ := ncutils.RunCmd("wg", true)
		log.Println(out)
		//if err := nc.Configure(); err != nil {
		//log.Fatal("configure ", err)
		//}
		time.Sleep(time.Second * 5)
		wgMutex := sync.Mutex{}
		wgMutex.Lock()
		defer wgMutex.Unlock()
		client, _ := wgctrl.New()
		defer client.Close()
		//netmaker.SetMTU()
		if err := client.ConfigureDevice("netmaker", nc.Config); err != nil {
			log.Fatal("apply --> ", err)
		}

	},
}

func init() {
	rootCmd.AddCommand(testCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// testCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// testCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
