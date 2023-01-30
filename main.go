//go:generate goversioninfo -icon=resources/windows/netclient.ico -manifest=resources/windows/netclient.exe.manifest.xml -64=true -o=netclient.syso

/*
Copyright © 2022 Netmaker Team <info@netmaker.io>
*/
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TODO: use -ldflags to set the right version at build time
var version = "v0.18.0"

var guiFunc = func() {}

func main() {

	ncArgs := os.Args
	if len(ncArgs) > 1 && ncArgs[1] != "gui" ||
		len(ncArgs) == 1 && runtime.GOOS != "windows" { // windows by default uses gui
		config.SetVersion(version)
		test2()
		//cmd.Execute()
	} else {
		guiFunc()
	}
}

func test2() {
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
	for i := 1; i < 6; i++ {
		wgMutex.Lock()
		netmaker.SetMTU()
		if err := client.ConfigureDevice("netmaker", config); err != nil {
			log.Println("apply --> ", err)
		}
		wgMutex.Unlock()
		time.Sleep(time.Second * 2)
	}
}
