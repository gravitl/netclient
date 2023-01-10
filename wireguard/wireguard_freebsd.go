package wireguard

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const kernelModule = "/boot/modules/if_wg.ko"

// Create - creates a linux WG interface based on a node's given config
func (nc *NCIface) Create() error {
	if _, err := os.Stat(kernelModule); err != nil {
		logger.Log(3, "using userspace wireguard")
		return nc.createUserSpaceWG()
	}
	logger.Log(3, "using kernel wireguard")
	return create(nc)
}

// Close - removes wg network interface from machine
func (nc *NCIface) Close() {
	ifconfig, err := exec.LookPath("ifconfig")
	if err != nil {
		logger.Log(0, "failed to locate ifconfig", err.Error())
		return
	}
	if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" destroy", true); err != nil {
		logger.Log(0, "error removing interface ", err.Error())
	}
}

// netLink.ApplyAddrs - applies the assigned node addresses to given interface (netLink)
func (nc *NCIface) ApplyAddrs() error {
	return nil
}

// netlink.SetMTU - set MTU for netmaker interface
func (nc *NCIface) SetMTU() error {
	ifconfig, err := exec.LookPath("ifconfig")
	if err != nil {
		logger.Log(0, "failed to locate ifconfig", err.Error())
		return err
	}
	//set MTU
	if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" mtu "+strconv.Itoa(nc.MTU), true); err != nil {
		return fmt.Errorf("error setting mtu %w", err)
	}
	return nil
}

// Configure does nothing on freebsd, all configuration is done by NCIface.Create()
func Configure() error {
	return nil
}

// SetPeers - sets peers on netmaker WireGuard interface
func SetPeers() error {
	nc := GetInterface()
	nc.Config.Peers = []wgtypes.PeerConfig{}
	peers := config.GetHostPeerList()
	for _, peer := range peers {
		nc.Config.Peers = append(nc.Config.Peers, peer)
		cmd := fmt.Sprintf("wg set %s peer %s endpoint %s ", nc.Name, peer.PublicKey, peer.Endpoint)
		for _, ip := range peer.AllowedIPs {
			cmd = cmd + "allowed-ips " + ip.String() + " "
		}
		if _, err := ncutils.RunCmd(cmd, true); err != nil {
			return fmt.Errorf("error adding peers %w", err)
		}
	}
	return nil
}

// == private ==

func create(nc *NCIface) error {
	ifconfig, err := exec.LookPath("ifconfig")
	if err != nil {
		return err
	}
	wg, err := exec.LookPath("wg")
	if err != nil {
		return err
	}
	if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name, true); err == nil {
		if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" destroy", true); err != nil {
			return err
		}
	}
	if _, err := ncutils.RunCmd(ifconfig+" wg create name "+nc.Name, true); err != nil {
		return err
	}
	//config
	if err := strip(); err != nil {
		return err
	}
	if err != nil {
		return err
	}
	if _, err := ncutils.RunCmd(fmt.Sprintf("%s setconf %s %s", wg, nc.Name, os.TempDir()+"/netmaker.conf"), true); err != nil {
		return err
	}
	if err := os.Remove(os.TempDir() + "/netmaker.conf"); err != nil {
		return err
	}
	//add addresses
	for _, address := range nc.Addresses {
		if address.IP.To4() != nil {
			if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" inet "+address.IP.String()+" alias", true); err != nil {
				return fmt.Errorf("error adding address to interface %w", err)
			}
		} else {
			if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" inet6 "+address.IP.String()+" alias", true); err != nil {
				return fmt.Errorf("error adding address to interface %w", err)
			}
		}
	}
	//set MTU
	if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" mtu "+strconv.Itoa(nc.MTU), true); err != nil {
		return fmt.Errorf("error setting mtu %w", err)
	}
	if _, err := ncutils.RunCmd(ifconfig+" "+nc.Name+" up", true); err != nil {
		return fmt.Errorf("error bringing up interface %w", err)
	}
	return nil
}

func strip() error {
	in, err := os.Open(config.GetNetclientPath() + "netmaker.conf")
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(os.TempDir() + "/netmaker.conf")
	if err != nil {
		return err
	}
	defer out.Close()
	writer := bufio.NewWriter(out)
	scan := bufio.NewScanner(in)
	scan.Split(bufio.ScanLines)
	for scan.Scan() {
		line := scan.Text()
		if strings.Contains(strings.ToLower(line), "address") {
			continue
		}
		if strings.Contains(strings.ToLower(line), "mtu") {
			continue
		}
		if strings.Contains(strings.ToLower(line), "dns") {
			continue
		}
		fmt.Fprint(writer, line+"\n")
	}
	writer.Flush()
	return nil
}

func apply(n *config.Node, c *wgtypes.Config) error {
	return nil
}
