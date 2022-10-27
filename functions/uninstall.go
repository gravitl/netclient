package functions

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/netclient/daemon"
	"github.com/gravitl/netmaker/netclient/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// Uninstall - uninstalls networks from client
func Uninstall() error {
	networks, err := config.GetSystemNetworks()
	if err != nil {
		logger.Log(1, "unable to retrieve networks: ", err.Error())
		logger.Log(1, "continuing uninstall without leaving networks")
	} else {
		for _, network := range networks {
			err = LeaveNetwork(network)
			if err != nil {
				logger.Log(1, "encounter issue leaving network", network, ":", err.Error())
			}
		}
	}
	err = nil

	// clean up OS specific stuff
	if ncutils.IsWindows() {
		daemon.CleanupWindows()
	} else if ncutils.IsMac() {
		daemon.CleanupMac()
	} else if ncutils.IsLinux() {
		daemon.CleanupLinux()
	} else if ncutils.IsFreeBSD() {
		daemon.CleanupFreebsd()
	} else if !ncutils.IsKernel() {
		logger.Log(1, "manual cleanup required")
	}

	return err
}

// LeaveNetwork - client exits a network
func LeaveNetwork(network string) error {
	logger.Log(0, "leaving network", network)
	node, err := config.ReadConfig(network)
	if err != nil {
		return err
	}
	logger.Log(2, "deleting node from server")
	if err := deleteNodeFromServer(node); err != nil {
		logger.Log(0, "error deleting node from server", err.Error())
	}
	logger.Log(2, "deleting wireguard interface")
	if err := deleteLocalNetwork(node); err != nil {
		logger.Log(0, "error deleting wireguard interface", err.Error())
	}
	logger.Log(2, "deleting configuration files")
	if err := WipeLocal(node); err != nil {
		logger.Log(0, "error deleting local network files", err.Error())
	}
	logger.Log(2, "removing dns entries")
	if err := removeHostDNS(node.Interface, ncutils.IsWindows()); err != nil {
		logger.Log(0, "failed to delete dns entries for", node.Interface, err.Error())
	}
	logger.Log(2, "restarting daemon")
	return daemon.Restart()
}

func deleteNodeFromServer(node *config.Node) error {
	if node.IsServer {
		return errors.New("attempt to delete server node ... not permitted")
	}
	token, err := Authenticate(node)
	if err != nil {
		return fmt.Errorf("unable to authenticate %w", err)
	}
	server, err := config.ReadServerConfig(node.Server)
	if err != nil {
		return fmt.Errorf("could not read sever config %w", err)
	}
	endpoint := httpclient.Endpoint{
		URL:           "https://" + server.API,
		Method:        http.MethodPost,
		Route:         "/api/nodes/" + node.Network + "/" + node.ID,
		Authorization: "Bearer " + token,
	}
	response, err := endpoint.GetResponse()
	if err != nil {
		return fmt.Errorf("error deleting node on server: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		bodybytes, _ := io.ReadAll(response.Body)
		defer response.Body.Close()
		return fmt.Errorf("error deleting node from network %s on server %s %s", node.Network, response.Status, string(bodybytes))
	}
	return nil
}

func deleteLocalNetwork(node *config.Node) error {
	wgClient, wgErr := wgctrl.New()
	if wgErr != nil {
		return wgErr
	}
	removeIface := node.Interface
	queryAddr := node.PrimaryAddress()
	if ncutils.IsMac() {
		var macIface string
		macIface, wgErr = local.GetMacIface(queryAddr.IP.String())
		if wgErr == nil && removeIface != "" {
			removeIface = macIface
		}
	}
	dev, err := wgClient.Device(removeIface)
	if err != nil {
		return fmt.Errorf("error flushing routes %w", err)
	}
	local.FlushPeerRoutes(removeIface, dev.Peers[:])
	local.RemoveCIDRRoute(removeIface, &node.NetworkRange)
	return nil
}

// DeleteInterface - delete an interface of a network
func DeleteInterface(ifacename string, postdown string) error {
	return wireguard.RemoveConf(ifacename, true)
}

// WipeLocal - wipes local instance
func WipeLocal(node *config.Node) error {
	fail := false
	if err := wireguard.RemoveConf(node.Interface, true); err == nil {
		logger.Log(1, "network:", node.Network, "removed WireGuard interface: ", node.Interface)
	} else if strings.Contains(err.Error(), "does not exist") {
		err = nil
	} else {
		fail = true
	}
	if err := os.Remove(config.GetNetclientNodePath() + node.Network + ".yml"); err != nil {
		logger.Log(0, "failed to delete file", err.Error())
		fail = true
	}
	if err := os.Remove(config.GetNetclientNodePath() + node.Network + ".yml.bak"); err != nil {
		logger.Log(0, "failed to delete file", err.Error())
		fail = true
	}
	if fail {
		return errors.New("not all files were deleted")
	}
	return nil
}
