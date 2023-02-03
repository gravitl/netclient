package wg

import (
	"fmt"
	"sync"

	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGIface represents a interface instance
type WGIface struct {
	Name   string
	Device *wgtypes.Device
	mu     sync.Mutex
}

// GetWgIface - gets the Wireguard interface config
func GetWgIface(iface string) (*WGIface, error) {
	wgIface := &WGIface{
		Name: iface,
		mu:   sync.Mutex{},
	}
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	wgIface.Device, err = wgClient.Device(iface)
	if err != nil {
		return nil, err
	}
	return wgIface, nil
}

// UpdatePeer updates existing Wireguard Peer or creates a new one if doesn't exist
func (w *WGIface) UpdatePeerEndpoint(peer wgtypes.PeerConfig) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	logger.Log(0, "updating interface %s peer %s: endpoint %s ", w.Name, peer.PublicKey.String(), peer.Endpoint.String())

	// //parse allowed ips
	// _, ipNet, err := net.ParseCIDR(allowedIps)
	// if err != nil {
	// 	return err
	// }

	peerN := wgtypes.PeerConfig{
		UpdateOnly: true,
		PublicKey:  peer.PublicKey,
		Endpoint:   peer.Endpoint,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerN},
	}
	err := w.configureDevice(config)
	if err != nil {
		return fmt.Errorf("received error \"%v\" while updating peer on interface %s with settings: endpoint %s", err, w.Name, peer.Endpoint.String())
	}
	return nil
}

// configureDevice configures the wireguard device
func (w *WGIface) configureDevice(config wgtypes.Config) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()

	// validate if device with name exists
	_, err = wg.Device(w.Name)
	if err != nil {
		return err
	}
	logger.Log(0, "got Wireguard device %s\n", w.Name)

	return wg.ConfigureDevice(w.Name, config)
}

// WGIface.GetListenPort - returns the listening port of the Wireguard endpoint
func (w *WGIface) GetListenPort() (*int, error) {
	logger.Log(0, "getting Wireguard listen port of interface %s", w.Name)

	//discover Wireguard current configuration
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wg.Close()

	d, err := wg.Device(w.Name)
	if err != nil {
		return nil, err
	}
	logger.Log(0, fmt.Sprintf("got Wireguard device listen port %s, %d", w.Name, d.ListenPort))

	return &d.ListenPort, nil
}

// GetPeers - gets all wg peers from the interface
func GetPeers(ifaceName string) ([]wgtypes.Peer, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return []wgtypes.Peer{}, err
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			logger.Log(0, "got error while closing wgctl: ", err.Error())
		}
	}()

	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		return []wgtypes.Peer{}, err
	}
	return wgDevice.Peers, nil
}

// GetPeer - gets the peerinfo from the wg interface
func GetPeer(ifaceName, peerPubKey string) (wgtypes.Peer, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return wgtypes.Peer{}, err
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			logger.Log(0, "got error while closing wgctl: ", err.Error())
		}
	}()
	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		return wgtypes.Peer{}, err
	}
	for _, peer := range wgDevice.Peers {
		if peer.PublicKey.String() == peerPubKey {
			return peer, nil
		}
	}
	return wgtypes.Peer{}, fmt.Errorf("peer not found")
}
