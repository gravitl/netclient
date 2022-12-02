package wg

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	DefaultMTU         = 1280
	DefaultWgPort      = 51820
	DefaultWgKeepAlive = 20 * time.Second
)

// WGIface represents a interface instance
type WGIface struct {
	Name   string
	Device *wgtypes.Device
	mu     sync.Mutex
}

// WGAddress Wireguard parsed address
type WGAddress struct {
	IP      net.IP
	Network *net.IPNet
}

// NewWGIFace Creates a new Wireguard interface instance
func NewWGIFace(iface string) (*WGIface, error) {
	wgIface := &WGIface{
		Name: iface,
		mu:   sync.Mutex{},
	}
	err := wgIface.GetWgIface(iface)
	if err != nil {
		return nil, err
	}
	return wgIface, nil
}

func (w *WGIface) GetWgIface(iface string) error {
	var err error
	wgClient, err := wgctrl.New()
	if err != nil {
		return err
	}
	w.Device, err = wgClient.Device(iface)
	if err != nil {
		return err
	}

	return nil
}

func GetWgIfacePubKey(iface string) [32]byte {
	wgClient, err := wgctrl.New()
	if err != nil {
		log.Println("Error fetching pub key: ", iface, err)
		return [32]byte{}
	}
	dev, err := wgClient.Device(iface)
	if err != nil {
		log.Println("Error fetching pub key: ", iface, err)
		return [32]byte{}
	}

	return dev.PublicKey
}

func GetWgIfacePrivKey(iface string) [32]byte {
	wgClient, err := wgctrl.New()
	if err != nil {
		log.Println("Error fetching pub key: ", iface, err)
		return [32]byte{}
	}
	dev, err := wgClient.Device(iface)
	if err != nil {
		log.Println("Error fetching pub key: ", iface, err)
		return [32]byte{}
	}
	return dev.PrivateKey
}

// parseAddress parse a string ("1.2.3.4/24") address to WG Address
func parseAddress(address string) (WGAddress, error) {
	ip, network, err := net.ParseCIDR(address)
	if err != nil {
		return WGAddress{}, err
	}
	return WGAddress{
		IP:      ip,
		Network: network,
	}, nil
}

// UpdatePeer updates existing Wireguard Peer or creates a new one if doesn't exist
func (w *WGIface) UpdatePeerEndpoint(peer wgtypes.PeerConfig) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Printf("updating interface %s peer %s: endpoint %s ", w.Name, peer.PublicKey.String(), peer.Endpoint.String())

	// //parse allowed ips
	// _, ipNet, err := net.ParseCIDR(allowedIps)
	// if err != nil {
	// 	return err
	// }

	peerN := wgtypes.PeerConfig{
		UpdateOnly: true,
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
	log.Printf("got Wireguard device %s\n", w.Name)

	return wg.ConfigureDevice(w.Name, config)
}

// GetListenPort returns the listening port of the Wireguard endpoint
func (w *WGIface) GetListenPort() (*int, error) {
	log.Printf("getting Wireguard listen port of interface %s", w.Name)

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
	log.Printf("got Wireguard device listen port %s, %d", w.Name, d.ListenPort)

	return &d.ListenPort, nil
}

// GetRealIface - retrieves tun iface based on reference iface name from config file
func GetRealIface(iface string) (string, error) {
	RunCmd("wg show interfaces", false)
	ifacePath := "/var/run/wireguard/" + iface + ".name"
	if !(FileExists(ifacePath)) {
		return "", errors.New(ifacePath + " does not exist")
	}
	realIfaceName, err := GetFileAsString(ifacePath)
	if err != nil {
		return "", err
	}
	realIfaceName = strings.TrimSpace(realIfaceName)
	if !(FileExists(fmt.Sprintf("/var/run/wireguard/%s.sock", realIfaceName))) {
		return "", errors.New("interface file does not exist")
	}
	return realIfaceName, nil
}

// FileExists - checks if file exists locally
func FileExists(f string) bool {
	info, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil && strings.Contains(err.Error(), "not a directory") {
		return false
	}
	if err != nil {
		log.Println(0, "error reading file: "+f+", "+err.Error())
	}
	return !info.IsDir()
}

// GetFileAsString - returns the string contents of a given file
func GetFileAsString(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), err
}

// RunCmd - runs a local command
func RunCmd(command string, printerr bool) (string, error) {
	args := strings.Fields(command)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Wait()
	out, err := cmd.CombinedOutput()
	if err != nil && printerr {
		log.Println("error running command: ", command)
		log.Println(strings.TrimSuffix(string(out), "\n"))
	}
	return string(out), err
}

// RemovePeer removes a Wireguard Peer from the interface iface
func (w *WGIface) RemovePeer(peerKey string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Printf("Removing peer %s from interface %s ", peerKey, w.Name)

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	peer := wgtypes.PeerConfig{
		PublicKey: peerKeyParsed,
		Remove:    true,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}
	err = w.configureDevice(config)
	if err != nil {
		return fmt.Errorf("received error \"%v\" while removing peer %s from interface %s", err, peerKey, w.Name)
	}
	return nil
}

// UpdatePeer
func (w *WGIface) Update(peerConf wgtypes.PeerConfig, updateOnly bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	log.Printf("---------> NEWWWWWW Updating peer %+v from interface %s ", peerConf, w.Name)

	peerConf.UpdateOnly = updateOnly
	peerConf.ReplaceAllowedIPs = true
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConf},
	}
	err = w.configureDevice(config)
	if err != nil {
		return fmt.Errorf("received error \"%v\" while Updating peer %s from interface %s", err, peerConf.PublicKey.String(), w.Name)
	}
	return nil
}

func GetPeer(ifaceName, peerPubKey string) (wgtypes.Peer, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return wgtypes.Peer{}, err
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			log.Printf("got error while closing wgctl: %v", err)
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
