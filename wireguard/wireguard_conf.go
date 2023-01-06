package wireguard

import (
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
)

const (
	sectionInterface = "Interface" // indexes ini section of Interface in WG conf files
	sectionPeers     = "Peer"      // indexes ini section of Peer in WG conf files
)

// WgConfExists - checks if Netmaker WireGuard conf exists
func WgConfExists() bool {
	file := config.GetNetclientPath() + "netmaker.conf"
	_, err := os.Stat(file)
	return err == nil || !os.IsNotExist(err)
}

// UpdateWgInterface - updates the interface section of a wireguard config file
func UpdateWgInterface(node *config.Node, host *config.Config) error {
	file := config.GetNetclientPath() + "netmaker.conf"
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard, err := ini.LoadSources(options, file)
	if err != nil {
		return err
	}
	wireguard.DeleteSection(sectionInterface)
	wireguard.Section(sectionInterface).Key("PrivateKey").SetValue(host.PrivateKey.String())
	wireguard.Section(sectionInterface).Key("ListenPort").SetValue(strconv.Itoa(host.ListenPort))
	addrString := node.Address.String()
	if node.Address6.IP != nil {
		if addrString != "" {
			addrString += ","
		}
		addrString += node.Address6.String()
	}
	wireguard.Section(sectionInterface).Key("Address").SetValue(addrString)
	//if node.DNSOn == "yes" {
	//	wireguard.Section(section_interface).Key("DNS").SetValue(nameserver)
	//}
	//need to split postup/postdown because ini lib adds a quotes which breaks freebsd
	if node.PostUp != "" {
		parts := strings.Split(node.PostUp, " ; ")
		for i, part := range parts {
			if i == 0 {
				wireguard.Section(sectionInterface).Key("PostUp").SetValue(part)
			}
			wireguard.Section(sectionInterface).Key("PostUp").AddShadow(part)
		}
	}
	if node.PostDown != "" {
		parts := strings.Split(node.PostDown, " ; ")
		for i, part := range parts {
			if i == 0 {
				wireguard.Section(sectionInterface).Key("PostDown").SetValue(part)
			}
			wireguard.Section(sectionInterface).Key("PostDown").AddShadow(part)
		}
	}
	if host.MTU != 0 {
		wireguard.Section(sectionInterface).Key("MTU").SetValue(strconv.FormatInt(int64(host.MTU), 10))
	}
	if err := wireguard.SaveTo(file); err != nil {
		return err
	}
	return nil
}

// UpdateKeepAlive - updates the persistentkeepalive of all peers
func UpdateKeepAlive(keepalive int) error {
	file := config.GetNetclientPath() + "netmaker.conf"
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard, err := ini.LoadSources(options, file)
	if err != nil {
		return err
	}
	peers, err := wireguard.SectionsByName(sectionPeers)
	if err != nil {
		return err
	}
	newvalue := strconv.Itoa(keepalive)
	for i := range peers {
		wireguard.SectionWithIndex(sectionPeers, i).Key("PersistentKeepALive").SetValue(newvalue)
	}
	if err := wireguard.SaveTo(file); err != nil {
		return err
	}
	return nil
}

// UpdateWgPeers updates the peers section of wg conf file with a new set of peers
func UpdateWgPeers(peers []wgtypes.PeerConfig) (*net.UDPAddr, error) {

	var internetGateway *net.UDPAddr
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard, err := ini.LoadSources(options, config.GetNetclientPath()+"netmaker.conf")
	if err != nil {
		return internetGateway, err
	}
	//delete the peers sections as they are going to be replaced
	wireguard.DeleteSection(sectionPeers)
	for i, peer := range peers {
		wireguard.SectionWithIndex(sectionPeers, i).Key("PublicKey").SetValue(peer.PublicKey.String())
		if peer.PresharedKey != nil {
			wireguard.SectionWithIndex(sectionPeers, i).Key("PreSharedKey").SetValue(peer.PresharedKey.String())
		}
		if peer.AllowedIPs != nil {
			var allowedIPs string
			for i, ip := range peer.AllowedIPs {
				if i == 0 {
					allowedIPs = ip.String()
				} else {
					allowedIPs = allowedIPs + ", " + ip.String()
				}
			}
			wireguard.SectionWithIndex(sectionPeers, i).Key("AllowedIps").SetValue(allowedIPs)
			if strings.Contains(allowedIPs, "0.0.0.0/0") || strings.Contains(allowedIPs, "::/0") {
				internetGateway = peer.Endpoint
			}
		}
		if peer.Endpoint != nil {
			wireguard.SectionWithIndex(sectionPeers, i).Key("Endpoint").SetValue(peer.Endpoint.String())
		}
		if peer.PersistentKeepaliveInterval != nil && peer.PersistentKeepaliveInterval.Seconds() > 0 {
			wireguard.SectionWithIndex(sectionPeers, i).Key("PersistentKeepalive").SetValue(strconv.FormatInt((int64)(peer.PersistentKeepaliveInterval.Seconds()), 10))
		}
	}
	if err := wireguard.SaveTo(config.GetNetclientPath() + "netmaker.conf"); err != nil {
		return internetGateway, err
	}
	return internetGateway, nil
}

// UpdatePrivateKey - updates the private key of a wireguard config file
func UpdatePrivateKey(file, privateKey string) error {
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard, err := ini.LoadSources(options, file)
	if err != nil {
		return err
	}
	wireguard.Section(sectionInterface).Key("PrivateKey").SetValue(privateKey)
	if err := wireguard.SaveTo(file); err != nil {
		return err
	}
	return nil
}

// WriteWgConfig - creates a wireguard config file
func WriteWgConfig(host *config.Config, nodes config.NodeMap) error {
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard := ini.Empty(options)
	wireguard.Section(sectionInterface).Key("PrivateKey").SetValue(host.PrivateKey.String())
	wireguard.Section(sectionInterface).Key("ListenPort").SetValue(strconv.Itoa(host.ListenPort))
	for _, node := range nodes {
		if node.Address.IP != nil {
			wireguard.Section(sectionInterface).Key("Address").AddShadow(node.Address.String())
		}
		if node.Address6.IP != nil {
			wireguard.Section(sectionInterface).Key("Address").AddShadow(node.Address6.String())
		}
		// need to figure out DNS
		//if node.DNSOn == "yes" {
		//	wireguard.Section(section_interface).Key("DNS").SetValue(cfg.Server.CoreDNSAddr)
		//}
		//need to split postup/postdown because ini lib adds a ` and the ` breaks freebsd
		//works fine on others
		if node.PostUp != "" {
			if host.OS == "freebsd" {
				parts := strings.Split(node.PostUp, " ; ")
				for i, part := range parts {
					if i == 0 {
						wireguard.Section(sectionInterface).Key("PostUp").SetValue(part)
					}
					wireguard.Section(sectionInterface).Key("PostUp").AddShadow(part)
				}
			} else {
				wireguard.Section(sectionInterface).Key("PostUp").SetValue((node.PostUp))
			}
		}
		if node.PostDown != "" {
			if host.OS == "freebsd" {
				parts := strings.Split(node.PostDown, " ; ")
				for i, part := range parts {
					if i == 0 {
						wireguard.Section(sectionInterface).Key("PostDown").SetValue(part)
					}
					wireguard.Section(sectionInterface).Key("PostDown").AddShadow(part)
				}
			} else {
				wireguard.Section(sectionInterface).Key("PostDown").SetValue((node.PostDown))
			}
		}
	}
	if host.MTU != 0 {
		wireguard.Section(sectionInterface).Key("MTU").SetValue(strconv.FormatInt(int64(host.MTU), 10))
	}

	peers := config.GetHostPeerList()
	for i, peer := range peers {
		wireguard.SectionWithIndex(sectionPeers, i).Key("PublicKey").SetValue(peer.PublicKey.String())
		if peer.PresharedKey != nil {
			wireguard.SectionWithIndex(sectionPeers, i).Key("PreSharedKey").SetValue(peer.PresharedKey.String())
		}
		if peer.AllowedIPs != nil {
			var allowedIPs string
			for j, ip := range peer.AllowedIPs {
				if j == 0 {
					allowedIPs = ip.String()
				} else {
					allowedIPs = allowedIPs + ", " + ip.String()
				}
			}
			wireguard.SectionWithIndex(sectionPeers, i).Key("AllowedIps").SetValue(allowedIPs)
		}
		if peer.Endpoint != nil {
			wireguard.SectionWithIndex(sectionPeers, i).Key("Endpoint").SetValue(peer.Endpoint.String())
		}
		if peer.PersistentKeepaliveInterval != nil && peer.PersistentKeepaliveInterval.Seconds() > 0 {
			wireguard.SectionWithIndex(sectionPeers, i).Key("PersistentKeepalive").SetValue(strconv.FormatInt((int64)(peer.PersistentKeepaliveInterval.Seconds()), 10))
		}

	}

	if err := wireguard.SaveTo(config.GetNetclientPath() + "netmaker.conf"); err != nil {
		logger.Log(0, "failed to save wg conf file ", err.Error())
		return err
	}
	return nil
}

// AddAddress adds a nodes addresses (v4 and v6) to interface section of wg config file
func AddAddresses(node *config.Node) {
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard, err := ini.LoadSources(options, config.GetNetclientPath()+"netmaker.conf")
	if err != nil {
		logger.Log(0, "could not open the netmaker.conf wireguard file", err.Error())
		return
	}
	if node.Address.IP != nil {
		wireguard.Section(sectionInterface).Key("Address").AddShadow(node.Address.IP.String())
	}
	if node.Address6.IP != nil {
		wireguard.Section(sectionInterface).Key("Address").AddShadow(node.Address6.IP.String())
	}
	wireguard.SaveTo(config.GetNetclientPath() + "netmaker.conf")
}
