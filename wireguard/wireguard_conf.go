package wireguard

import (
	"net"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
)

// UpdateWgInterface - updates the interface section of a wireguard config file
func UpdateWgInterface(file, nameserver string, node *config.Node) error {
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard, err := ini.LoadSources(options, file)
	if err != nil {
		return err
	}
	if node.UDPHolePunch {
		node.ListenPort = 0
	}
	wireguard.DeleteSection(sectionInterface)
	wireguard.Section(sectionInterface).Key("PrivateKey").SetValue(node.PrivateKey.String())
	wireguard.Section(sectionInterface).Key("ListenPort").SetValue(strconv.Itoa(node.ListenPort))
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
	if node.MTU != 0 {
		wireguard.Section(sectionInterface).Key("MTU").SetValue(strconv.FormatInt(int64(node.MTU), 10))
	}
	if err := wireguard.SaveTo(file); err != nil {
		return err
	}
	return nil
}

// UpdateKeepAlive - updates the persistentkeepalive of all peers
func UpdateKeepAlive(file string, keepalive int) error {
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

func UpdateWgPeers(file string, peers []wgtypes.PeerConfig) (*net.UDPAddr, error) {
	var internetGateway *net.UDPAddr
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard, err := ini.LoadSources(options, file)
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
	if err := wireguard.SaveTo(file); err != nil {
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
func WriteWgConfig(node *config.Node, peers []wgtypes.PeerConfig) error {
	options := ini.LoadOptions{
		AllowNonUniqueSections: true,
		AllowShadows:           true,
	}
	wireguard := ini.Empty(options)
	wireguard.Section(sectionInterface).Key("PrivateKey").SetValue(node.PrivateKey.String())
	if node.ListenPort > 0 && !node.UDPHolePunch {
		wireguard.Section(sectionInterface).Key("ListenPort").SetValue(strconv.Itoa(node.ListenPort))
	}
	addrString := node.Address.String()
	if node.Address6.IP != nil {
		if addrString != "" {
			addrString += ","
		}
		addrString += node.Address6.String()
	}
	wireguard.Section(sectionInterface).Key("Address").SetValue(addrString)
	// need to figure out DNS
	//if node.DNSOn == "yes" {
	//	wireguard.Section(section_interface).Key("DNS").SetValue(cfg.Server.CoreDNSAddr)
	//}
	//need to split postup/postdown because ini lib adds a ` and the ` breaks freebsd
	//works fine on others
	if node.PostUp != "" {
		if config.Netclient.OS == "freebsd" {
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
		if config.Netclient.OS == "freebsd" {
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
	if node.MTU != 0 {
		wireguard.Section(sectionInterface).Key("MTU").SetValue(strconv.FormatInt(int64(node.MTU), 10))
	}
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
		}
		if peer.Endpoint != nil {
			wireguard.SectionWithIndex(sectionPeers, i).Key("Endpoint").SetValue(peer.Endpoint.String())
		}

		if peer.PersistentKeepaliveInterval != nil && peer.PersistentKeepaliveInterval.Seconds() > 0 {
			wireguard.SectionWithIndex(sectionPeers, i).Key("PersistentKeepalive").SetValue(strconv.FormatInt((int64)(peer.PersistentKeepaliveInterval.Seconds()), 10))
		}
	}
	if err := wireguard.SaveTo(config.GetNetclientInterfacePath() + node.Interface + ".conf"); err != nil {
		return err
	}
	return nil
}
