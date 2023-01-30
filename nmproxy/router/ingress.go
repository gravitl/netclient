package router

import (
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type peerInfo struct {
	peerKey  wgtypes.Key
	peerAddr net.IPNet
	Allow    bool
}

type ingressRoute struct {
	ingGWAddr        net.IPNet
	remotePeerKey    wgtypes.Key
	remoteClientAddr net.IPNet
	masquerade       bool
	peers            []peerInfo
}

func SetIngressRoutes(r ingressRoute) {

	r = ingressRoute{
		ingGWAddr: net.IPNet{
			IP:   net.ParseIP("10.24.52.4"),
			Mask: net.CIDRMask(32, 32),
		},
		remotePeerKey: wgtypes.Key{},
		remoteClientAddr: net.IPNet{
			IP:   net.ParseIP("10.24.52.252"),
			Mask: net.CIDRMask(32, 32),
		},
		peers: []peerInfo{
			{
				peerAddr: net.IPNet{
					IP:   net.ParseIP("10.24.52.1"),
					Mask: net.CIDRMask(32, 32),
				},
				Allow: true,
			},
		},
	}

	// set routing rules
	fwCrtl.InsertIngressRoutingRules(r)

}
