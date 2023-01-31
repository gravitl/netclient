package router

import (
	"net"

	"github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type peerInfo struct {
	peerKey  wgtypes.Key
	peerAddr net.IPNet
	Allow    bool
}

type ingressRoute struct {
	remotePeerKey    wgtypes.Key
	remoteClientAddr net.IPNet
	masquerade       bool
	peers            []peerInfo
}

func SetIngressRoutes(ingressUpdate []models.IngressInfo) error {
	r := ingressRoute{}
	// r = ingressRoute{
	// 	ingGWAddr: net.IPNet{
	// 		IP:   net.ParseIP("10.24.52.4"),
	// 		Mask: net.CIDRMask(32, 32),
	// 	},
	// 	remotePeerKey: wgtypes.Key{},
	// 	remoteClientAddr: net.IPNet{
	// 		IP:   net.ParseIP("10.24.52.252"),
	// 		Mask: net.CIDRMask(32, 32),
	// 	},
	// 	peers: []peerInfo{
	// 		{
	// 			peerAddr: net.IPNet{
	// 				IP:   net.ParseIP("10.24.52.1"),
	// 				Mask: net.CIDRMask(32, 32),
	// 			},
	// 			Allow: true,
	// 		},
	// 	},
	// }

	// set routing rules
	return fwCrtl.InsertIngressRoutingRules(r)

}
