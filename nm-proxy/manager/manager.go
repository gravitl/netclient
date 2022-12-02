package manager

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"

	"github.com/gravitl/netclient/nm-proxy/common"
	"github.com/gravitl/netclient/nm-proxy/models"
	peerpkg "github.com/gravitl/netclient/nm-proxy/peer"
	"github.com/gravitl/netclient/nm-proxy/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

/*
TODO:-
 1. ON Ingress node
    --> for attached ext clients
    -> start sniffer (will recieve pkts from ext clients (add ebf filter to listen on only ext traffic) if not intended to the interface forward it.)
    -> start remote conn after endpoint is updated
    -->
*/
var sent bool

type ProxyAction string

type ProxyManagerPayload struct {
	InterfaceName   string                 `json:"interface_name"`
	Network         string                 `json:"network"`
	WgAddr          string                 `json:"wg_addr"`
	Peers           []wgtypes.PeerConfig   `json:"peers"`
	PeerMap         map[string]PeerConf    `json:"peer_map"`
	IsRelayed       bool                   `json:"is_relayed"`
	IsIngress       bool                   `json:"is_ingress"`
	RelayedTo       *net.UDPAddr           `json:"relayed_to"`
	IsRelay         bool                   `json:"is_relay"`
	RelayedPeerConf map[string]RelayedConf `json:"relayed_conf"`
}

type RelayedConf struct {
	RelayedPeerEndpoint *net.UDPAddr         `json:"relayed_peer_endpoint"`
	RelayedPeerPubKey   string               `json:"relayed_peer_pub_key"`
	Peers               []wgtypes.PeerConfig `json:"relayed_peers"`
}

type PeerConf struct {
	IsExtClient            bool         `json:"is_ext_client"`
	Address                string       `json:"address"`
	IsAttachedExtClient    bool         `json:"is_attached_ext_client"`
	IngressGatewayEndPoint *net.UDPAddr `json:"ingress_gateway_endpoint"`
	IsRelayed              bool         `json:"is_relayed"`
	RelayedTo              *net.UDPAddr `json:"relayed_to"`
	Proxy                  bool         `json:"proxy"`
}

const (
	AddInterface    ProxyAction = "ADD_INTERFACE"
	DeleteInterface ProxyAction = "DELETE_INTERFACE"
)

func StartProxyManager(ctx context.Context, manageChan chan *ProxyManagerPayload) {
	for {

		select {
		case <-ctx.Done():
			log.Println("shutting down proxy manager...")
			return
		case mI := <-manageChan:
			log.Printf("-------> PROXY-MANAGER: %+v\n", mI)
			mI.SetIngressGateway()
			err := mI.AddInterfaceToProxy()
			if err != nil {
				log.Printf("failed to add interface: [%s] to proxy: %v\n  ", mI.InterfaceName, err)
			}

		}
	}
}

func (m *ProxyManagerPayload) RelayUpdate() {
	common.IsRelay = m.IsRelay
}

func (m *ProxyManagerPayload) SetIngressGateway() {
	common.IsIngressGateway = m.IsIngress
}

func (m *ProxyManagerPayload) RelayPeers() {
	common.IsRelay = true
	for relayedNodePubKey, relayedNodeConf := range m.RelayedPeerConf {
		relayedNodePubKeyHash := fmt.Sprintf("%x", md5.Sum([]byte(relayedNodePubKey)))
		if _, ok := common.RelayPeerMap[relayedNodePubKeyHash]; !ok {
			common.RelayPeerMap[relayedNodePubKeyHash] = make(map[string]models.RemotePeer)
		}
		for _, peer := range relayedNodeConf.Peers {
			if peer.Endpoint != nil {
				peer.Endpoint.Port = models.NmProxyPort
				remotePeerKeyHash := fmt.Sprintf("%x", md5.Sum([]byte(peer.PublicKey.String())))
				common.RelayPeerMap[relayedNodePubKeyHash][remotePeerKeyHash] = models.RemotePeer{
					Endpoint: peer.Endpoint,
				}
			}

		}
		relayedNodeConf.RelayedPeerEndpoint.Port = models.NmProxyPort
		common.RelayPeerMap[relayedNodePubKeyHash][relayedNodePubKeyHash] = models.RemotePeer{
			Endpoint: relayedNodeConf.RelayedPeerEndpoint,
		}

	}
}

func cleanUpInterface(network string) {
	log.Println("########------------>  CLEANING UP: ", common.WgIfaceMap.Iface.Name)
	if peerMap, ok := common.WgIfaceMap.NetworkPeerMap[network]; ok {
		for _, peerI := range peerMap {
			peerI.Mutex.Lock()
			peerI.StopConn()
			peerI.Mutex.Unlock()

		}
		delete(common.WgIfaceMap.NetworkPeerMap, network)
	}

}

func (m *ProxyManagerPayload) processPayload() (*wg.WGIface, error) {
	var err error
	var wgIface *wg.WGIface
	if m.InterfaceName == "" {
		return nil, errors.New("interface cannot be empty")
	}
	if m.Network == "" {
		return nil, errors.New("network name cannot be empty")
	}
	if len(m.Peers) == 0 {
		return nil, errors.New("no peers to add")
	}

	if runtime.GOOS == "darwin" {
		m.InterfaceName, err = wg.GetRealIface(m.InterfaceName)
		if err != nil {
			log.Println("failed to get real iface: ", err)
		}
	}
	common.InterfaceName = m.InterfaceName
	wgIface, err = wg.NewWGIFace(m.InterfaceName)
	if err != nil {
		log.Println("Failed init new interface: ", err)
		return nil, err
	}
	if common.WgIfaceMap.Iface == nil {
		common.WgIfaceMap.Iface = wgIface.Device
		common.WgIfaceMap.IfaceKeyHash = fmt.Sprintf("%x", md5.Sum([]byte(wgIface.Device.PublicKey.String())))
	}

	var peerConnMap models.PeerConnMap
	var found bool
	if peerConnMap, found = common.WgIfaceMap.NetworkPeerMap[m.Network]; !found {

		return wgIface, nil
	}
	if m.IsRelay {
		m.RelayPeers()
	}
	common.IsRelay = m.IsRelay
	// check if node is getting relayed
	if common.IsRelayed != m.IsRelayed {
		common.IsRelayed = m.IsRelayed
		cleanUpInterface(m.Network)
		return wgIface, nil
	}

	// sync map with wg device config
	// check if listen port has changed
	if wgIface.Device.ListenPort != common.WgIfaceMap.Iface.ListenPort {
		// reset proxy for this interface
		cleanUpInterface(m.Network)
		return wgIface, nil
	}
	// check device conf different from proxy
	common.WgIfaceMap.Iface = wgIface.Device
	// sync peer map with new update
	for peerPubKey, peerConn := range peerConnMap {
		if _, ok := m.PeerMap[peerPubKey]; !ok {
			peerConn.Mutex.Lock()
			if peerConn.IsAttachedExtClient {
				log.Println("------> Deleting ExtClient Watch Thread: ", peerConn.Key.String())
				if val, ok := common.ExtClientsWaitTh[peerConn.Key.String()]; ok {
					val.CancelFunc()
					delete(common.ExtClientsWaitTh, peerConn.Key.String())
				}
				log.Println("-----> Deleting Ext Client from Src Ip Map: ", peerConn.Key.String())
				delete(common.ExtSourceIpMap, peerConn.Config.PeerConf.Endpoint.String())
			}
			peerConn.StopConn()
			peerConn.Mutex.Unlock()
			delete(common.PeerKeyHashMap, fmt.Sprintf("%x", md5.Sum([]byte(peerConn.Key.String()))))
			delete(peerConnMap, peerConn.Key.String())
			continue
		}
	}
	for i := len(m.Peers) - 1; i >= 0; i-- {

		if currentPeer, ok := peerConnMap[m.Peers[i].PublicKey.String()]; ok {
			currentPeer.Mutex.Lock()
			if currentPeer.IsAttachedExtClient {
				m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
				currentPeer.Mutex.Unlock()
				continue
			}
			// check if proxy is off for the peer
			if !m.PeerMap[m.Peers[i].PublicKey.String()].Proxy {

				// cleanup proxy connections for the peer
				currentPeer.StopConn()
				delete(peerConnMap, currentPeer.Key.String())
				// update the peer with actual endpoint
				if err := wgIface.Update(m.Peers[i], false); err != nil {
					log.Println("falied to update peer: ", err)
				}
				m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
				currentPeer.Mutex.Unlock()
				continue

			}
			// check if peer is not connected to proxy
			devPeer, err := wg.GetPeer(m.InterfaceName, currentPeer.Key.String())
			if err == nil {
				log.Printf("---------> COMAPRING ENDPOINT: DEV: %s, Proxy: %s", devPeer.Endpoint.String(), currentPeer.Config.LocalConnAddr.String())
				if devPeer.Endpoint.String() != currentPeer.Config.LocalConnAddr.String() {
					log.Println("---------> endpoint is not set to proxy: ", currentPeer.Key)
					currentPeer.StopConn()
					currentPeer.Mutex.Unlock()
					delete(peerConnMap, currentPeer.Key.String())
					continue
				}
			}
			//check if peer is being relayed
			if currentPeer.IsRelayed != m.PeerMap[m.Peers[i].PublicKey.String()].IsRelayed {
				log.Println("---------> peer relay status has been changed: ", currentPeer.Key)
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue
			}
			// check if relay endpoint has been changed
			if currentPeer.RelayedEndpoint != nil &&
				m.PeerMap[m.Peers[i].PublicKey.String()].RelayedTo != nil &&
				currentPeer.RelayedEndpoint.String() != m.PeerMap[m.Peers[i].PublicKey.String()].RelayedTo.String() {
				log.Println("---------> peer relay endpoint has been changed: ", currentPeer.Key)
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue
			}

			if currentPeer.Config.RemoteConnAddr.IP.String() != m.Peers[i].Endpoint.IP.String() {
				log.Println("----------> Resetting proxy for Peer: ", currentPeer.Key, m.InterfaceName)
				currentPeer.StopConn()
				currentPeer.Mutex.Unlock()
				delete(peerConnMap, currentPeer.Key.String())
				continue

			} else {
				// delete the peer from the list
				log.Println("-----------> No updates observed so deleting peer: ", m.Peers[i].PublicKey)
				m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
			}
			currentPeer.Mutex.Unlock()

		} else if !m.PeerMap[m.Peers[i].PublicKey.String()].Proxy && !m.PeerMap[m.Peers[i].PublicKey.String()].IsAttachedExtClient {
			log.Println("-----------> skipping peer, proxy is off: ", m.Peers[i].PublicKey)
			if err := wgIface.Update(m.Peers[i], false); err != nil {
				log.Println("falied to update peer: ", err)
			}
			m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
		}
	}

	common.WgIfaceMap.NetworkPeerMap[m.Network] = peerConnMap
	log.Println("CLEANED UP..........")
	return wgIface, nil
}

func (m *ProxyManagerPayload) AddInterfaceToProxy() error {
	var err error

	wgInterface, err := m.processPayload()
	if err != nil {
		return err
	}

	log.Printf("wg: %+v\n", wgInterface)
	for i, peerI := range m.Peers {
		if !m.PeerMap[m.Peers[i].PublicKey.String()].Proxy {
			continue
		}
		peerConf := m.PeerMap[peerI.PublicKey.String()]
		if peerI.Endpoint == nil && !(peerConf.IsAttachedExtClient || peerConf.IsExtClient) {
			log.Println("Endpoint nil for peer: ", peerI.PublicKey.String())
			continue
		}

		if peerConf.IsExtClient && !peerConf.IsAttachedExtClient {
			peerI.Endpoint = peerConf.IngressGatewayEndPoint
		}

		var isRelayed bool
		var relayedTo *net.UDPAddr
		if m.IsRelayed {
			isRelayed = true
			relayedTo = m.RelayedTo
		} else {

			isRelayed = peerConf.IsRelayed
			relayedTo = peerConf.RelayedTo

		}
		if peerConf.IsAttachedExtClient {
			log.Println("Extclient Thread...")
			go func(wgInterface *wg.WGIface, peer *wgtypes.PeerConfig,
				isRelayed bool, relayTo *net.UDPAddr, peerConf PeerConf) {
				addExtClient := false
				commChan := make(chan *net.UDPAddr, 30)
				ctx, cancel := context.WithCancel(context.Background())
				common.ExtClientsWaitTh[peerI.PublicKey.String()] = models.ExtClientPeer{
					CancelFunc: cancel,
					CommChan:   commChan,
				}
				defer func() {
					if addExtClient {
						log.Println("GOT ENDPOINT for Extclient adding peer...")

						common.ExtSourceIpMap[peer.Endpoint.String()] = models.RemotePeer{
							Interface:           wgInterface.Name,
							PeerKey:             peer.PublicKey.String(),
							IsExtClient:         peerConf.IsExtClient,
							IsAttachedExtClient: peerConf.IsAttachedExtClient,
							Endpoint:            peer.Endpoint,
						}

						peerpkg.AddNewPeer(wgInterface, m.Network, peer, peerConf.Address, isRelayed,
							peerConf.IsExtClient, peerConf.IsAttachedExtClient, relayedTo)

					}
					log.Println("Exiting extclient watch Thread for: ", peer.PublicKey.String())
				}()
				for {
					select {
					case <-ctx.Done():
						return
					case endpoint := <-commChan:
						if endpoint != nil {
							addExtClient = true
							peer.Endpoint = endpoint
							delete(common.ExtClientsWaitTh, peer.PublicKey.String())
							return
						}
					}

				}

			}(wgInterface, &peerI, isRelayed, relayedTo, peerConf)
			continue
		}

		peerpkg.AddNewPeer(wgInterface, m.Network, &peerI, peerConf.Address, isRelayed,
			peerConf.IsExtClient, peerConf.IsAttachedExtClient, relayedTo)

	}
	return nil
}
