package flow

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/flow/exporter"
	"github.com/gravitl/netclient/flow/tracker"
	"github.com/gravitl/netclient/networking"
	pbflow "github.com/gravitl/netmaker/grpc/flow"
	"github.com/gravitl/netmaker/models"
)

const RefreshDuration = 10 * time.Minute

type Manager struct {
	peerAddrIdentityMap map[string]models.PeerIdentity
	flowClient          *exporter.FlowGrpcClient
	flowTracker         *tracker.FlowTracker
	cancel              context.CancelFunc
	startOnce           sync.Once
	mu                  sync.RWMutex
}

var manager *Manager

func init() {
	manager = &Manager{}
}

func GetManager() *Manager {
	return manager
}

func (m *Manager) Start() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	var err error
	m.startOnce.Do(func() {
		fmt.Println("[flow] starting flow manager")
		var peerInfo models.HostPeerInfo
		peerInfo, err = networking.GetPeerInfo()
		if err != nil {
			return
		}

		m.peerAddrIdentityMap = peerInfo.PeerAddrIdentityMap

		for _, node := range config.GetNodes() {
			if node.Server == config.CurrServer {
				if node.Address.IP != nil {
					m.peerAddrIdentityMap[node.Address.String()] = models.PeerIdentity{
						ID:   node.ID.String(),
						Type: models.PeerType_Node,
					}
				}

				if node.Address6.IP != nil {
					m.peerAddrIdentityMap[node.Address6.String()] = models.PeerIdentity{
						ID:   node.ID.String(),
						Type: models.PeerType_Node,
					}
				}
			}
		}

		flowClient := exporter.NewFlowGrpcClient(
			config.GetServer(config.CurrServer).GRPC,
			exporter.WithTLS(&tls.Config{}),
		)

		err = flowClient.Start()
		if err != nil {
			return
		}

		m.flowClient = flowClient

		var flowTracker *tracker.FlowTracker
		flowTracker, err = tracker.New(
			func(f func(node *models.CommonNode) bool) {
				for _, node := range config.GetNodes() {
					if node.Server == config.CurrServer {
						if !f(&node.CommonNode) {
							return
						}
					}
				}
			},
			func(ip string) *pbflow.FlowParticipant {
				m.mu.RLock()
				var identity models.PeerIdentity
				var found bool
				_ip := net.ParseIP(ip)
				if _ip.To4() != nil {
					identity, found = m.peerAddrIdentityMap[fmt.Sprintf("%s/%d", ip, 32)]
				} else {
					identity, found = m.peerAddrIdentityMap[fmt.Sprintf("%s/%d", ip, 128)]
				}

				if !found {
					for addr := range m.peerAddrIdentityMap {
						_, cidr, err := net.ParseCIDR(addr)
						if err != nil {
							continue
						}
						if cidr.Contains(_ip) {
							identity = m.peerAddrIdentityMap[addr]
							found = true
							break
						}
					}
				}
				m.mu.RUnlock()
				if !found {
					return &pbflow.FlowParticipant{
						Ip:   ip,
						Type: pbflow.ParticipantType_PARTICIPANT_EXTERNAL,
					}
				}

				participantType := pbflow.ParticipantType_PARTICIPANT_UNSPECIFIED
				switch identity.Type {
				case models.PeerType_Node:
					participantType = pbflow.ParticipantType_PARTICIPANT_NODE
				case models.PeerType_User:
					participantType = pbflow.ParticipantType_PARTICIPANT_USER
				case models.PeerType_WireGuard:
					participantType = pbflow.ParticipantType_PARTICIPANT_EXTCLIENT
				case models.PeerType_EgressRange:
					participantType = pbflow.ParticipantType_PARTICIPANT_EGRESS_RANGE
				}

				return &pbflow.FlowParticipant{
					Ip:   ip,
					Type: participantType,
					Id:   identity.ID,
				}
			},
			flowClient,
		)
		if err != nil {
			return
		}

		m.flowTracker = flowTracker

		err = m.flowTracker.TrackConnections()
		if err != nil {
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		m.cancel = cancel

		go m.startRefreshLoop(ctx)
	})
	if err != nil {
		fmt.Println("[flow] error starting flow manager:", err)
	}

	return err
}

func (m *Manager) Stop() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	fmt.Println("[flow] stopping flow manager")
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}

	if m.flowClient != nil {
		err := m.flowClient.Stop()
		if err != nil {
			fmt.Println("[flow] error stopping flow manager:", err)
			return err
		}
		m.flowClient = nil
	}

	if m.flowTracker != nil {
		err := m.flowTracker.Close()
		if err != nil {
			fmt.Println("[flow] error stopping flow manager:", err)
			return err
		}
		m.flowTracker = nil
	}

	// reset start once
	m.startOnce = sync.Once{}

	return nil
}

func (m *Manager) startRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(RefreshDuration)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			peerInfo, err := networking.GetPeerInfo()
			if err == nil {
				for _, node := range config.GetNodes() {
					if node.Server == config.CurrServer {
						if node.Address.IP != nil {
							peerInfo.PeerAddrIdentityMap[node.Address.IP.String()] = models.PeerIdentity{
								ID:   node.ID.String(),
								Type: models.PeerType_Node,
							}
						}

						if node.Address6.IP != nil {
							peerInfo.PeerAddrIdentityMap[node.Address6.IP.String()] = models.PeerIdentity{
								ID:   node.ID.String(),
								Type: models.PeerType_Node,
							}
						}
					}
				}

				m.mu.Lock()
				m.peerAddrIdentityMap = peerInfo.PeerAddrIdentityMap
				m.mu.Unlock()
			}
		}
	}
}
