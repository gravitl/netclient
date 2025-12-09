package flow

import (
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/flow/exporter"
	"github.com/gravitl/netclient/flow/tracker"
	pbflow "github.com/gravitl/netmaker/grpc/flow"
	"github.com/gravitl/netmaker/models"
)

const RefreshDuration = 10 * time.Minute

type Manager struct {
	participantIdentifiers map[string]models.PeerIdentity
	flowClient             *exporter.FlowGrpcClient
	flowTracker            *tracker.FlowTracker
	startOnce              sync.Once
	mu                     sync.RWMutex
}

var manager *Manager

func init() {
	manager = &Manager{}
}

func GetManager() *Manager {
	return manager
}

func (m *Manager) Start(participantIdentifiers map[string]models.PeerIdentity) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	m.mu.Lock()
	m.participantIdentifiers = participantIdentifiers
	m.mu.Unlock()

	var err error
	m.startOnce.Do(func() {
		fmt.Println("[flow] starting flow manager")

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
				identity, found := m.participantIdentifiers[ip]
				if !found {
					for addr := range m.participantIdentifiers {
						_, cidr, err := net.ParseCIDR(addr)
						if err != nil {
							continue
						}
						if cidr.Contains(net.ParseIP(ip)) {
							identity, found = m.participantIdentifiers[addr]
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
				case models.PeerType_EgressRoute:
					participantType = pbflow.ParticipantType_PARTICIPANT_EGRESS_ROUTE
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
