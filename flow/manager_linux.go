//go:build linux

package flow

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/flow/exporter"
	"github.com/gravitl/netclient/flow/tracker"
	pbflow "github.com/gravitl/netmaker/grpc/flow"
	"github.com/gravitl/netmaker/models"
	ct "github.com/ti-mo/conntrack"
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
	m.mu.Lock()
	m.participantIdentifiers = participantIdentifiers
	m.mu.Unlock()

	var err error
	m.startOnce.Do(func() {
		slog.Info("[flow] starting flow manager")

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
			func(flow *ct.Flow) bool {
				// filter out dns packet events.
				if flow.TupleOrig.Proto.Protocol == 17 &&
					(flow.TupleOrig.Proto.SourcePort == 53 ||
						flow.TupleOrig.Proto.DestinationPort == 53) {
					return true
				}

				// filter out icmp packet events.
				if flow.TupleOrig.Proto.Protocol == 1 || flow.TupleOrig.Proto.Protocol == 58 {
					return true
				}

				// filter out metrics events.
				if flow.TupleOrig.Proto.Protocol == 6 &&
					(flow.TupleOrig.Proto.SourcePort == uint16(config.GetServer(config.CurrServer).MetricsPort) ||
						flow.TupleOrig.Proto.DestinationPort == uint16(config.GetServer(config.CurrServer).MetricsPort)) {
					return true
				}

				return false
			},
			func(addr netip.Addr) *pbflow.FlowParticipant {
				ip := addr.String()
				ipCidr := netip.PrefixFrom(addr, addr.BitLen()).String()

				m.mu.RLock()
				identity, found := m.participantIdentifiers[ipCidr]
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
					Name: identity.Name,
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
		slog.Debug("[flow] error starting flow manager: " + err.Error())
	}

	return err
}

func (m *Manager) Stop() error {
	slog.Debug("[flow] stopping flow manager")

	if m.flowClient != nil {
		err := m.flowClient.Stop()
		if err != nil {
			slog.Debug("[flow] error stopping flow manager: " + err.Error())
			return err
		}
		m.flowClient = nil
	}

	if m.flowTracker != nil {
		err := m.flowTracker.Close()
		if err != nil {
			slog.Debug("[flow] error stopping flow manager: " + err.Error())
			return err
		}
		m.flowTracker = nil
	}

	// reset start once
	m.startOnce = sync.Once{}

	return nil
}
