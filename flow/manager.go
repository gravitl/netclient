package flow

import (
	"context"
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
	peerIPIdentityMap map[string]models.PeerIdentity
	flowClient        *exporter.FlowGrpcClient
	flowTracker       *tracker.FlowTracker
	cancel            context.CancelFunc
	mu                sync.RWMutex
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

	// restart if already running.
	err := m.Stop()
	if err != nil {
		return err
	}

	peerInfo, err := networking.GetPeerInfo()
	if err != nil {
		return err
	}

	m.peerIPIdentityMap = peerInfo.PeerIPIdentityMap

	flowClient := exporter.NewFlowGrpcClient("")

	err = flowClient.Start()
	if err != nil {
		return err
	}

	m.flowClient = flowClient

	flowTracker, err := tracker.New(
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
			identity, ok := m.peerIPIdentityMap[ip]
			m.mu.RUnlock()
			if !ok {
				return &pbflow.FlowParticipant{
					Ip:   ip,
					Type: pbflow.ParticipantType_PARTICIPANT_EXTERNAL,
				}
			}

			participantType := pbflow.ParticipantType_PARTICIPANT_UNSPECIFIED
			if identity.Type == models.PeerType_Node {
				participantType = pbflow.ParticipantType_PARTICIPANT_NODE
			} else if identity.Type == models.PeerType_User {
				participantType = pbflow.ParticipantType_PARTICIPANT_USER
			} else if identity.Type == models.PeerType_WireGuard {
				participantType = pbflow.ParticipantType_PARTICIPANT_EXTCLIENT
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
		return err
	}

	m.flowTracker = flowTracker

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	go m.startRefreshLoop(ctx)
	return nil
}

func (m *Manager) Stop() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}

	if m.flowClient != nil {
		err := m.flowClient.Stop()
		if err != nil {
			return err
		}
		m.flowClient = nil
	}

	if m.flowTracker != nil {
		err := m.flowTracker.Close()
		if err != nil {
			return err
		}
		m.flowTracker = nil
	}

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
				m.mu.Lock()
				m.peerIPIdentityMap = peerInfo.PeerIPIdentityMap
				m.mu.Unlock()
			}

		}
	}
}
