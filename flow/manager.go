//go:build !linux

package flow

import "github.com/gravitl/netmaker/models"

type NoopManager struct{}

var manager *NoopManager

func init() {
	manager = &NoopManager{}
}

func GetManager() *NoopManager {
	return manager
}

func (m *NoopManager) Start(_ map[string]models.PeerIdentity) error {
	return nil
}

func (m *NoopManager) Stop() error {
	return nil
}
