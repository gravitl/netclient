//go:build !linux && !darwin

package sshserver

import "github.com/gravitl/netmaker/models"

type Manager struct{}

var manager = &Manager{}

// GetManager returns the package-level SSH server manager singleton.
func GetManager() *Manager {
	return manager
}

// Start is a no-op on platforms without an embedded SSH server.
func (m *Manager) Start(_ map[string]models.PeerIdentity, _ map[string]models.SSHAuthorizedIdentity) error {
	return nil
}

// Stop is a no-op on platforms without an embedded SSH server.
func (m *Manager) Stop() error {
	return nil
}
