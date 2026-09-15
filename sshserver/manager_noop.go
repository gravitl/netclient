//go:build !linux

package sshserver

import "github.com/gravitl/netmaker/models"

type Manager struct{}

var manager = &Manager{}

// GetManager returns the package-level SSH server manager singleton.
func GetManager() *Manager {
	return manager
}

// Start is a no-op outside Linux.
func (m *Manager) Start(_ map[string]models.PeerIdentity, _ map[string]models.SSHAuthorizedIdentity) error {
	return nil
}

// Stop is a no-op outside Linux.
func (m *Manager) Stop() error {
	return nil
}
