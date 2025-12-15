package cache

import "os/exec"

type systemdManager struct{}

func newSystemdManager() *systemdManager {
	return &systemdManager{}
}

func (m *systemdManager) Flush() error {
	return exec.Command("resolvectl", "flush-caches").Run()
}
