package cache

import "os/exec"

type windowsManager struct{}

func NewManager() Manager {
	return &windowsManager{}
}

func (w *windowsManager) Flush() error {
	return exec.Command("ipconfig", "/flushdns").Run()
}
