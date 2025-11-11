package cache

import "os/exec"

type windowsManager struct{}

func NewManager() Manager {
	return &windowsManager{}
}

func (w *windowsManager) Flush() error {
	return exec.Command("C:\\Windows\\System32\\ipconfig.exe", "/flushdns").Run()
}
