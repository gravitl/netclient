package cache

import "os/exec"

type darwinManager struct{}

func NewManager() Manager {
	return &darwinManager{}
}

func (d *darwinManager) Flush() error {
	err := exec.Command("dscacheutil", "-flushcache").Run()
	if err != nil {
		return err
	}

	return exec.Command("killall", "-HUP", "mDNSResponder").Run()
}
