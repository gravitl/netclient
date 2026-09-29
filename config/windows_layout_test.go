package config

import "testing"

func TestWindowsShouldCopyState(t *testing.T) {
	keep := []string{
		"netclient.json",
		"nodes.json",
		"servers.json",
		"desired_connections.json",
		"netclient.yml",
		".uisession.json",
		".serverctx",
		"host.pem",
	}
	for _, name := range keep {
		if !WindowsShouldCopyState(name) {
			t.Errorf("expected to copy %s", name)
		}
	}
	drop := []string{"netclient.exe", "winsw.exe", "wintun.dll", "winsw.xml", "netclient.exe.tmp"}
	for _, name := range drop {
		if WindowsShouldCopyState(name) {
			t.Errorf("expected to skip %s", name)
		}
	}
}
