//go:build !windows
// +build !windows

package firewall

// RefreshACLInterface is a no-op outside Windows (WFP ACL iface bind).
func RefreshACLInterface() {}
