//go:build freebsd
// +build freebsd

package firewall

// newFirewall returns a no-op firewall manager on FreeBSD.
func newFirewall() (firewallController, error) {
	return noopFirewall{}, nil
}
