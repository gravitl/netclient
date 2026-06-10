//go:build !linux

package wireguard

func listHostWireGuardInterfaces() []ReconcileEntry {
	return nil
}

func isWireGuardLink(link interface{}) bool {
	return false
}

func markNetclientOwnership(link interface{}) error {
	return nil
}

func deleteLinkByName(name, reason, caller string) error {
	return nil
}

func cachedKernelWireGuardPresent() bool {
	return false
}
