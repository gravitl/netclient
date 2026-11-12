package wireguard

// setWindowsMTU applies a positive host MTU to the Windows adapter with the
// setter for the WireGuard implementation in use. It calls no Windows APIs,
// so its tests run on every platform.
func setWindowsMTU(mtu int, userspace bool, setUserspace, setWireGuardNT func()) {
	if mtu <= 0 {
		return
	}
	if userspace {
		setUserspace()
		return
	}
	setWireGuardNT()
}
