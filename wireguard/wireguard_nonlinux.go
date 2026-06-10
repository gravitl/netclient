//go:build !linux

package wireguard

// CreateWithReason creates the interface; non-linux builds delegate to Create.
func (n *NCIface) CreateWithReason(reason string) error {
	return n.Create()
}

// DeleteInterface removes the interface on non-linux platforms.
func (n *NCIface) DeleteInterface(reason string) error {
	n.Close()
	return nil
}
