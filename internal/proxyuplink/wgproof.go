package proxyuplink

import (
	"fmt"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/proxy"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const helloTimestampSkew = 5 * time.Minute

// buildClientHello creates a ClientHello proven with this host's WireGuard private key
// against the gateway's WireGuard public key (X25519 DH + HMAC).
func buildClientHello(host *config.Config, opts Options) (proxy.ClientHello, error) {
	if host == nil {
		return proxy.ClientHello{}, fmt.Errorf("proxyuplink: host required for hello")
	}
	gwPubStr := PeerPubKeyForNode(opts.RelayPeerID)
	if gwPubStr == "" {
		return proxy.ClientHello{}, fmt.Errorf("proxyuplink: gateway WireGuard public key not found for relay %s", opts.RelayPeerID)
	}
	gwPub, err := wgtypes.ParseKey(gwPubStr)
	if err != nil {
		return proxy.ClientHello{}, fmt.Errorf("proxyuplink: parse gateway pubkey: %w", err)
	}

	var clientPriv, gwPubRaw [32]byte
	copy(clientPriv[:], host.PrivateKey[:])
	copy(gwPubRaw[:], gwPub[:])

	h := proxy.ClientHello{
		Version:     1,
		NodeID:      opts.NodeID,
		RelayPeerID: opts.RelayPeerID,
		NetworkID:   opts.NetworkID,
		PublicKey:   host.PublicKey.String(),
		Timestamp:   time.Now().Unix(),
	}
	proof, err := proxy.ComputeHelloProof(&clientPriv, &gwPubRaw, proxy.HelloMACInput(h))
	if err != nil {
		return proxy.ClientHello{}, err
	}
	h.Proof = proof
	return h, nil
}

// validateWGHelloProof verifies ClientHello using this gateway's WireGuard private key.
func validateWGHelloProof(hello proxy.ClientHello) error {
	if hello.NodeID == "" || hello.PublicKey == "" || hello.Proof == "" {
		return proxy.ErrAuthFailed
	}
	now := time.Now().Unix()
	if hello.Timestamp < now-int64(helloTimestampSkew.Seconds()) ||
		hello.Timestamp > now+int64(helloTimestampSkew.Seconds()) {
		return fmt.Errorf("%w: hello timestamp out of range", proxy.ErrAuthFailed)
	}

	clientPub, err := wgtypes.ParseKey(hello.PublicKey)
	if err != nil {
		return proxy.ErrAuthFailed
	}
	// Public key must match the node id we know from peer updates.
	if want := PeerPubKeyForNode(hello.NodeID); want != "" && want != hello.PublicKey {
		return fmt.Errorf("%w: public key does not match node_id", proxy.ErrAuthFailed)
	}
	// Must be a configured WireGuard peer on this host.
	foundPeer := false
	for _, p := range config.Netclient().HostPeers {
		if p.PublicKey == clientPub {
			foundPeer = true
			break
		}
	}
	if !foundPeer {
		return fmt.Errorf("%w: unknown WireGuard peer", proxy.ErrAuthFailed)
	}

	host := config.Netclient()
	if host == nil {
		return proxy.ErrAuthFailed
	}
	var gwPriv, clientPubRaw [32]byte
	copy(gwPriv[:], host.PrivateKey[:])
	copy(clientPubRaw[:], clientPub[:])
	if !proxy.VerifyHelloProof(&gwPriv, &clientPubRaw, hello) {
		return fmt.Errorf("%w: invalid wireguard hello proof", proxy.ErrAuthFailed)
	}
	return nil
}
