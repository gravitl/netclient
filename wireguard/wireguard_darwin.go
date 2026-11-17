package wireguard

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// internetGwPeerEndpoint resolves the exit peer's underlay UDP endpoint from
// HostPeers / better-endpoint cache when the live device peer is not ready yet.
func internetGwPeerEndpoint(publicKey string) *net.UDPAddr {
	if pk, err := wgtypes.ParseKey(publicKey); err == nil {
		if host := config.Netclient(); host != nil {
			for _, p := range host.HostPeers {
				if p.PublicKey == pk && p.Endpoint != nil && p.Endpoint.IP != nil {
					return p.Endpoint
				}
			}
		}
	}
	if peer, err := GetPeer(ncutils.GetInterfaceName(), publicKey); err == nil && peer.Endpoint != nil {
		return peer.Endpoint
	}
	if ep, ok := GetBetterEndpoint(publicKey); ok && ep != nil {
		return ep
	}
	return nil
}

// NCIface.Create - makes a new Wireguard interface for darwin users (userspace)
func (nc *NCIface) Create() error {
	err := nc.createUserSpaceWG()
	if err != nil {
		return err
	}

	if !nc.IsTestIface {
		cmd := exec.Command("ifconfig", "lo0", "alias", "127.51.8.21")
		out, err := cmd.CombinedOutput()
		if err != nil {
			slog.Error("failed to add address for dns server", "command", cmd.String(), "error", string(out))
			return err
		}
	}

	return nil
}

// NCIface.ApplyAddrs syncs overlay node addresses to the connected set.
// Diff-based (remove stale, add missing) — closer to develop's add-only path
// and avoids wiping every address (which can drop exit half-defaults 0.0.0.0/1).
// Exit routing stays in SetInternetGw / RestoreInternetGw only.
func (nc *NCIface) ApplyAddrs() error {
	want := make(map[string]struct{}, len(nc.Addresses))
	for _, address := range nc.Addresses {
		if address.IP != nil {
			want[address.IP.String()] = struct{}{}
		}
	}
	if iface, err := net.InterfaceByName(nc.Name); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				ipnet, ok := a.(*net.IPNet)
				if !ok || ipnet.IP == nil || !ipnet.IP.IsGlobalUnicast() {
					continue
				}
				if _, keep := want[ipnet.IP.String()]; keep {
					continue
				}
				removeDarwinNodeAddr(nc.Name, ipnet.IP, networkRangeForNodeIP(ipnet.IP))
			}
		}
	}
	for _, address := range nc.Addresses {
		addDarwinNodeAddr(nc.Name, address)
	}
	return nil
}

func networkRangeForNodeIP(ip net.IP) net.IPNet {
	for _, node := range config.GetNodes() {
		if node.Address.IP != nil && node.Address.IP.Equal(ip) {
			return node.NetworkRange
		}
		if node.Address6.IP != nil && node.Address6.IP.Equal(ip) {
			return node.NetworkRange6
		}
	}
	return net.IPNet{}
}

func removeDarwinNodeAddr(iface string, ip net.IP, network net.IPNet) {
	if ip == nil {
		return
	}
	if ip.To4() != nil {
		if network.IP != nil {
			darwinDeleteNetRoute("-inet", network.String(), iface, ip)
		}
		cmd := exec.Command("ifconfig", iface, "inet", ip.String(), "delete")
		if out, err := cmd.CombinedOutput(); err != nil && !darwinAddrGone(out) {
			slog.Warn("failed to delete iface address", "command", cmd.String(), "error", string(out))
		}
		return
	}
	if network.IP != nil {
		darwinDeleteNetRoute("-inet6", network.String(), iface, ip)
	}
	cmd := exec.Command("ifconfig", iface, "inet6", ip.String(), "-alias")
	if out, err := cmd.CombinedOutput(); err != nil && !darwinAddrGone(out) {
		slog.Warn("failed to delete iface address", "command", cmd.String(), "error", string(out))
	}
}

func addDarwinNodeAddr(iface string, address ifaceAddress) {
	if address.IP == nil {
		return
	}
	if address.IP.To4() != nil {
		cmd := exec.Command("ifconfig", iface, "inet", "add", address.IP.String(), address.IP.String())
		if out, err := cmd.CombinedOutput(); err != nil && !darwinAddrExists(out) {
			slog.Error("error adding address", "command", cmd.String(), "error", string(out))
		}
		if address.Network.IP != nil {
			// Pin to utun + bind -ifa to this network's node IP so multi-net
			// does not pick another utun address as src (e.g. test IP for
			// netmaker destinations).
			darwinAddNetRoute("-inet", address.Network.String(), iface, address.IP)
		}
		return
	}
	cmd := exec.Command("ifconfig", iface, "inet6", address.IP.String(), "prefixlen", "64", "alias")
	if out, err := cmd.CombinedOutput(); err != nil && !darwinAddrExists(out) {
		slog.Error("error adding address", "command", cmd.String(), "error", string(out))
	}
	if address.Network.IP != nil {
		darwinAddNetRoute("-inet6", address.Network.String(), iface, address.IP)
	}
}

// darwinAddNetRoute installs a prefix on the WireGuard iface. src (when set)
// is passed as -ifa so Darwin uses that overlay address as the packet source
// under multi-net; without it macOS may pick any utun address. Also clears
// legacy via-IP / unscoped iface routes that may sit on en0 or lack -ifa.
func darwinAddNetRoute(family, network, iface string, src net.IP) {
	darwinDeleteNetRoute(family, network, iface, src)
	args := []string{"add", "-net", family, network}
	if src != nil {
		args = append(args, "-ifa", src.String())
	}
	args = append(args, "-interface", iface)
	cmd := exec.Command("route", args...)
	if out, err := cmd.CombinedOutput(); err != nil && !routeAlreadyExists(out) {
		slog.Error("failed to add route", "command", cmd.String(), "error", string(out))
	}
}

// darwinDeleteNetRoute removes iface-pinned routes (with and without -ifa) and
// any legacy via-nexthop entry (pre-fix routes that may sit on en0).
func darwinDeleteNetRoute(family, network, iface string, src net.IP) {
	if src != nil {
		cmd := exec.Command("route", "delete", "-net", family, network, "-ifa", src.String(), "-interface", iface)
		if out, err := cmd.CombinedOutput(); err != nil && !darwinRouteGone(out) {
			slog.Debug("ifa overlay route delete", "command", cmd.String(), "output", string(out))
		}
	}
	cmd := exec.Command("route", "delete", "-net", family, network, "-interface", iface)
	if out, err := cmd.CombinedOutput(); err != nil && !darwinRouteGone(out) {
		slog.Debug("overlay route delete", "command", cmd.String(), "output", string(out))
	}
	if src == nil {
		return
	}
	cmd = exec.Command("route", "delete", "-net", family, network, src.String())
	if out, err := cmd.CombinedOutput(); err != nil && !darwinRouteGone(out) {
		slog.Debug("legacy via-route delete", "command", cmd.String(), "output", string(out))
	}
}

func darwinAddrExists(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "file exists") || strings.Contains(s, "already exists")
}

func darwinAddrGone(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "not found") ||
		strings.Contains(s, "no such") ||
		strings.Contains(s, "can't find")
}

func darwinRouteGone(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "not in table") ||
		strings.Contains(s, "no such") ||
		strings.Contains(s, "not found")
}

// RemoveRoutes removes egress routes. Always pins delete to the WireGuard iface
// and also clears any legacy via-nexthop entry that may have landed on en0.
func RemoveRoutes(addrs []ifaceAddress) {
	iface := ncutils.GetInterfaceName()
	for _, addr := range addrs {
		if addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network {
			continue
		}
		family := "-inet6"
		if addr.Network.IP.To4() != nil {
			family = "-inet"
		}
		darwinDeleteNetRoute(family, addr.Network.String(), iface, addr.IP)
	}
}

// SetRoutes - sets additional routes to the interface
func SetRoutes(addrs []ifaceAddress) error {
	iface := ncutils.GetInterfaceName()
	for _, addr := range addrs {
		if (len(config.GetNodes()) > 1 && addr.IP == nil) || addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network || (len(config.GetNodes()) > 1 && addr.GwIP == nil) {
			continue
		}
		if addr.Network.IP == nil {
			continue
		}
		family := "-inet6"
		if addr.Network.IP.To4() != nil {
			family = "-inet"
		}
		// -interface <utun> + -ifa <NodeAddr> when known (multi-net egress).
		darwinAddNetRoute(family, addr.Network.String(), iface, addr.IP)
	}
	return nil
}

func routeAlreadyExists(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "file exists") || strings.Contains(s, "already in table")
}

func (nc *NCIface) SetMTU() error {
	// set MTU for the interface
	cmd := exec.Command("ifconfig", nc.Name, "mtu", fmt.Sprint(nc.MTU), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Log(0, fmt.Sprintf("failed to set mtu with command %s - %v", cmd.String(), out))
		return err
	}
	return nil
}

func (nc *NCIface) Close() {
	// Must call closeUserspaceWg (own lock) — do not hold wgMutex across it.
	// Skipping it leaves a stale Device/relayBind after SIGHUP (disconnect/connect).
	if UserspaceWGActive() {
		_ = nc.closeUserspaceWg()
	} else {
		wgMutex.Lock()
		if nc.Iface != nil {
			if err := nc.Iface.Close(); err != nil {
				slog.Debug("error closing netclient interface", "error", err)
			}
		}
		wgMutex.Unlock()
	}

	sockPath := "/var/run/wireguard/" + nc.Name + ".sock"
	if _, statErr := os.Stat(sockPath); statErr == nil {
		_ = os.Remove(sockPath)
	}

	if !nc.IsTestIface {
		cmd := exec.Command("ifconfig", "lo0", "-alias", "127.51.8.21")
		out, err := cmd.CombinedOutput()
		if err != nil {
			slog.Error("failed to remove address for dns server", "command", cmd.String(), "error", string(out))
		}
	}
}

// DeleteOldInterface - removes named interface
func DeleteOldInterface(iface string) {
	logger.Log(3, "deleting interface", iface)
	conf := "/Applications/Netclient/config/" + iface + ".conf"
	if _, err := ncutils.RunCmd("wg-quick down "+conf, true); err != nil {
		slog.Error("remove wireguard tunnel", "interface", iface, "error", err)
	}
}

// GetDefaultGatewayIp - get current default gateway
func GetDefaultGatewayIp() (ip net.IP, err error) {
	// IPv4 Check
	gwDef, errDef := getRouteGateway("default")
	gwHalf1, err1 := getRouteGateway("0.0.0.1")
	gwHalf2, err2 := getRouteGateway("128.0.0.1")

	if err1 == nil && err2 == nil && gwHalf1.Equal(gwHalf2) {
		if errDef != nil || !gwHalf1.Equal(gwDef) {
			return gwHalf1, nil
		}
	}

	// On darwin, IGW sets interface-based split routes (route add -net -inet 0.0.0.0/1 -interface <iface>)
	// which have no gateway: line in `route -n get` output. Detect this by checking if both
	// half-routes go through the netclient WireGuard interface, and return CurrGwNmIP if so.
	if err1 != nil || err2 != nil {
		ncIface := ncutils.GetInterfaceName()
		iface1, errIf1 := getRouteInterface("0.0.0.1")
		iface2, errIf2 := getRouteInterface("128.0.0.1")
		if errIf1 == nil && errIf2 == nil && iface1 == ncIface && iface2 == ncIface {
			if gwNmIP := config.Netclient().CurrGwNmIP; gwNmIP != nil {
				return gwNmIP, nil
			}
		}
	}

	// IPv6 Check
	gwHalf6_1, err6_1 := getRouteGateway("2000::1")
	gwHalf6_2, err6_2 := getRouteGateway("8000::1")
	if err6_1 == nil && err6_2 == nil && gwHalf6_1.Equal(gwHalf6_2) {
		gwDef6, errDef6 := getRouteGateway("-inet6", "default")
		if errDef6 != nil || !gwHalf6_1.Equal(gwDef6) {
			return gwHalf6_1, nil
		}
	}

	// Same interface-based route check for IPv6
	if err6_1 != nil || err6_2 != nil {
		ncIface := ncutils.GetInterfaceName()
		iface1, errIf1 := getRouteInterface("2000::1")
		iface2, errIf2 := getRouteInterface("8000::1")
		if errIf1 == nil && errIf2 == nil && iface1 == ncIface && iface2 == ncIface {
			if gwNmIP := config.Netclient().CurrGwNmIP; gwNmIP != nil {
				return gwNmIP, nil
			}
		}
	}

	if errDef == nil {
		return gwDef, nil
	}
	return nil, fmt.Errorf("default gateway not found")
}

// GetDefaultGatewayIp6 - get current default gateway IPv6 address
func GetDefaultGatewayIp6() (ip net.IP, err error) {
	return getRouteGateway("-inet6", "default")
}

func getRouteGateway(args ...string) (ip net.IP, err error) {
	fullArgs := append([]string{"-n", "get"}, args...)
	cmd := exec.Command("route", fullArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip = net.ParseIP(parts[1])
				if ip != nil {
					return ip, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("gateway not found for %v", args)
}

// getRouteInterface extracts the interface name from `route -n get` output.
// This is needed on darwin because interface-based routes (e.g. added via
// `route add -net -inet 0.0.0.0/1 -interface utunX`) do not have a gateway:
// line, only an interface: line.
func getRouteInterface(args ...string) (string, error) {
	fullArgs := append([]string{"-n", "get"}, args...)
	cmd := exec.Command("route", fullArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}
	return "", fmt.Errorf("interface not found for %v", args)
}

// RestoreInternetGw - restore the old default gateway
func RestoreInternetGw() (err error) {
	err = resetDefaultRoutesOnHost()
	if err == nil {
		GetIGWMonitor().Stop()
	}
	return err
}

func resetDefaultRoutesOnHost() error {
	iface := ncutils.GetInterfaceName()
	exec.Command("route", "delete", "-net", "-inet", "0.0.0.0/1", "-interface", iface).Run()
	exec.Command("route", "delete", "-net", "-inet", "128.0.0.0/1", "-interface", iface).Run()
	exec.Command("route", "delete", "-net", "-inet6", ipv6HalfDefaultLow, "-interface", iface).Run()
	exec.Command("route", "delete", "-net", "-inet6", ipv6HalfDefaultHigh, "-interface", iface).Run()

	removeUnderlayPins(false, darwinPinOps)
	removeUnderlayPins(true, darwinPinOps)
	config.Netclient().CurrGwNmIP = nil
	config.Netclient().CurrGwNmIP6 = nil
	config.Netclient().OriginalDefaultGatewayIp = nil
	config.Netclient().OriginalDefaultGatewayIp6 = nil
	return config.WriteNetclientConfig()
}

// SetInternetGw - set a new default gateway.
// Installs IPv4 and/or IPv6 OS default routes when the corresponding nexthop is present.
func SetInternetGw(publicKey string, gw4, gw6 net.IP) (err error) {
	if IsZeroWGPublicKey(publicKey) {
		return fmt.Errorf("internet gateway peer public key is empty")
	}
	// Resolve+pin API/broker on LAN before 0.0.0.0/0 moves onto the exit.
	SyncControlPlaneUnderlayPins()
	err = setDefaultRoutesOnHost(publicKey, gw4, gw6)
	if len(config.Netclient().CurrGwNmIP) > 0 || len(config.Netclient().CurrGwNmIP6) > 0 {
		GetIGWMonitor().Monitor(publicKey, gw4, gw6)
		if err != nil {
			slog.Warn("internet gateway partially configured", "error", err.Error())
		}
		return nil
	}
	return err
}

func setDefaultRoutesOnHost(publicKey string, gw4, gw6 net.IP) error {
	armUnderlayPins()
	refreshDarwinLANGateways()
	if len(config.Netclient().OriginalDefaultGatewayIp) == 0 {
		return fmt.Errorf("failed to get current gateway")
	}

	peer, err := GetPeer(ncutils.GetInterfaceName(), publicKey)
	if err != nil || peer.Endpoint == nil {
		// Right after iface recreate the live device may not have the exit
		// peer yet. HostPeers still has the underlay endpoint for pinning.
		if ep := internetGwPeerEndpoint(publicKey); ep != nil {
			peer.Endpoint = ep
			err = nil
		}
	}
	if err != nil {
		return fmt.Errorf("failed to get peer: %w", err)
	}
	if peer.Endpoint == nil {
		return fmt.Errorf("peer endpoint is nil")
	}

	// Pin the exit and every other peer underlay BEFORE 0.0.0.0/1. Otherwise
	// WireGuard UDP to a site-egress gateway is swallowed by the split default
	// and trombones through the exit (large extra RTT with unchanged TTL).
	syncDarwinUnderlayPins(publicKey)

	iface := ncutils.GetInterfaceName()
	// Drop any previous half-defaults so we can re-add with the correct -ifa
	// (multi-net: kernel otherwise keeps an old src from the other network).
	exec.Command("route", "delete", "-net", "-inet", "0.0.0.0/1", "-interface", iface).Run()
	exec.Command("route", "delete", "-net", "-inet", "128.0.0.0/1", "-interface", iface).Run()
	exec.Command("route", "delete", "-net", "-inet6", ipv6HalfDefaultLow, "-interface", iface).Run()
	exec.Command("route", "delete", "-net", "-inet6", ipv6HalfDefaultHigh, "-interface", iface).Run()

	run := func(args ...string) {
		if out, err := exec.Command("route", args...).CombinedOutput(); err != nil {
			slog.Error("failed to add route", "command", fmt.Sprint(args), "output", string(out), "error", err)
		}
	}
	// Bind src to the exit network's overlay address. Without -ifa, macOS picks
	// any utun address (often the second connected network) and exit traffic fails.
	addHalfDefault := func(inet, cidr string, src net.IP) {
		args := []string{"add", "-net", inet, cidr}
		if src != nil {
			args = append(args, "-ifa", src.String())
		}
		args = append(args, "-interface", iface)
		run(args...)
	}

	if len(gw4) > 0 {
		src4 := igwSourceIP(gw4)
		if src4 != nil {
			logger.Log(0, "exit IPv4 route source bound to", src4.String(), "(exit network)")
		} else {
			logger.Log(0, "exit IPv4 route: no exit-network source found; kernel will pick an iface address")
		}
		addHalfDefault("-inet", "0.0.0.0/1", src4)
		addHalfDefault("-inet", "128.0.0.0/1", src4)
		config.Netclient().CurrGwNmIP = gw4
	}

	if len(gw6) > 0 {
		src6 := igwSourceIP(gw6)
		if src6 != nil {
			logger.Log(0, "exit IPv6 route source bound to", src6.String(), "(exit network)")
		}
		addHalfDefault("-inet6", ipv6HalfDefaultLow, src6)
		addHalfDefault("-inet6", ipv6HalfDefaultHigh, src6)
		config.Netclient().CurrGwNmIP6 = gw6
		if len(config.Netclient().CurrGwNmIP) == 0 {
			config.Netclient().CurrGwNmIP = gw6
		}
	} else if shouldBlockIPv6Leak(gw4, gw6) {
		// IPv4-only exit on a dual-stack host: pull IPv6 off the ISP so Happy
		// Eyeballs cannot leak. No CurrGwNmIP6 and no peer ::/0 — packets hit
		// the iface and drop via cryptokey routing; apps fall back to IPv4.
		logger.Log(0, "IPv4-only exit: diverting IPv6 off ISP to prevent leak")
		addHalfDefault("-inet6", ipv6HalfDefaultLow, nil)
		addHalfDefault("-inet6", ipv6HalfDefaultHigh, nil)
	}

	// Reinstall more-specific egress CIDRs so they win over 0.0.0.0/1 after IGW
	// install or monitor recovery (same as Linux table-111 reapply).
	reapplyCachedEgressRoutes()

	return config.WriteNetclientConfig()
}

// pinInternetGwHostRoutes reconciles underlay pins against the current peer
// set and LAN gateway. Safe (and cheap) to call repeatedly while exit routing
// is active; pins follow a Wi-Fi/LAN gateway change.
func pinInternetGwHostRoutes(publicKey string) {
	refreshDarwinLANGateways()
	syncDarwinUnderlayPins(publicKey)
}

// refreshDarwinLANGateways re-reads the LAN default gateways. Exit routing
// only adds half-defaults on utun, so `route get default` still reports the
// LAN; the cached value is kept when the lookup fails (e.g. Wi-Fi briefly down).
func refreshDarwinLANGateways() {
	nc := config.Netclient()
	overlay := func(ip net.IP) bool {
		return ip.Equal(nc.CurrGwNmIP) || ip.Equal(nc.CurrGwNmIP6)
	}
	if gw, err := getRouteGateway("default"); err == nil && gw.To4() != nil && !overlay(gw) {
		nc.OriginalDefaultGatewayIp = gw
	}
	if gw, err := getRouteGateway("-inet6", "default"); err == nil && gw.To4() == nil && !overlay(gw) {
		nc.OriginalDefaultGatewayIp6 = gw
	}
}

var darwinPinOps = underlayPinOps{install: installDarwinPin, remove: removeDarwinPin}

func syncDarwinUnderlayPins(publicKey string) {
	nc := config.Netclient()
	ips := IGWUnderlayPinIPs(publicKey)
	prune := canPruneUnderlayPins(publicKey)
	reconcileUnderlayPins(false, ips, viaGateway(nc.OriginalDefaultGatewayIp), prune, darwinPinOps)
	reconcileUnderlayPins(true, ips, viaGateway(nc.OriginalDefaultGatewayIp6), prune, darwinPinOps)
}

func darwinRouteFamily(ip net.IP) string {
	if ip.To4() != nil {
		return "-inet"
	}
	return "-inet6"
}

func installDarwinPin(ip net.IP, via string) error {
	fam := darwinRouteFamily(ip)
	out, err := exec.Command("route", "-n", "add", fam, "-host", ip.String(), via).CombinedOutput()
	if err == nil {
		return nil
	}
	if !routeAlreadyExists(out) {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	// A pre-existing route may point at a gateway from a previous network;
	// replace it rather than trusting it.
	removeDarwinPin(ip, "")
	if out, err = exec.Command("route", "-n", "add", fam, "-host", ip.String(), via).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func removeDarwinPin(ip net.IP, _ string) {
	_ = exec.Command("route", "-n", "delete", darwinRouteFamily(ip), "-host", ip.String()).Run()
}
