package functions

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ShowStatus prints the current host and network state.
// When wgShow is set, it prints the live WireGuard device in the same form as `wg show`.
func ShowStatus(wgShow bool) error {
	iface := ncutils.GetInterfaceName()
	device, devErr := wireguardDevice(iface)
	if wgShow {
		if devErr != nil {
			return fmt.Errorf("failed to read wireguard interface %s: %w", iface, devErr)
		}
		fmt.Print(formatWGShow(device, time.Now()))
		return nil
	}

	fmt.Print(formatStatus(statusViewFromConfig(iface, device)))
	return nil
}

type networkStatus struct {
	Name   string
	Status string
	IPv4   string
	IPv6   string
	Server string
}

type statusView struct {
	Host       string
	Server     string
	Iface      string
	IfaceUp    bool
	ListenPort int
	PublicKey  string
	Endpoint   string
	Exit       string
	Networks   []networkStatus
}

func statusViewFromConfig(iface string, device *wgtypes.Device) statusView {
	host := config.Netclient()
	view := statusView{
		Host:    host.Name,
		Server:  config.CurrServer,
		Iface:   iface,
		IfaceUp: interfaceUp(iface),
	}
	if device != nil {
		if keySet(device.PublicKey) {
			view.PublicKey = device.PublicKey.String()
		}
		if device.ListenPort != 0 {
			view.ListenPort = device.ListenPort
		}
	}
	if view.PublicKey == "" && keySet(host.PublicKey.Key) {
		view.PublicKey = host.PublicKey.String()
	}
	if view.ListenPort == 0 {
		view.ListenPort = host.ListenPort
	}
	if host.EndpointIP != nil {
		view.Endpoint = host.EndpointIP.String()
	}
	var exits []string
	if len(host.CurrGwNmIP) > 0 {
		exits = append(exits, host.CurrGwNmIP.String())
	}
	if len(host.CurrGwNmIP6) > 0 {
		exits = append(exits, host.CurrGwNmIP6.String())
	}
	view.Exit = strings.Join(exits, ", ")

	nodes := config.GetNodes()
	names := make([]string, 0, len(nodes))
	for name := range nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		node := nodes[name]
		row := networkStatus{
			Name:   node.Network,
			Status: "disconnected",
			IPv4:   "-",
			IPv6:   "-",
			Server: node.Server,
		}
		if node.Connected {
			row.Status = "connected"
		}
		if node.Address.IP != nil {
			row.IPv4 = node.Address.String()
		}
		if node.Address6.IP != nil {
			row.IPv6 = node.Address6.String()
		}
		if row.Name == "" {
			row.Name = name
		}
		view.Networks = append(view.Networks, row)
	}
	return view
}

func formatStatus(view statusView) string {
	var b strings.Builder
	host := view.Host
	if host == "" {
		host = "-"
	}
	server := view.Server
	if server == "" {
		server = "-"
	}
	ifaceState := "down"
	if view.IfaceUp {
		ifaceState = "up"
	}
	fmt.Fprintf(&b, "Host: %s\n", host)
	fmt.Fprintf(&b, "Server: %s\n", server)
	fmt.Fprintf(&b, "Interface: %s %s\n", view.Iface, ifaceState)
	if view.ListenPort != 0 {
		fmt.Fprintf(&b, "Listen port: %d\n", view.ListenPort)
	}
	if view.PublicKey != "" {
		fmt.Fprintf(&b, "Public key: %s\n", view.PublicKey)
	}
	if view.Endpoint != "" {
		fmt.Fprintf(&b, "Endpoint: %s\n", view.Endpoint)
	}
	exit := view.Exit
	if exit == "" {
		exit = "none"
	}
	fmt.Fprintf(&b, "Exit: %s\n", exit)
	b.WriteString("\n")
	if len(view.Networks) == 0 {
		b.WriteString("No networks joined\n")
		return b.String()
	}
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NETWORK\tSTATUS\tIPV4\tIPV6\tSERVER")
	for _, network := range view.Networks {
		server := network.Server
		if server == "" {
			server = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", network.Name, network.Status, network.IPv4, network.IPv6, server)
	}
	_ = tw.Flush()
	return b.String()
}

func interfaceUp(name string) bool {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	return ifi.Flags&net.FlagUp != 0
}

func wireguardDevice(iface string) (*wgtypes.Device, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wg.Close()
	return wg.Device(iface)
}

// formatWGShow prints a device the way `wg show` does.
// Private and preshared keys are hidden, matching the default wg output.
func formatWGShow(device *wgtypes.Device, now time.Time) string {
	if now.IsZero() {
		now = time.Now()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "interface: %s\n", device.Name)
	if keySet(device.PublicKey) {
		fmt.Fprintf(&b, "  public key: %s\n", device.PublicKey.String())
	}
	if keySet(device.PrivateKey) {
		b.WriteString("  private key: (hidden)\n")
	}
	if device.ListenPort != 0 {
		fmt.Fprintf(&b, "  listening port: %d\n", device.ListenPort)
	}
	if device.FirewallMark != 0 {
		fmt.Fprintf(&b, "  fwmark: 0x%x\n", device.FirewallMark)
	}
	for _, peer := range device.Peers {
		b.WriteByte('\n')
		fmt.Fprintf(&b, "peer: %s\n", peer.PublicKey.String())
		if keySet(peer.PresharedKey) {
			b.WriteString("  preshared key: (hidden)\n")
		}
		if peer.Endpoint != nil {
			fmt.Fprintf(&b, "  endpoint: %s\n", peer.Endpoint.String())
		}
		if len(peer.AllowedIPs) > 0 {
			ips := make([]string, 0, len(peer.AllowedIPs))
			for _, ip := range peer.AllowedIPs {
				ips = append(ips, ip.String())
			}
			fmt.Fprintf(&b, "  allowed ips: %s\n", strings.Join(ips, ", "))
		}
		if !peer.LastHandshakeTime.IsZero() {
			ago := now.Sub(peer.LastHandshakeTime)
			if ago < 0 {
				ago = 0
			}
			fmt.Fprintf(&b, "  latest handshake: %s ago\n", prettyDuration(ago))
		}
		fmt.Fprintf(&b, "  transfer: %s received, %s sent\n", prettyBytes(peer.ReceiveBytes), prettyBytes(peer.TransmitBytes))
		if peer.PersistentKeepaliveInterval > 0 {
			seconds := int(peer.PersistentKeepaliveInterval / time.Second)
			unit := "seconds"
			if seconds == 1 {
				unit = "second"
			}
			fmt.Fprintf(&b, "  persistent keepalive: every %d %s\n", seconds, unit)
		}
	}
	return b.String()
}

func keySet(key wgtypes.Key) bool {
	var zero wgtypes.Key
	return key != zero
}

func prettyDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	seconds := int64(d / time.Second)
	units := []struct {
		name string
		div  int64
	}{
		{"year", 365 * 24 * 60 * 60},
		{"day", 24 * 60 * 60},
		{"hour", 60 * 60},
		{"minute", 60},
		{"second", 1},
	}
	var parts []string
	for _, unit := range units {
		if seconds < unit.div && unit.div != 1 {
			continue
		}
		n := seconds / unit.div
		if n == 0 && unit.div != 1 {
			continue
		}
		if unit.div == 1 && n == 0 && len(parts) > 0 {
			break
		}
		name := unit.name
		if n != 1 {
			name += "s"
		}
		parts = append(parts, fmt.Sprintf("%d %s", n, name))
		seconds %= unit.div
		if unit.div == 1 {
			break
		}
	}
	if len(parts) == 0 {
		return "0 seconds"
	}
	return strings.Join(parts, ", ")
}

func prettyBytes(n int64) string {
	if n < 0 {
		n = 0
	}
	const unit = 1024
	v := float64(n)
	if v < unit {
		return fmt.Sprintf("%d B", n)
	}
	suffixes := []string{"KiB", "MiB", "GiB", "TiB"}
	for _, suffix := range suffixes {
		v /= unit
		if v < unit || suffix == "TiB" {
			return fmt.Sprintf("%.2f %s", v, suffix)
		}
	}
	return fmt.Sprintf("%d B", n)
}
