//go:build darwin
// +build darwin

package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
)

const (
	darwinPFAnchor     = "com.gravitl.netmaker"
	darwinPFAnchorPath = "/etc/pf.anchors/com.gravitl.netmaker"
	darwinPFConfPath   = "/etc/pf.conf"
	darwinPFBegin      = "# BEGIN gravitl netmaker"
	darwinPFEnd        = "# END gravitl netmaker"
)

// darwinFirewall implements Desktop default-deny inbound on the mesh iface via
// pf. Full ACL / egress / ingress policy is not applied on Darwin — only
// ChangeACLInTarget(DROP|ACCEPT) and FlushAll matter for Desktop builds.
type darwinFirewall struct {
	noopFirewall
	mux         sync.Mutex
	denyInbound bool
}

func newFirewall() (firewallController, error) {
	logger.Log(0, "using Darwin pf for Desktop inbound ACL defaults...")
	return &darwinFirewall{}, nil
}

// ChangeACLInTarget installs (DROP) or clears (ACCEPT) a pf block-in on the
// netmaker iface. Outbound stays allowed with keep state so return traffic for
// connections this host initiated still works.
func (d *darwinFirewall) ChangeACLInTarget(target string) {
	d.mux.Lock()
	defer d.mux.Unlock()
	if strings.EqualFold(target, targetDrop) {
		if err := d.applyInboundDenyLocked(); err != nil {
			slog.Warn("darwin pf: failed to apply inbound deny", "error", err)
			logger.Log(0, "darwin pf: failed to apply inbound deny: ", err.Error())
			return
		}
		d.denyInbound = true
		logger.Log(0, "darwin pf: default deny inbound on ", ncutils.GetInterfaceName())
		return
	}
	if err := d.clearInboundDenyLocked(); err != nil {
		slog.Warn("darwin pf: failed to clear inbound deny", "error", err)
		return
	}
	d.denyInbound = false
}

// ChangeACLFwdTarget is a no-op on Darwin Desktop (devices are not gateways).
func (d *darwinFirewall) ChangeACLFwdTarget(string) {}

func (d *darwinFirewall) FlushAll() {
	d.mux.Lock()
	defer d.mux.Unlock()
	if err := d.clearInboundDenyLocked(); err != nil {
		slog.Warn("darwin pf: FlushAll failed to clear inbound deny", "error", err)
	}
	d.denyInbound = false
}

func (d *darwinFirewall) applyInboundDenyLocked() error {
	iface := strings.TrimSpace(ncutils.GetInterfaceName())
	if iface == "" {
		return fmt.Errorf("empty netmaker interface name")
	}
	if err := ensureDarwinPFAnchorHook(); err != nil {
		return err
	}
	rules := darwinInboundDenyRules(iface)
	if err := os.WriteFile(darwinPFAnchorPath, []byte(rules), 0o644); err != nil {
		return fmt.Errorf("write pf anchor: %w", err)
	}
	if err := runPFCtl("-a", darwinPFAnchor, "-f", darwinPFAnchorPath); err != nil {
		return err
	}
	// Enable pf if it was off; ignore "already enabled".
	_ = runPFCtl("-e")
	return nil
}

func (d *darwinFirewall) clearInboundDenyLocked() error {
	// Empty the on-disk anchor so a later pf.conf reload stays inert.
	if err := os.WriteFile(darwinPFAnchorPath, []byte(""), 0o644); err != nil && !os.IsNotExist(err) {
		slog.Debug("darwin pf: could not truncate anchor file", "error", err)
	}
	// Flush rules in the anchor even if the file was already gone.
	if err := runPFCtl("-a", darwinPFAnchor, "-F", "all"); err != nil {
		// Anchor may not be loaded yet (first run / pf disabled) — not fatal.
		slog.Debug("darwin pf: flush anchor", "error", err)
	}
	return nil
}

// darwinInboundDenyRules returns pf rules: block unsolicited inbound on the
// mesh iface; allow outbound (stateful return traffic).
func darwinInboundDenyRules(iface string) string {
	iface = strings.TrimSpace(iface)
	var b strings.Builder
	b.WriteString("# gravitl netclient Desktop — default deny inbound on mesh iface\n")
	b.WriteString(fmt.Sprintf("block drop in on %s all\n", iface))
	b.WriteString(fmt.Sprintf("pass out on %s all keep state\n", iface))
	return b.String()
}

func ensureDarwinPFAnchorHook() error {
	existing, err := os.ReadFile(darwinPFConfPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read pf.conf: %w", err)
	}
	content := string(existing)
	if strings.Contains(content, darwinPFBegin) && strings.Contains(content, darwinPFAnchor) {
		return nil
	}
	hook := fmt.Sprintf("\n%s\nanchor \"%s\"\nload anchor \"%s\" from \"%s\"\n%s\n",
		darwinPFBegin, darwinPFAnchor, darwinPFAnchor, darwinPFAnchorPath, darwinPFEnd)
	if !strings.HasSuffix(content, "\n") && content != "" {
		content += "\n"
	}
	content += hook
	if err := os.WriteFile(darwinPFConfPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("update pf.conf: %w", err)
	}
	// Load the updated main ruleset so the anchor is referenced.
	if err := runPFCtl("-f", darwinPFConfPath); err != nil {
		return fmt.Errorf("reload pf.conf: %w", err)
	}
	return nil
}

func runPFCtl(args ...string) error {
	cmd := exec.Command("pfctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("pfctl %s: %w", strings.Join(args, " "), err)
		}
		// pfctl -e prints to stderr when already enabled.
		if strings.Contains(msg, "pf already enabled") {
			return nil
		}
		return fmt.Errorf("pfctl %s: %w (%s)", strings.Join(args, " "), err, msg)
	}
	return nil
}
