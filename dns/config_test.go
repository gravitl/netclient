package dns

import (
	"net"
	"runtime"
	"slices"
	"testing"

	dnsconfig "github.com/gravitl/netclient/dns/config"
)

func TestDNSConfigFingerprint(t *testing.T) {
	base := dnsconfig.Config{
		SplitDNS:      true,
		MatchDomains:  []string{"example.com", "nm.local"},
		SearchDomains: []string{"example.com"},
		Nameservers:   []net.IP{net.ParseIP("127.51.8.21"), net.ParseIP("100.64.0.1")},
	}
	fp := dnsConfigFingerprint("netmaker", base)
	if fp != dnsConfigFingerprint("netmaker", base) {
		t.Fatal("fingerprint not stable for identical config")
	}
	if fp == dnsConfigFingerprint("other", base) {
		t.Fatal("fingerprint should change with interface name")
	}

	full := base
	full.SplitDNS = false
	if fp == dnsConfigFingerprint("netmaker", full) {
		t.Fatal("fingerprint should change with SplitDNS")
	}

	extraNS := base
	extraNS.Nameservers = append(append([]net.IP{}, base.Nameservers...), net.ParseIP("100.64.0.2"))
	if fp == dnsConfigFingerprint("netmaker", extraNS) {
		t.Fatal("fingerprint should change with nameservers")
	}

	extraMatch := base
	extraMatch.MatchDomains = append(append([]string{}, base.MatchDomains...), "other.local")
	if fp == dnsConfigFingerprint("netmaker", extraMatch) {
		t.Fatal("fingerprint should change with match domains")
	}
}

func TestResetOSConfigSkipsWhenAlreadyRemoved(t *testing.T) {
	prevManager := configManager
	prevFP := appliedDNSFP
	prevRemoved := appliedDNSRemoved
	t.Cleanup(func() {
		configManager = prevManager
		appliedDNSMu.Lock()
		appliedDNSFP = prevFP
		appliedDNSRemoved = prevRemoved
		appliedDNSMu.Unlock()
	})

	calls := 0
	configManager = &countingDNSManager{onConfigure: func(_ string, cfg dnsconfig.Config) error {
		calls++
		if !cfg.Remove {
			t.Fatalf("expected Remove=true, got %#v", cfg)
		}
		return nil
	}}

	clearAppliedDNSConfig()
	applied, err := ResetOSConfig()
	if err != nil {
		t.Fatalf("ResetOSConfig: %v", err)
	}
	if applied {
		t.Fatal("expected skip when already removed")
	}
	if calls != 0 {
		t.Fatalf("OS Configure called %d times, want 0", calls)
	}

	appliedDNSMu.Lock()
	appliedDNSRemoved = false
	appliedDNSFP = "stale"
	appliedDNSMu.Unlock()

	applied, err = ResetOSConfig()
	if err != nil {
		t.Fatalf("ResetOSConfig: %v", err)
	}
	if !applied {
		t.Fatal("expected apply when not yet removed")
	}
	if calls != 1 {
		t.Fatalf("OS Configure called %d times, want 1", calls)
	}

	applied, err = ResetOSConfig()
	if err != nil {
		t.Fatalf("ResetOSConfig second: %v", err)
	}
	if applied || calls != 1 {
		t.Fatalf("second Reset should skip: applied=%v calls=%d", applied, calls)
	}
}

type countingDNSManager struct {
	onConfigure func(iface string, cfg dnsconfig.Config) error
}

func (c *countingDNSManager) Configure(iface string, cfg dnsconfig.Config) error {
	return c.onConfigure(iface, cfg)
}

func TestOrderListenerIPs(t *testing.T) {
	tests := []struct {
		name  string
		addrs []string
		want  []string
	}{
		{
			name:  "ipv4 leads on a dual stack node",
			addrs: []string{"100.104.160.10:53", "[fd3c:7c5c:8180:6b13::a]:53"},
			want:  []string{"100.104.160.10", "fd3c:7c5c:8180:6b13::a"},
		},
		{
			name:  "ipv6 is still published when it binds first",
			addrs: []string{"[fd3c:7c5c:8180:6b13::a]:53", "100.104.160.10:53"},
			want:  []string{"100.104.160.10", "fd3c:7c5c:8180:6b13::a"},
		},
		{
			name:  "loopback listener stays primary",
			addrs: []string{"100.104.160.10:53", "[fd3c:7c5c:8180:6b13::a]:53", "127.51.8.21:53"},
			want:  []string{"127.51.8.21", "100.104.160.10", "fd3c:7c5c:8180:6b13::a"},
		},
		{
			name:  "duplicates and unparseable addresses are dropped",
			addrs: []string{"100.104.160.10:53", "100.104.160.10:53", "netmaker:53", ""},
			want:  []string{"100.104.160.10"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := orderListenerIPs(tt.addrs)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("orderListenerIPs(%v) = %v, want %v", tt.addrs, got, tt.want)
			}
		})
	}
}

func TestNameserversForOS(t *testing.T) {
	all := []string{"127.51.8.21", "100.104.160.10", "fd3c:7c5c:8180:6b13::a"}
	got := nameserversForOS(all)
	if runtime.GOOS == "darwin" {
		if !slices.Equal(got, []string{"127.51.8.21"}) {
			t.Fatalf("darwin nameserversForOS = %v, want only loopback", got)
		}
	} else if !slices.Equal(got, all) {
		t.Fatalf("non-darwin nameserversForOS = %v, want %v", got, all)
	}

	// Fallback when loopback is missing: keep overlay addresses on all platforms.
	noLoopback := []string{"100.104.160.10", "fd3c:7c5c:8180:6b13::a"}
	got = nameserversForOS(noLoopback)
	if !slices.Equal(got, noLoopback) {
		t.Fatalf("nameserversForOS without loopback = %v, want %v", got, noLoopback)
	}
}

func TestGetIpFromServerString(t *testing.T) {
	tests := map[string]string{
		"100.104.160.10:53":           "100.104.160.10",
		"[fd3c:7c5c:8180:6b13::a]:53": "fd3c:7c5c:8180:6b13::a",
		"127.51.8.21:53":              "127.51.8.21",
		"100.104.160.10":              "100.104.160.10",
		"fd3c:7c5c:8180:6b13::a":      "fd3c:7c5c:8180:6b13::a",
		"[fd3c:7c5c:8180:6b13::a]":    "fd3c:7c5c:8180:6b13::a",
		"":                            "",
	}

	for addr, want := range tests {
		if got := getIpFromServerString(addr); got != want {
			t.Errorf("getIpFromServerString(%q) = %q, want %q", addr, got, want)
		}
	}
}
