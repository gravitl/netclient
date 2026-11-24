package dns

import (
	"runtime"
	"slices"
	"testing"
)

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
