package firewall

import "testing"

func TestNetNatName(t *testing.T) {
	a := netNatName("egress-uuid-1")
	b := netNatName("egress-uuid-1")
	c := netNatName("egress-uuid-2")
	if a != b {
		t.Fatalf("expected deterministic name, got %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("expected different names for different egress IDs")
	}
	if !isNetmakerNetNatName(a) {
		t.Fatalf("expected netmaker prefix on %q", a)
	}
	if isNetmakerNetNatName("OtherNat") {
		t.Fatalf("did not expect unrelated name to match")
	}
}

func TestNormalizeNetNatPrefix(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"100.110.0.2/24", "100.110.0.0/24"},
		{"100.110.0.0/24", "100.110.0.0/24"},
		{" 10.0.0.5/16 ", "10.0.0.0/16"},
		{"", ""},
		{"<nil>", ""},
		{"not-a-cidr", "not-a-cidr"},
	}
	for _, tt := range tests {
		if got := normalizeNetNatPrefix(tt.in); got != tt.want {
			t.Fatalf("normalizeNetNatPrefix(%q)=%q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNetNatPrefixesEqual(t *testing.T) {
	if !netNatPrefixesEqual("100.110.0.2/24", "100.110.0.0/24") {
		t.Fatal("expected host and network form of same CIDR to match")
	}
	if netNatPrefixesEqual("100.110.0.0/24", "100.110.1.0/24") {
		t.Fatal("expected different networks not to match")
	}
}
