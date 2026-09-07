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
