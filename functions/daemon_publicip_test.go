package functions

import (
	"net"
	"testing"
)

func TestPublicIPForProto(t *testing.T) {
	v4 := net.ParseIP("1.39.179.175")
	v6 := net.ParseIP("2402:3a80:2a3:bad4:a09d:c07a:a944:3cff")

	if got := publicIPForProto(v4, 4); got == nil || !got.Equal(v4) {
		t.Fatalf("publicIPForProto(v4, 4) = %v, want %v", got, v4)
	}
	if got := publicIPForProto(v4, 6); got != nil {
		t.Fatalf("publicIPForProto(v4, 6) = %v, want nil", got)
	}
	if got := publicIPForProto(v6, 6); got == nil || !got.Equal(v6) {
		t.Fatalf("publicIPForProto(v6, 6) = %v, want %v", got, v6)
	}
	if got := publicIPForProto(v6, 4); got != nil {
		t.Fatalf("publicIPForProto(v6, 4) = %v, want nil", got)
	}
}
