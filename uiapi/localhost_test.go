package uiapi

import "testing"

func TestIsLoopbackAPIHost(t *testing.T) {
	allow := []string{"127.0.0.1:61820", "localhost:61820", "[::1]:61820", "127.0.0.1", "localhost"}
	for _, host := range allow {
		if !isLoopbackAPIHost(host) {
			t.Errorf("expected to allow %q", host)
		}
	}
	deny := []string{"evil.example:61820", "evil.example", "127.0.0.1:80", "8.8.8.8:61820", ""}
	for _, host := range deny {
		if isLoopbackAPIHost(host) {
			t.Errorf("expected to reject %q", host)
		}
	}
}
