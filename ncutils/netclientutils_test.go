package ncutils

import "testing"

func TestRadomMacAddress(t *testing.T) {
	mac := RandomMacAddress()
	if mac.String() == "" {
		t.Error("empty mac Address")
	}
}
