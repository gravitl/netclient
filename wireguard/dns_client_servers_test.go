package wireguard

import "testing"

func TestParseDnsClientServerAddressJSON(t *testing.T) {
	t.Run("array", func(t *testing.T) {
		input := `[
			{"InterfaceIndex": 12, "ServerAddresses": ["1.1.1.1", "8.8.8.8"]},
			{"InterfaceIndex": 5, "ServerAddresses": ["10.0.0.1"]}
		]`
		got, err := parseDnsClientServerAddressJSON(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		if got[0].InterfaceIndex != 12 || len(got[0].ServerAddresses) != 2 {
			t.Fatalf("unexpected first entry: %+v", got[0])
		}
	})

	t.Run("single object", func(t *testing.T) {
		input := `{"InterfaceIndex": 12, "ServerAddresses": ["1.1.1.1"]}`
		got, err := parseDnsClientServerAddressJSON(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0].InterfaceIndex != 12 || got[0].ServerAddresses[0] != "1.1.1.1" {
			t.Fatalf("unexpected parse: %+v", got)
		}
	})

	t.Run("empty", func(t *testing.T) {
		if _, err := parseDnsClientServerAddressJSON("  "); err == nil {
			t.Fatal("expected error for empty input")
		}
	})
}
