package posture

import "testing"

func TestParseExecutingAccountName(t *testing.T) {
	got := parseExecutingAccountName("AzureAD\\abhishek-internal, abhi@abhisheknetmaker.onmicrosoft.com")
	want := "abhi@abhisheknetmaker.onmicrosoft.com"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestIsMachineAccount(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"WORKGROUP\\WIN-PMV0N6INPC6$", true},
		{"COMPUTERNAME$@tenant.onmicrosoft.com", true},
		{"abhi@abhisheknetmaker.onmicrosoft.com", false},
		{"AzureAD\\abhishek-internal", false},
	}
	for _, tc := range cases {
		if got := isMachineAccount(tc.value); got != tc.want {
			t.Errorf("isMachineAccount(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsValidUserEmailRejectsComputerUPN(t *testing.T) {
	if isValidUserEmail("COMPUTERNAME$@tenant.onmicrosoft.com") {
		t.Error("expected computer UPN to be rejected")
	}
}

func TestFirstValidUserEmail(t *testing.T) {
	got := firstValidUserEmail(
		"WORKGROUP\\WIN-PMV0N6INPC6$",
		"COMPUTERNAME$@tenant.onmicrosoft.com",
		"abhi@abhisheknetmaker.onmicrosoft.com",
	)
	if got != "abhi@abhisheknetmaker.onmicrosoft.com" {
		t.Errorf("got %q", got)
	}
}
