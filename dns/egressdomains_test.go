package dns

import (
	"testing"

	"github.com/gravitl/netmaker/models"
)

func TestDomainMatchesPattern(t *testing.T) {
	tests := []struct {
		query   string
		pattern string
		want    bool
	}{
		{"github.com", "github.com", true},
		{"api.github.com", "github.com", true},
		{"github.com", "*.github.com", true},
		{"api.github.com", "*.github.com", true},
		{"notgithub.com", "github.com", false},
		{"foo.intercom.io", "*.intercom.io", true},
		{"intercom.io", "*.intercom.io", true},
	}
	for _, tc := range tests {
		if got := domainMatchesPattern(tc.query, tc.pattern); got != tc.want {
			t.Fatalf("domainMatchesPattern(%q, %q) = %v, want %v", tc.query, tc.pattern, got, tc.want)
		}
	}
}

func TestMatchesEgressDomain(t *testing.T) {
	SyncEgressDomainPatterns(nil)
	if MatchesEgressDomain("github.com") {
		t.Fatal("expected no match with empty patterns")
	}

	SyncEgressDomainPatterns([]models.EgressDomain{{Domain: "github.com"}})
	if !MatchesEgressDomain("github.com.") {
		t.Fatal("expected match for github.com")
	}
	if !MatchesEgressDomain("api.github.com") {
		t.Fatal("expected match for api.github.com")
	}
}
