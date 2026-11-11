//go:build darwin
// +build darwin

package firewall

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDarwinInboundDenyRules(t *testing.T) {
	rules := darwinInboundDenyRules("utun69")
	assert.Contains(t, rules, "block drop in on utun69 all")
	assert.Contains(t, rules, "pass out on utun69 all keep state")
	assert.Equal(t, 1, strings.Count(rules, "block drop in"))
	assert.Equal(t, 1, strings.Count(rules, "pass out"))
}
