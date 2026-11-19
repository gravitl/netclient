package functions

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gravitl/netmaker/schema"
	"github.com/stretchr/testify/assert"
)

func resetDeleteHostGuard() {
	deleteHostGuardMu.Lock()
	ignoreDeleteHostUntil = 0
	ignoredTenantID = ""
	ignoredHostID = ""
	deleteHostGuardMu.Unlock()
}

func TestShouldIgnoreStaleDeleteHost(t *testing.T) {
	resetDeleteHostGuard()
	t.Cleanup(resetDeleteHostGuard)

	leftTenant := "tenant-left"
	leftHost := uuid.New()
	left := schema.Host{ID: leftHost, TenantID: leftTenant}
	otherTenant := schema.Host{ID: leftHost, TenantID: "tenant-new"}
	sameTenantNewHost := schema.Host{ID: uuid.New(), TenantID: leftTenant}

	assert.False(t, ShouldIgnoreStaleDeleteHost(left))

	ArmIgnoreStaleDeleteHost(leftTenant, leftHost.String())
	assert.True(t, ShouldIgnoreStaleDeleteHost(left))
	// Window stays armed until it expires (multiple MQ deliveries).
	assert.True(t, ShouldIgnoreStaleDeleteHost(left))
	// Same host under a different tenant must not be suppressed.
	assert.False(t, ShouldIgnoreStaleDeleteHost(otherTenant))
	// Same left tenant but different host ID must not be suppressed.
	assert.False(t, ShouldIgnoreStaleDeleteHost(sameTenantNewHost))
	// Left identity still ignored after non-matching checks.
	assert.True(t, ShouldIgnoreStaleDeleteHost(left))

	deleteHostGuardMu.Lock()
	ignoreDeleteHostUntil = time.Now().Add(-time.Second).UnixNano()
	deleteHostGuardMu.Unlock()
	assert.False(t, ShouldIgnoreStaleDeleteHost(left))
}

func TestShouldIgnoreStaleDeleteHostTenantOnly(t *testing.T) {
	resetDeleteHostGuard()
	t.Cleanup(resetDeleteHostGuard)

	leftTenant := "tenant-left"
	ArmIgnoreStaleDeleteHost(leftTenant, "")
	assert.True(t, ShouldIgnoreStaleDeleteHost(schema.Host{ID: uuid.New(), TenantID: leftTenant}))
	assert.False(t, ShouldIgnoreStaleDeleteHost(schema.Host{ID: uuid.New(), TenantID: "other"}))
}
