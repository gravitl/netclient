package uiapi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRestorePhaseStartedAtTracksHoldWindow(t *testing.T) {
	prev := OnRestoreIdle
	OnRestoreIdle = nil
	t.Cleanup(func() {
		OnRestoreIdle = prev
		SetRestorePhase("")
	})

	SetRestorePhase("")
	assert.True(t, RestorePhaseStartedAt().IsZero())

	SetRestorePhase(RestorePhaseNetworks)
	started := RestorePhaseStartedAt()
	assert.False(t, started.IsZero())

	// Networks→Exit→Routes must keep the original clock.
	time.Sleep(5 * time.Millisecond)
	SetRestorePhase(RestorePhaseExit)
	assert.Equal(t, started.UnixNano(), RestorePhaseStartedAt().UnixNano())
	SetRestorePhase(RestorePhaseRoutes)
	assert.Equal(t, started.UnixNano(), RestorePhaseStartedAt().UnixNano())

	idleCalls := 0
	OnRestoreIdle = func() { idleCalls++ }
	SetRestorePhase("")
	assert.True(t, RestorePhaseStartedAt().IsZero())
	assert.Equal(t, 1, idleCalls)

	// Idle→idle must not re-fire.
	SetRestorePhase("")
	assert.Equal(t, 1, idleCalls)
}

func TestHoldIGWTeardownRestoreDeadlineElapsed(t *testing.T) {
	// Mirrors desktop holdIGWTeardown restore-phase age check without a session.
	SetRestorePhase("")
	t.Cleanup(func() { SetRestorePhase("") })

	SetRestorePhase(RestorePhaseExit)
	started := RestorePhaseStartedAt()
	assert.False(t, started.IsZero())
	assert.Less(t, time.Since(started), 45*time.Second)
}
