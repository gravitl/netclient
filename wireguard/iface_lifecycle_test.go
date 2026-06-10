package wireguard

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordCreateAttemptRateLimit(t *testing.T) {
	name := "test-rate-limit-" + time.Now().Format("150405.000000")
	createRateTimes = map[string][]time.Time{}

	for i := 0; i < maxCreatesPerWindow; i++ {
		require.NoError(t, recordCreateAttempt(name))
	}
	err := recordCreateAttempt(name)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing further creates")
}

func TestBuildReconcilePlanDesiredMissing(t *testing.T) {
	plan := BuildReconcilePlan()
	assert.NotEmpty(t, plan.Desired)

	foundDesired := false
	for _, entry := range plan.Existing {
		if entry.Name == plan.Desired && entry.Action == ActionCreate {
			foundDesired = true
		}
	}
	if !foundDesired {
		for _, entry := range plan.Existing {
			if entry.Name == plan.Desired && entry.Action == ActionReuse {
				foundDesired = true
			}
		}
	}
	assert.True(t, foundDesired, "plan should include desired interface action")
}

func TestIfacePresentInPlan(t *testing.T) {
	plan := ReconcilePlan{
		Existing: []ReconcileEntry{{Name: "netmaker"}},
	}
	assert.True(t, ifacePresentInPlan(plan, "netmaker"))
	assert.False(t, ifacePresentInPlan(plan, "other"))
}

func TestClearCreateRate(t *testing.T) {
	name := "clear-rate-test"
	createRateTimes[name] = []time.Time{time.Now()}
	clearCreateRate(name)
	createRateMu.Lock()
	_, ok := createRateTimes[name]
	createRateMu.Unlock()
	assert.False(t, ok)
}
