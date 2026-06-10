package wireguard

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
)

const (
	// NetclientIfaceAlias marks kernel interfaces owned by netclient.
	NetclientIfaceAlias = "netclient-managed"

	maxCreatesPerWindow = 3
	createRateWindow    = 10 * time.Minute
)

// IfaceMetrics holds counters for wireguard interface lifecycle operations.
var IfaceMetrics struct {
	CreateTotal       atomic.Uint64
	DeleteTotal       atomic.Uint64
	ReuseTotal        atomic.Uint64
	CreateErrorsTotal atomic.Uint64
}

// ReconcileAction describes a planned interface operation.
type ReconcileAction string

const (
	ActionCreate ReconcileAction = "create"
	ActionReuse  ReconcileAction = "reuse"
	ActionUpdate ReconcileAction = "update"
	ActionDelete ReconcileAction = "delete"
	ActionNone   ReconcileAction = "none"
)

// ReconcileEntry describes one interface in a reconciliation plan.
type ReconcileEntry struct {
	Name        string          `json:"name"`
	Type        string          `json:"type,omitempty"`
	Owned       bool            `json:"owned"`
	Present     bool            `json:"present"`
	IsWireGuard bool            `json:"isWireGuard"`
	Action      ReconcileAction `json:"action"`
	Alias       string          `json:"alias,omitempty"`
}

// ReconcilePlan captures desired vs existing interface state.
type ReconcilePlan struct {
	Desired   string           `json:"desired"`
	Existing  []ReconcileEntry `json:"existing"`
	Generated time.Time        `json:"generated"`
}

var (
	createRateMu    sync.Mutex
	createRateTimes = map[string][]time.Time{}
	kernelWGPresent *bool
	kernelWGPresentMu sync.Mutex
)

// CallerInfo returns a short reason label and caller function name for logging.
func CallerInfo(skip int) (reason, caller string) {
	pc, _, _, ok := runtime.Caller(skip + 1)
	if !ok {
		return "unspecified", "unknown"
	}
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "unspecified", "unknown"
	}
	full := fn.Name()
	if idx := strings.LastIndex(full, "/"); idx >= 0 {
		full = full[idx+1:]
	}
	return full, full
}

func logIfaceOp(op, ifaceName, reason, caller string, err error) {
	attrs := []any{
		"operation", op,
		"interfaceName", ifaceName,
		"reason", reason,
		"caller", caller,
	}
	if err != nil {
		attrs = append(attrs, "error", err)
		slog.Error("wireguard interface operation failed", attrs...)
		return
	}
	slog.Info("wireguard interface operation", attrs...)
}

func recordCreateAttempt(name string) error {
	createRateMu.Lock()
	defer createRateMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-createRateWindow)
	times := createRateTimes[name]
	filtered := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	if len(filtered) >= maxCreatesPerWindow {
		return fmt.Errorf("interface %q created %d times in %s; refusing further creates", name, len(filtered), createRateWindow)
	}
	filtered = append(filtered, now)
	createRateTimes[name] = filtered
	return nil
}

func clearCreateRate(name string) {
	createRateMu.Lock()
	defer createRateMu.Unlock()
	delete(createRateTimes, name)
}

// BuildReconcilePlan compares desired and existing wireguard interfaces.
func BuildReconcilePlan() ReconcilePlan {
	desired := ncutils.GetInterfaceName()
	existing := listHostWireGuardInterfaces()
	plan := ReconcilePlan{
		Desired:   desired,
		Existing:  existing,
		Generated: time.Now(),
	}
	for i := range plan.Existing {
		entry := &plan.Existing[i]
		switch {
		case entry.Name == desired && entry.IsWireGuard:
			entry.Action = ActionReuse
		case entry.Owned && entry.Name != desired:
			entry.Action = ActionDelete
		case !entry.Owned:
			entry.Action = ActionNone
		default:
			entry.Action = ActionNone
		}
	}
	if !ifacePresentInPlan(plan, desired) {
		plan.Existing = append(plan.Existing, ReconcileEntry{
			Name:        desired,
			Owned:       true,
			Present:     false,
			IsWireGuard: true,
			Action:      ActionCreate,
		})
	}
	return plan
}

func ifacePresentInPlan(plan ReconcilePlan, name string) bool {
	for _, e := range plan.Existing {
		if e.Name == name {
			return true
		}
	}
	return false
}

// LogReconcilePlan emits the current reconciliation plan.
func LogReconcilePlan(plan ReconcilePlan) {
	slog.Info("wireguard interface reconciliation plan",
		"desired", plan.Desired,
		"entries", plan.Existing,
	)
}

// DumpReconcilePlan returns a human-readable reconciliation snapshot.
func DumpReconcilePlan() ReconcilePlan {
	return BuildReconcilePlan()
}

// ReconcileOnStartup reuses matching interfaces and removes stale netclient-owned ones.
func ReconcileOnStartup(reason string) error {
	_, caller := CallerInfo(1)
	plan := BuildReconcilePlan()
	LogReconcilePlan(plan)

	for _, entry := range plan.Existing {
		if entry.Action != ActionDelete {
			continue
		}
		if err := deleteLinkByName(entry.Name, reason, caller); err != nil {
			return err
		}
	}
	return nil
}

// RefreshInterface updates an existing interface in-place without delete/recreate.
func RefreshInterface(reason string, replacePeers bool) error {
	_, caller := CallerInfo(1)
	nc := NewNCIface(config.Netclient(), config.GetNodes())
	if err := nc.CreateWithReason(reason); err != nil {
		logIfaceOp("refresh_create", nc.Name, reason, caller, err)
		return err
	}
	if err := nc.Configure(); err != nil {
		logIfaceOp("refresh_configure", nc.Name, reason, caller, err)
		return err
	}
	if err := SetPeers(replacePeers); err != nil {
		logIfaceOp("refresh_set_peers", nc.Name, reason, caller, err)
		return err
	}
	SetRoutesFromCache()
	logIfaceOp("refresh", nc.Name, reason, caller, nil)
	return nil
}
