package querycache

import (
	"container/list"
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ttl             = 15 * time.Minute
	cleanupInterval = 5 * time.Minute
)

type lookupEntry struct {
	domain string
	ts     time.Time
}

type Manager struct {
	enabled atomic.Bool
	cancel  context.CancelFunc
	mu      sync.RWMutex
	entries map[string]*list.List
}

var (
	manager  *Manager
	initOnce sync.Once
)

func GetManager() *Manager {
	initOnce.Do(func() {
		manager = &Manager{
			entries: make(map[string]*list.List),
		}
	})

	return manager
}

func (m *Manager) Enable() {
	m.enabled.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	go m.startCleanup(ctx)
}

func (m *Manager) Disable() {
	m.enabled.Store(false)
	if m.cancel != nil {
		m.cancel()
	}
}

// Record stores a domain→IP resolution at the given time.
// ip is normalized to its canonical string form before storage.
func (m *Manager) Record(ip, domain string, ts time.Time) {
	if !m.enabled.Load() {
		return
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	addr = addr.Unmap()
	key := addr.String()
	domain = strings.TrimSuffix(domain, ".")

	m.mu.Lock()
	l, ok := m.entries[key]
	if !ok {
		l = list.New()
		m.entries[key] = l
	}
	l.PushBack(lookupEntry{domain: domain, ts: ts})
	m.mu.Unlock()
}

// Lookup returns the domain most recently resolved to ip at or before the given time.
// Returns "" if no matching entry exists.
func (m *Manager) Lookup(ip string, before time.Time) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	key := addr.String()

	m.mu.RLock()
	l, ok := m.entries[key]
	if !ok {
		m.mu.RUnlock()
		return ""
	}
	// Entries are ordered oldest→newest (PushBack). Walk back-to-front to
	// find the most recent entry whose ts is ≤ before.
	var result string
	for e := l.Back(); e != nil; e = e.Prev() {
		entry := e.Value.(lookupEntry)
		if !entry.ts.After(before) {
			result = entry.domain
			break
		}
	}
	m.mu.RUnlock()
	return result
}

// StartCleanup starts a background goroutine that removes entries older than
// ttl.
func (m *Manager) startCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.prune(time.Now().Add(-ttl))
			}
		}
	}()
}

func (m *Manager) prune(cutoff time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, l := range m.entries {
		for e := l.Front(); e != nil; {
			if e.Value.(lookupEntry).ts.Before(cutoff) {
				next := e.Next()
				l.Remove(e)
				e = next
			} else {
				break
			}
		}
		if l.Len() == 0 {
			delete(m.entries, key)
		}
	}
}
