package querycache

import (
	"container/list"
	"context"
	"net/netip"
	"strings"
	"sync"
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

var (
	mu      sync.RWMutex
	entries = make(map[string]*list.List)
)

// Record stores a domain→IP resolution at the given time.
// ip is normalized to its canonical string form before storage.
func Record(ip, domain string, ts time.Time) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	addr = addr.Unmap()
	key := addr.String()
	domain = strings.TrimSuffix(domain, ".")

	mu.Lock()
	l, ok := entries[key]
	if !ok {
		l = list.New()
		entries[key] = l
	}
	l.PushBack(lookupEntry{domain: domain, ts: ts})
	mu.Unlock()
}

// Lookup returns the domain most recently resolved to ip at or before the given time.
// Returns "" if no matching entry exists.
func Lookup(ip string, before time.Time) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	key := addr.String()

	mu.RLock()
	l, ok := entries[key]
	if !ok {
		mu.RUnlock()
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
	mu.RUnlock()
	return result
}

// StartCleanup starts a background goroutine that removes entries older than
// ttl.
func StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				prune(time.Now().Add(-ttl))
			}
		}
	}()
}

func prune(cutoff time.Time) {
	mu.Lock()
	defer mu.Unlock()
	for key, l := range entries {
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
			delete(entries, key)
		}
	}
}
