// Package throttle is a small in-process fixed-window counter used to cap
// abusable unauthenticated flows (resend verification, forgot password).
//
// It is deliberately independent of any shared store: a per-replica cap is
// enough to blunt enumeration and mail-bombing, and it keeps these endpoints
// working when no central limiter is deployed.
package throttle

import (
	"sync"
	"time"
)

type window struct {
	count     int
	expiresAt time.Time
}

// Throttle allows at most `limit` events per `window` for each key.
type Throttle struct {
	mu       sync.Mutex
	limit    int
	duration time.Duration
	windows  map[string]*window
}

// New returns a Throttle permitting `limit` events per `duration` per key.
// A limit of zero or less disables throttling.
func New(limit int, duration time.Duration) *Throttle {
	return &Throttle{limit: limit, duration: duration, windows: make(map[string]*window)}
}

// Allow records an attempt for key and reports whether it is within budget.
// An empty key is always allowed — an unidentifiable caller must never be able
// to drain a budget that other callers share.
func (t *Throttle) Allow(key string) bool {
	if t.limit <= 0 || key == "" {
		return true
	}

	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	t.evictExpired(now)

	w, ok := t.windows[key]
	if !ok || now.After(w.expiresAt) {
		t.windows[key] = &window{count: 1, expiresAt: now.Add(t.duration)}
		return true
	}
	if w.count >= t.limit {
		return false
	}
	w.count++
	return true
}

// evictExpired drops elapsed windows so the map cannot grow without bound as
// attackers rotate keys. Callers must hold the mutex.
func (t *Throttle) evictExpired(now time.Time) {
	for key, w := range t.windows {
		if now.After(w.expiresAt) {
			delete(t.windows, key)
		}
	}
}

// size reports the number of tracked windows; used by tests to assert eviction.
func (t *Throttle) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.windows)
}
