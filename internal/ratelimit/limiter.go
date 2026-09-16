// Package ratelimit implements the keyed token-bucket limiter used to throttle
// the credential endpoints (/register, /login, /token) and the helpers that
// derive rate-limit keys (client IP behind trusted proxies, hashed identity).
//
// Storage is in-process. The auth service has no shared store of its own —
// its only database access is the lazily-created per-tenant pool, which is
// exactly what the limiter must protect (an unknown project would otherwise
// trigger a vault round-trip before being throttled). The consequence is that
// limits are enforced per replica: with N replicas behind a round-robin
// service an attacker gets at most N× the configured budget. Size the
// configured limits with the replica count in mind, or pair with an edge
// limiter for hard global caps.
package ratelimit

import (
	"sync"
	"time"
)

// Decision is the outcome of a limiter check. RetryAfter is the time until at
// least one more request would be admitted; it is zero when Allowed.
type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
}

// Blocked is the inverse of Allowed, kept for readability at peek call sites.
func (d Decision) Blocked() bool { return !d.Allowed }

// Limiter is a keyed token bucket: each key holds up to `limit` tokens and
// refills continuously at `limit` tokens per `window`. It is safe for
// concurrent use.
type Limiter struct {
	mu        sync.Mutex
	limit     float64
	window    time.Duration
	now       func() time.Time
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens  float64
	updated time.Time
}

// Option customises a Limiter.
type Option func(*Limiter)

// WithClock replaces the wall clock; used by tests to advance time manually.
func WithClock(now func() time.Time) Option {
	return func(l *Limiter) { l.now = now }
}

// New returns a Limiter admitting `limit` events per `window` per key.
// A limit of zero blocks every request.
func New(limit int, window time.Duration, opts ...Option) *Limiter {
	l := &Limiter{
		limit:   float64(limit),
		window:  window,
		now:     time.Now,
		buckets: make(map[string]*bucket),
	}
	for _, opt := range opts {
		opt(l)
	}
	l.lastSweep = l.now()
	return l
}

// Allow consumes one token for key and reports whether it was available.
func (l *Limiter) Allow(key string) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.refill(key)
	if b.tokens < 1 {
		return Decision{RetryAfter: l.timeToNextToken(b)}
	}
	b.tokens--
	return Decision{Allowed: true}
}

// Exhausted reports whether key has no tokens left without consuming one.
// Callers that want a "check before, charge after" pattern (login failures)
// use this before the expensive work and Allow afterwards.
func (l *Limiter) Exhausted(key string) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.refill(key)
	if b.tokens < 1 {
		return Decision{RetryAfter: l.timeToNextToken(b)}
	}
	return Decision{Allowed: true}
}

// Reset forgets key, restoring its full budget.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

// Len returns the number of keys currently tracked (after eviction).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// refill returns the bucket for key with tokens credited for elapsed time,
// creating a full bucket on first sight. Must be called with mu held.
func (l *Limiter) refill(key string) *bucket {
	now := l.now()
	l.sweep(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.limit, updated: now}
		l.buckets[key] = b
		return b
	}
	if elapsed := now.Sub(b.updated); elapsed > 0 && l.window > 0 {
		b.tokens += float64(elapsed) / float64(l.window) * l.limit
		if b.tokens > l.limit {
			b.tokens = l.limit
		}
	}
	b.updated = now
	return b
}

// timeToNextToken is how long until the bucket has one whole token again.
func (l *Limiter) timeToNextToken(b *bucket) time.Duration {
	if l.limit <= 0 {
		return l.window
	}
	missing := 1 - b.tokens
	return time.Duration(missing * float64(l.window) / l.limit)
}

// sweep evicts buckets idle for at least one window: they have refilled to
// capacity and are indistinguishable from unseen keys, so dropping them keeps
// memory bounded by the number of active keys. Runs at most once per window.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < l.window {
		return
	}
	l.lastSweep = now
	for key, b := range l.buckets {
		if now.Sub(b.updated) >= l.window {
			delete(l.buckets, key)
		}
	}
}
